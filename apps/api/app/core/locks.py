"""Small concurrency primitives used by the audit chain.

The audit writer allocates the next ``seq`` by reading ``MAX(seq)`` and inserting
the successor. Two writers that read the same maximum would collide on the
``(task_id, seq)`` unique constraint. That constraint is deliberate -- a forked
chain must be loud -- but the normal case should not become a 500. A per-task lock
serialises the read-and-append inside one process; Postgres adds a row lock for
the multi-process case (see ``AuditLogger.write``).

The registry is bounded: a long-lived process that has handled a million tasks
must not leak a lock per task. Locks are reference-counted and dropped when the
last holder leaves.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager


class KeyedLock:
    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, tuple[threading.Lock, int]] = {}

    @contextmanager
    def hold(self, key: str) -> Iterator[None]:
        with self._guard:
            lock, waiters = self._locks.get(key, (threading.Lock(), 0))
            self._locks[key] = (lock, waiters + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._guard:
                current_lock, current_waiters = self._locks[key]
                if current_waiters <= 1:
                    self._locks.pop(key, None)
                else:
                    self._locks[key] = (current_lock, current_waiters - 1)

    def size(self) -> int:
        with self._guard:
            return len(self._locks)


# One registry per domain for the process. Tests may inspect size() to prove
# neither grows without bound.
TASK_LOCKS = KeyedLock()
APPROVAL_LOCKS = KeyedLock()
