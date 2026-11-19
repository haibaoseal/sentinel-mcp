"""Per-tenant rate limiting and a process-wide task gate.

Both are deliberately in-process. That is an honest limit for a single-replica
deployment and it is named in OPERATIONS.md: a multi-replica service needs a
shared counter (Redis) for the rate limit and a queue for the task gate. The
point of the gate is not to be the final scaling story -- it is to make overload
a 429 with a `Retry-After` instead of an unbounded thread pool.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class TenantRateLimiter:
    def __init__(self, per_minute: int, *, clock=time.monotonic) -> None:
        self.per_minute = max(1, per_minute)
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._guard = threading.Lock()

    def check(self, tenant_id: str) -> LimitDecision:
        now = self._clock()
        window_start = now - 60.0
        with self._guard:
            bucket = self._events.setdefault(tenant_id, deque())
            while bucket and bucket[0] <= window_start:
                bucket.popleft()
            if len(bucket) >= self.per_minute:
                retry_after = max(1, int(60 - (now - bucket[0])))
                return LimitDecision(False, 0, retry_after)
            bucket.append(now)
            return LimitDecision(True, self.per_minute - len(bucket), 0)

    def reset(self) -> None:
        with self._guard:
            self._events.clear()


class TaskGate:
    """Bounds how many agent runs execute at once.

    A bounded semaphore rather than an unbounded thread pool: when every slot is
    busy the caller gets an immediate 429 and can retry, instead of the service
    accumulating work until memory or the database gives out.
    """

    def __init__(self, max_concurrent: int) -> None:
        self._semaphore = threading.BoundedSemaphore(max(1, max_concurrent))
        self.max_concurrent = max(1, max_concurrent)

    def acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        self._semaphore.release()
