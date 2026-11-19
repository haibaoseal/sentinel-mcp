"""Failure handling for tool execution.

Two mechanisms, deliberately separate:

- **Retry** is opt-in and applies to read-only tools only. Retrying a write is
  how a payment is sent twice; the policy contract already labels an action, so
  the retry policy can refuse to guess.
- **A circuit breaker** stops hammering a dependency that is already failing.
  It is per tool, in-process, and its state is exported as a gauge. A
  multi-replica deployment needs a shared breaker; that is a documented limit,
  not an implied guarantee.

The breaker counts only `ToolExecutionError`. A policy block or a bad argument is
a decision, not a failed dependency, and must not trip it.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from app.core.errors import CircuitOpenError, ToolExecutionError

T = TypeVar("T")

try:  # The governance library must install without the optional web stack.
    from app.observability import metrics as _metrics
except Exception:  # pragma: no cover - import guard
    _metrics = None


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 3
    recovery_seconds: float = 15.0
    clock: Callable[[], float] = time.monotonic
    _failures: int = 0
    _opened_at: float | None = None
    _half_open_in_flight: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def state(self) -> str:
        with self._lock:
            if self._opened_at is None:
                return "closed"
            if self.clock() - self._opened_at >= self.recovery_seconds:
                return "half_open"
            return "open"

    def allow(self) -> None:
        """Raise if a call may not proceed; reserve the half-open probe."""
        with self._lock:
            if self._opened_at is None:
                return
            if self.clock() - self._opened_at < self.recovery_seconds:
                raise CircuitOpenError(
                    f"circuit for {self.name!r} is open for another "
                    f"{self.recovery_seconds - (self.clock() - self._opened_at):.1f}s"
                )
            if self._half_open_in_flight:
                raise CircuitOpenError(f"circuit for {self.name!r} is half-open; probe in flight")
            self._half_open_in_flight = True
            self._publish(open_=True)

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._half_open_in_flight = False
            self._publish(open_=False)

    def release_probe(self) -> None:
        """Release a half-open probe slot without clearing prior failure state.

        Used when a call raises a non-dependency bug (e.g. ValueError or
        ToolArgumentError): it must neither trip the breaker nor falsely heal an
        open/half-open breaker back to closed.
        """
        with self._lock:
            self._half_open_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self._half_open_in_flight = False
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = self.clock()
                self._publish(open_=True)

    def _publish(self, *, open_: bool) -> None:
        if _metrics is not None:
            _metrics.CIRCUIT_OPEN.labels(tool=self.name).set(1 if open_ else 0)


@dataclass
class RetryPolicy:
    max_attempts: int = 2
    base_delay: float = 0.05
    max_delay: float = 0.5
    jitter: float = 0.2
    sleep: Callable[[float], None] = time.sleep
    random: Callable[[], float] = random.random

    def run(
        self,
        fn: Callable[[], T],
        *,
        tool_name: str | None = None,
        on_retry: Callable[[int, ToolExecutionError], None] | None = None,
    ) -> tuple[T, int]:
        attempts = 0
        while True:
            attempts += 1
            try:
                return fn(), attempts
            except ToolExecutionError as exc:
                if attempts >= self.max_attempts:
                    raise
                if on_retry is not None:
                    on_retry(attempts, exc)
                if _metrics is not None:
                    label = tool_name or getattr(exc, "tool_name", "unknown")
                    _metrics.TOOL_RETRIES.labels(tool=label).inc()
                delay = min(self.max_delay, self.base_delay * (2 ** (attempts - 1)))
                self.sleep(delay + (delay * self.jitter * self.random()))


class ToolResilience:
    """Retry + breaker facade used by the firewall."""

    def __init__(
        self,
        *,
        retry_attempts: int = 2,
        retry_base_delay: float = 0.05,
        circuit_failure_threshold: int = 3,
        circuit_recovery_seconds: float = 15.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.retry = RetryPolicy(
            max_attempts=max(1, retry_attempts),
            base_delay=retry_base_delay,
            sleep=sleep,
        )
        self.circuit_failure_threshold = circuit_failure_threshold
        self.circuit_recovery_seconds = circuit_recovery_seconds
        self._breakers: dict[str, CircuitBreaker] = {}
        self._guard = threading.Lock()

    def breaker(self, tool_name: str) -> CircuitBreaker:
        with self._guard:
            if tool_name not in self._breakers:
                self._breakers[tool_name] = CircuitBreaker(
                    name=tool_name,
                    failure_threshold=self.circuit_failure_threshold,
                    recovery_seconds=self.circuit_recovery_seconds,
                )
            return self._breakers[tool_name]

    def execute(
        self,
        *,
        tool_name: str,
        action_type: str,
        fn: Callable[[], T],
        on_retry: Callable[[int, ToolExecutionError], None] | None = None,
    ) -> tuple[T, int]:
        breaker = self.breaker(tool_name)
        breaker.allow()
        try:
            if action_type == "read" and self.retry.max_attempts > 1:
                result, attempts = self.retry.run(fn, tool_name=tool_name, on_retry=on_retry)
            else:
                result, attempts = fn(), 1
        except ToolExecutionError:
            breaker.record_failure()
            raise
        except Exception:
            # A bug is not a dependency failure; do not trip the breaker and do
            # not falsely heal a half-open breaker either.
            breaker.release_probe()
            raise
        breaker.record_success()
        return result, attempts
