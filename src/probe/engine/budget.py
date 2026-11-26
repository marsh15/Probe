"""A bound on how many calls a scan (or one check) may make and how long it may take."""

import time
from collections.abc import Callable


class BudgetExhausted(Exception):
    """The call or time budget ran out. A check ends with what it has observed so far."""


class Budget:
    def __init__(
        self,
        calls: int,
        seconds: float | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        parent: "Budget | None" = None,
    ) -> None:
        if calls <= 0:
            raise ValueError("a budget needs at least one call")
        self._limit = calls
        self._clock = clock
        self._deadline = None if seconds is None else clock() + seconds
        self._parent = parent
        self.used = 0

    @property
    def remaining(self) -> int:
        return self._limit - self.used

    @property
    def remaining_seconds(self) -> float:
        local = float("inf") if self._deadline is None else max(0.0, self._deadline - self._clock())
        return min(local, self._parent.remaining_seconds) if self._parent is not None else local

    @property
    def expired(self) -> bool:
        return self._deadline is not None and self._clock() >= self._deadline

    def take(self, n: int = 1) -> None:
        """Spend ``n`` calls, or raise ``BudgetExhausted`` and spend nothing."""
        if n <= 0:
            raise ValueError("take() needs a positive count")
        if self.expired:
            raise BudgetExhausted("time budget exhausted")
        if self.used + n > self._limit:
            raise BudgetExhausted("call budget exhausted")
        if self._parent is not None:
            self._parent.take(n)  # raises first, so a refused call is counted nowhere
        self.used += n

    def child(self, calls: int, seconds: float | None = None) -> "Budget":
        """A tighter budget for one check; everything it spends is also spent here."""
        return Budget(calls, seconds, clock=self._clock, parent=self)
