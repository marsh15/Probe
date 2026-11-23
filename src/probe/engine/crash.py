"""Crash bookkeeping for one scan.

When the target dies Probe records a ``CrashEvent`` and restarts it, at most three times.
The third crash marks the target unstable: checks still waiting to make calls end in ERROR
("target_unstable") instead of running against a server that keeps dying.
"""

from probe.engine.outcomes import CrashEvent

MAX_RESTARTS = 3


class TargetCrashed(Exception):
    """The target died during a call. The crash is already recorded and the target restarted."""

    def __init__(self, event: CrashEvent) -> None:
        super().__init__(f"target crashed (exit code {event.exit_code})")
        self.event = event


class TargetUnstable(Exception):
    """The target died and cannot be restarted again; no more calls are possible."""


class CrashTracker:
    def __init__(self, max_restarts: int = MAX_RESTARTS) -> None:
        self.events: list[CrashEvent] = []
        self.restarts = 0
        # Set when the target could not be brought back (a restart or reconnect failed).
        self.abandoned = False
        self._max_restarts = max_restarts

    @property
    def can_restart(self) -> bool:
        return self.restarts < self._max_restarts

    @property
    def unstable(self) -> bool:
        return self.abandoned or len(self.events) >= self._max_restarts

    def record(self, event: CrashEvent) -> None:
        self.events.append(event)
