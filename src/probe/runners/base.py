"""What the engine needs from whatever starts and watches the server under test."""

from dataclasses import dataclass
from typing import Protocol

from probe.engine.outcomes import Transport as TransportKind
from probe.wire.transport_base import Transport


@dataclass(frozen=True, slots=True)
class RunnerState:
    running: bool
    exit_code: int | None = None
    oom_killed: bool = False


class Runner(Protocol):
    transport_kind: TransportKind
    sandboxed: bool

    async def start(self) -> Transport: ...

    async def restart(self) -> Transport:
        """A fresh process or container with the same fixtures."""
        ...

    async def second_instance(self) -> Transport | None:
        """A second, independent instance, or None where that is impossible (a URL target)."""
        ...

    async def logs(self) -> str: ...

    async def state(self) -> RunnerState: ...

    async def stop(self) -> None:
        """Graceful (close stdin or SIGTERM), then kill after 5 s."""
        ...


class TargetUnavailable(Exception):
    """The target cannot be started or reached. The scan reports ``target_unavailable``."""
