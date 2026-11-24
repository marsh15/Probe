"""Run the server under test as a local child process speaking MCP over stdin/stdout.

Nothing here is sandboxed and there are no fixtures: checks that need them are skipped by the
engine, and calls to tools that may write happen only with ``--allow-side-effects``.
"""

import contextlib
import os
from collections.abc import Mapping, Sequence
from pathlib import Path

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import RunnerState, TargetUnavailable
from probe.wire.limits import STDERR_RING_BYTES
from probe.wire.recorder import Recorder
from probe.wire.transport_base import CloseResult, Transport
from probe.wire.transport_stdio import StdioTransport

# Servers should not behave differently on the machine that happens to run the scan.
DEFAULT_ENV = {"TZ": "UTC", "LANG": "C.UTF-8"}


class LocalStdioRunner:
    transport_kind = TransportKind.STDIO
    sandboxed = False

    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        recorder: Recorder | None = None,
        inherit_env: bool = True,
    ) -> None:
        if not argv:
            raise ValueError("a command is required")
        self._argv = list(argv)
        self._env = dict(os.environ) if inherit_env else {}
        self._env.update(DEFAULT_ENV)  # uniform locale and zone, unless the caller says otherwise
        self._env.update(env or {})
        self._cwd = cwd
        self._recorder = recorder
        self._transport: StdioTransport | None = None
        self._extra: list[StdioTransport] = []

    async def start(self) -> Transport:
        self._transport = await self._spawn()
        return self._transport

    async def restart(self) -> Transport:
        """A fresh process. A running one is stopped first."""
        await self._stop(self._transport)
        return await self.start()

    async def second_instance(self) -> Transport | None:
        extra = await self._spawn()
        self._extra.append(extra)
        return extra

    async def check_shutdown(self) -> CloseResult:
        """Probe a fresh process; normal teardown still owns it if the caller is cancelled."""
        extra = await self.second_instance()
        if not isinstance(extra, StdioTransport):
            raise TargetUnavailable("could not start a shutdown probe")
        return await extra.close(grace_s=5, kill_after_s=5)

    async def logs(self) -> str:
        return self._transport.stderr_tail(STDERR_RING_BYTES) if self._transport else ""

    async def state(self) -> RunnerState:
        transport = self._transport
        if transport is None:
            return RunnerState(running=False)
        code = transport.returncode
        return RunnerState(running=code is None and transport.alive(), exit_code=code)

    async def stop(self) -> None:
        await self._stop(self._transport)
        for extra in self._extra:
            await self._stop(extra)
        self._extra.clear()

    async def _spawn(self) -> StdioTransport:
        try:
            return await StdioTransport.spawn(
                self._argv, env=self._env, cwd=self._cwd, recorder=self._recorder
            )
        except (OSError, ValueError) as exc:
            raise TargetUnavailable(
                f"could not start {self._argv[0]!r}: {type(exc).__name__}: {exc}"
            ) from exc

    @staticmethod
    async def _stop(transport: StdioTransport | None) -> None:
        if transport is not None:
            with contextlib.suppress(Exception):
                await transport.close()
