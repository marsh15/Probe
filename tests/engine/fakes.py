"""A fake runner, scripted servers that die or hang, and a ready-made ScanContext."""

import asyncio
from collections.abc import Callable, Sequence
from typing import Any

from probe.checks.context import ScanConfig, ScanContext
from probe.engine.budget import Budget
from probe.engine.outcomes import ToolInfo, ToolKind, Transport
from probe.runners.base import RunnerState
from probe.wire.errors import TransportClosed
from probe.wire.session import Session
from probe.wire.transport_base import Transport as WireTransport
from tests.wire.fake_eras import EraServer, Reply, ScriptedTransport, result


class DyingServer(EraServer):
    """Kills its connection when asked to call the tool `boom`; hangs `tools/list` on demand."""

    def __init__(self, *, boom_crashes: bool = True, hang_list: bool = False) -> None:
        super().__init__()
        self.boom_crashes = boom_crashes
        self.hang_list = hang_list
        self.transport: ScriptedTransport | None = None

    def handle(self, msg: dict[str, Any], headers: dict[str, str] | None) -> Reply | None:
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "tools/call" and params.get("name") == "boom" and self.boom_crashes:
            assert self.transport is not None
            self.transport._mark_closed(TransportClosed(139, "segfault"))
            return None
        if method == "tools/list" and self.hang_list:
            return None
        if method == "tools/call" and params.get("name") == "fails":
            return result(msg["id"], {"isError": True, "content": []})
        if method == "tools/call":
            return result(msg["id"], {"resultType": "complete", "isError": False, "content": []})
        return super().handle(msg, headers)


class FakeRunner:
    sandboxed = False

    def __init__(
        self,
        factory: Callable[[], EraServer] = DyingServer,
        kind: Transport = Transport.STDIO,
    ) -> None:
        self.transport_kind = kind
        self._factory = factory
        self.restarts = 0
        self.running = True
        self.exit_code: int | None = None
        self.transports: list[ScriptedTransport] = []

    def _new(self) -> ScriptedTransport:
        server = self._factory()
        transport = ScriptedTransport(server)
        if isinstance(server, DyingServer):
            server.transport = transport
        self.transports.append(transport)
        return transport

    async def start(self) -> WireTransport:
        return self._new()

    async def restart(self) -> WireTransport:
        self.restarts += 1
        self.running = True
        return self._new()

    async def second_instance(self) -> WireTransport | None:
        return self._new()

    async def logs(self) -> str:
        return ""

    async def state(self) -> RunnerState:
        return RunnerState(self.running, None if self.running else self.exit_code)

    async def stop(self) -> None:
        self.running = False

    def kill(self, exit_code: int = 137) -> None:
        self.running = False
        self.exit_code = exit_code


class FakeFixtures:
    def __init__(self) -> None:
        self.resets = 0

    async def reset(self) -> None:
        self.resets += 1


def tool(name: str, kind: ToolKind = "read", flags: Sequence[str] = ()) -> ToolInfo:
    return ToolInfo(
        name=name,
        title=None,
        description=None,
        input_schema={"type": "object"},
        output_schema=None,
        annotations={},
        kind=kind,
        flags=set(flags),  # type: ignore[arg-type]
        classification_source="heuristic",
        classification_reason="test",
        param_roles={},
    )


async def make_context(
    *,
    runner: FakeRunner | None = None,
    tools: Sequence[ToolInfo] | None = None,
    era: str = "modern",
    budget_calls: int = 1000,
    config: ScanConfig | None = None,
    **kwargs: Any,
) -> tuple[ScanContext, FakeRunner]:
    runner = runner or FakeRunner()
    transport = await runner.start()
    if era == "legacy":
        # The scripted server is modern by default; a legacy one must also speak initialize.
        server = transport.server  # type: ignore[attr-defined]
        server.legacy, server.modern = True, False
        server.legacy_probe = "error"
    session = await Session.open(transport, era=era, probe_timeout=2, request_timeout=5)  # type: ignore[arg-type]
    ctx = ScanContext(
        session=session,
        runner=runner,
        config=config or ScanConfig(),
        tools=tools if tools is not None else [tool("read_it")],
        budget=Budget(budget_calls),
        **kwargs,
    )
    return ctx, runner


async def settle() -> None:
    await asyncio.sleep(0)
