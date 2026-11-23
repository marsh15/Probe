"""Build a ScanContext against a scripted or real target and run checks on it."""

import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probe.checks.base import Check
from probe.checks.context import ScanConfig, ScanContext
from probe.engine.budget import Budget
from probe.engine.outcomes import CheckResult
from probe.engine.scan import run_checks
from probe.runners.local_stdio import LocalStdioRunner
from probe.runners.url import UrlRunner
from probe.wire.recorder import Recorder
from probe.wire.session import Session
from tests.engine.fakes import FakeRunner, tool
from tests.wire.fake_eras import EraServer
from tests.wire.fake_http import ServerState

MINI = Path(__file__).parent / "mini_server.py"


@dataclass
class Scan:
    ctx: ScanContext
    runner: Any
    recorder: Recorder

    async def run(self, check: type[Check]) -> CheckResult:
        [result] = await run_checks(self.ctx, [check])
        return result


def new_recorder(directory: Path, body_max_bytes: int | None = None) -> Recorder:
    directory.mkdir(parents=True, exist_ok=True)
    if body_max_bytes is None:
        return Recorder(directory / "trace.jsonl")
    return Recorder(directory / "trace.jsonl", body_max_bytes=body_max_bytes)


class ToolsServer(EraServer):
    """An EraServer that lists tools (a different set to legacy clients if asked)."""

    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        legacy_tools: list[dict[str, Any]] | None = None,
        list_extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        # Fields a modern tools/list result carries besides the tools (None removes them).
        self.list_extra = {"ttlMs": 60_000, "cacheScope": "public"}
        self.list_extra.update(list_extra or {})
        self.tools = (
            tools if tools is not None else [{"name": "a", "inputSchema": {"type": "object"}}]
        )
        self.legacy_tools = legacy_tools if legacy_tools is not None else self.tools

    def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
        reply = super()._modern(id_, method, *rest)
        if method == "tools/list" and reply and reply.body and "result" in reply.body:
            result = reply.body["result"]
            result["tools"] = self.tools
            result.update(self.list_extra)
            for key in [k for k, v in result.items() if v is None]:
                del result[key]
        return reply

    def _legacy(self, id_: Any, method: str, headers: Any) -> Any:
        reply = super()._legacy(id_, method, headers)
        if method == "tools/list" and reply.body and "result" in reply.body:
            reply.body["result"]["tools"] = self.legacy_tools
        return reply


async def _context(
    runner: Any, recorder: Recorder, *, era: str, mode: str, **kwargs: Any
) -> ScanContext:
    transport = await runner.start()
    session = await Session.open(
        transport,
        era=era,  # type: ignore[arg-type]
        probe_timeout=3,
        request_timeout=10,
    )
    return ScanContext(
        session=session,
        runner=runner,
        config=ScanConfig(mode=mode),  # type: ignore[arg-type]
        tools=[tool("read_it")],
        budget=Budget(1000),
        trace=recorder,
        **kwargs,
    )


@asynccontextmanager
async def scripted_scan(
    factory: Callable[[], EraServer],
    tmp_path: Path,
    *,
    era: str = "auto",
    mode: str = "deep",
    body_max_bytes: int | None = None,
) -> AsyncIterator[Scan]:
    """A stdio-like target answered in-process by ``factory()`` servers."""
    recorder = new_recorder(tmp_path, body_max_bytes)
    runner = FakeRunner(factory, recorder=recorder)
    try:
        yield Scan(await _context(runner, recorder, era=era, mode=mode), runner, recorder)
    finally:
        await runner.stop()
        recorder.close()


@asynccontextmanager
async def stdio_scan(
    argv: list[str],
    tmp_path: Path,
    *,
    era: str = "auto",
    mode: str = "deep",
    env: dict[str, str] | None = None,
) -> AsyncIterator[Scan]:
    """A real child process speaking over stdio."""
    recorder = new_recorder(tmp_path)
    runner = LocalStdioRunner(argv, env=env, recorder=recorder)
    try:
        yield Scan(await _context(runner, recorder, era=era, mode=mode), runner, recorder)
    finally:
        await runner.stop()
        recorder.close()


def mini_argv(*flags: str) -> list[str]:
    return [sys.executable, str(MINI), *flags]


@asynccontextmanager
async def http_scan(
    fake: tuple[str, ServerState],
    tmp_path: Path,
    *,
    server: EraServer,
    era: str = "auto",
    mode: str = "deep",
) -> AsyncIterator[Scan]:
    """An HTTP target: the scripted fake app answering as ``server`` at ``/mcp``."""
    base, state = fake
    state.script = server
    recorder = new_recorder(tmp_path)
    runner = UrlRunner(base + "/mcp", recorder=recorder)
    try:
        ctx = await _context(runner, recorder, era=era, mode=mode, second_instance_supported=False)
        yield Scan(ctx, runner, recorder)
    finally:
        await runner.stop()
        recorder.close()


@asynccontextmanager
async def url_scan(
    url: str, tmp_path: Path, *, era: str = "auto", mode: str = "deep"
) -> AsyncIterator[Scan]:
    """A real HTTP server at ``url`` (the full endpoint URL)."""
    recorder = new_recorder(tmp_path)
    runner = UrlRunner(url, recorder=recorder)
    try:
        ctx = await _context(runner, recorder, era=era, mode=mode, second_instance_supported=False)
        yield Scan(ctx, runner, recorder)
    finally:
        await runner.stop()
        recorder.close()


async def with_listing(scan: Scan) -> Scan:
    """Capture tools/list into the context, as discovery does at the start of a scan."""
    from probe.engine.discovery import list_tools, tool_infos

    listing = await list_tools(scan.ctx.client)
    scan.ctx.listing = listing
    scan.ctx.tools = tool_infos(listing.tools)
    return scan
