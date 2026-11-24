"""Lifecycle and fixture hooks observe targets without losing normal cleanup ownership."""

import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from probe.config.profile import FixturesSection
from probe.engine.fixtures import ScanFixtures
from probe.runners.base import RunnerState
from probe.runners.container import ContainerRunner
from probe.runners.local_stdio import LocalStdioRunner
from probe.wire.transport_base import CloseResult
from probe.wire.transport_stdio import StdioTransport


async def test_local_shutdown_keeps_the_main_process_alive_and_teardown_idempotent():
    runner = LocalStdioRunner([sys.executable, "-c", "import sys; sys.stdin.read()"])
    main = await runner.start()
    try:
        result = await runner.check_shutdown()
        assert result == CloseResult(0)
        assert main.alive()
    finally:
        await runner.stop()
        await runner.stop()
    assert not main.alive()


async def test_local_shutdown_supplies_both_five_second_deadlines(monkeypatch):
    runner = LocalStdioRunner([sys.executable, "-c", "pass"])
    extra = await runner.second_instance()
    close = AsyncMock(return_value=CloseResult(0))
    original_close = StdioTransport.close
    monkeypatch.setattr(runner, "second_instance", AsyncMock(return_value=extra))
    monkeypatch.setattr(extra, "close", close)
    try:
        await runner.check_shutdown()
        close.assert_awaited_once_with(grace_s=5, kill_after_s=5)
    finally:
        await original_close(extra, grace_s=0, kill_after_s=0)


@pytest.mark.parametrize("ignores_term", [False, True])
async def test_container_shutdown_observes_container_state_and_cleans(ignores_term, monkeypatch):
    from probe.runners import container as module

    now = iter([0, 0, 6]) if ignores_term else iter([0, 0])
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(now)))
    runner = object.__new__(ContainerRunner)
    signals = []
    instance = SimpleNamespace(
        container=SimpleNamespace(kill=lambda **kw: signals.append(kw)),
        transport=SimpleNamespace(close=AsyncMock(return_value=CloseResult(-9, True, True))),
    )
    runner._extras = [instance]
    runner.second_instance = AsyncMock(return_value=instance.transport)
    runner._state = AsyncMock(side_effect=[RunnerState(True), RunnerState(ignores_term, 0)])
    runner._stop_instance = AsyncMock()
    result = await runner.check_shutdown()
    assert result.killed == ignores_term  # the docker CLI's SIGKILL is irrelevant
    assert signals == [{"signal": "SIGTERM"}]
    instance.transport.close.assert_awaited_once_with(grace_s=5, kill_after_s=0)
    runner._stop_instance.assert_awaited_once_with(instance, kill=True)
    assert not runner._extras


async def test_container_shutdown_cancellation_still_cleans(monkeypatch):
    runner = object.__new__(ContainerRunner)
    instance = SimpleNamespace(
        transport=SimpleNamespace(close=AsyncMock(side_effect=asyncio.CancelledError))
    )
    runner._extras = [instance]
    runner.second_instance = AsyncMock(return_value=instance.transport)
    runner._stop_instance = AsyncMock()
    with pytest.raises(asyncio.CancelledError):
        await runner.check_shutdown()
    runner._stop_instance.assert_awaited_once_with(instance, kill=True)
    assert not runner._extras


async def test_fixture_fault_uses_control_api_only_and_no_http_is_optional(monkeypatch):
    fixtures = ScanFixtures(None, FixturesSection(), token="0123456789abcdef")
    assert await fixtures.backend_fault("/c/items/1") is False
    fixtures._services["fakehttp"] = "http://127.0.0.1:1234"
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"fault": True})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        "probe.engine.fixtures.httpx.AsyncClient",
        lambda **kw: original(**kw, transport=httpx.MockTransport(handle)),
    )
    assert await fixtures.backend_fault("/c/items/1", count=50)
    assert await fixtures.backend_fault(None)
    assert requests[0].url.path == "/_probe/fault"
    assert json.loads(requests[0].content) == {
        "route": "/c/items/1",
        "status": 429,
        "retry_after": 2,
        "count": 50,
    }
    assert requests[1].url.path == "/_probe/reset"
