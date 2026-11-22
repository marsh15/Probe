"""StdioTransport against scripted fake servers (each one a real subprocess)."""

import asyncio
import json
import signal
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from probe.wire.errors import (
    JsonRpcError,
    MalformedMessage,
    OversizeMessage,
    ProcessExited,
    RequestTimeout,
    StdoutNoise,
    TransportClosed,
    UnmatchedResponse,
)
from probe.wire.jsonrpc import Notification, Request, ResultResponse
from probe.wire.recorder import Recorder, read_trace
from probe.wire.transport_stdio import StdioTransport

FAKES = Path(__file__).parent / "fake_servers"

Spawn = Callable[..., Awaitable[StdioTransport]]


def argv(name: str, *args: str) -> list[str]:
    return [sys.executable, str(FAKES / f"{name}.py"), *args]


@pytest.fixture
async def spawn() -> AsyncIterator[Spawn]:
    started: list[StdioTransport] = []

    async def _spawn(name: str, *args: str, **kwargs: Any) -> StdioTransport:
        transport = await StdioTransport.spawn(argv(name, *args), **kwargs)
        started.append(transport)
        return transport

    yield _spawn
    for transport in started:
        await transport.close(grace_s=0.5, kill_after_s=0.5)


def req(id_: int | str, method: str = "m", **params: Any) -> dict[str, Any]:
    return Request(id_, method, params).to_obj()


async def wait_until(predicate: Callable[[], bool], within: float = 5.0) -> None:
    async with asyncio.timeout(within):
        while not predicate():  # noqa: ASYNC110 - polls transport state that has no event
            await asyncio.sleep(0.01)


def events_of[T](transport: StdioTransport, kind: type[T]) -> list[T]:
    return [e for e in transport.events() if isinstance(e, kind)]


async def test_concurrent_requests_are_correlated_by_id(spawn: Spawn) -> None:
    t = await spawn("slow")
    delays = {1: 0.3, 2: 0.1, 3: 0.2, "four": 0.0}
    responses = await asyncio.gather(
        *(t.request(req(i, delay=d), timeout=5) for i, d in delays.items())
    )
    assert [r.unwrap() for r in responses] == list(delays)


async def test_notifications_are_delivered(spawn: Spawn) -> None:
    t = await spawn("echo")
    await t.request(req(1, "notify", level="info"), timeout=5)
    stream = t.notifications()
    note = await asyncio.wait_for(anext(stream), 5)
    assert note == Notification("notifications/message", {"level": "info"})


async def test_notification_stream_ends_when_transport_closes(spawn: Spawn) -> None:
    t = await spawn("echo")
    await t.close()
    assert [n async for n in t.notifications()] == []


async def test_stdout_noise_is_recorded_and_skipped(spawn: Spawn, tmp_path: Path) -> None:
    recorder = Recorder(tmp_path / "trace.jsonl")
    t = await spawn("noisy", recorder=recorder)
    assert (await t.request(req(1), timeout=5)).unwrap() == {"ok": True}

    excerpts = [e.excerpt for e in events_of(t, StdoutNoise)]
    assert excerpts == [
        "noisy server starting up",
        '{"jsonrpc": "2.0", "id": ',
        "debug: handling request",
        "",
    ]
    recorded = [r["body"] for r in read_trace(recorder.close()) if r["dir"] == "event"]
    assert [b["excerpt"] for b in recorded if b["kind"] == "stdout_noise"] == excerpts


async def test_oversize_line_is_discarded_and_stream_stays_alive(spawn: Spawn) -> None:
    size = 2 * 1024 * 1024
    t = await spawn("oversize", str(size), max_message_bytes=1024 * 1024)
    response = await t.request(req(1), timeout=10)
    assert response == ResultResponse(1, "small")
    [event] = events_of(t, OversizeMessage)
    assert event == OversizeMessage(length=size, limit=1024 * 1024, complete=True)
    assert t.alive()


def test_oversize_32_mib_line_keeps_peak_rss_under_200_mb() -> None:
    # A fresh interpreter, so the peak measures only this scenario and not the whole test run.
    harness = Path(__file__).parent / "oversize_rss_harness.py"
    out = subprocess.run(  # noqa: S603 - our own interpreter and harness
        [sys.executable, str(harness)], capture_output=True, check=True, timeout=120
    )
    report = json.loads(out.stdout)
    print(f"peak RSS while streaming a 32 MiB line: {report['peak_rss_bytes'] / 2**20:.1f} MiB")
    assert report["result"] == "small"
    assert report["oversize_length"] == 32 * 1024 * 1024
    assert report["peak_rss_bytes"] < 200 * 1024 * 1024


async def test_crash_fails_pending_requests_with_exit_code(spawn: Spawn) -> None:
    t = await spawn("crash", "3")
    with pytest.raises(TransportClosed) as info:
        await t.request(req(1), timeout=5)
    assert info.value.exit_code == 3
    assert not t.alive()
    assert "fatal: something broke" in t.stderr_tail()
    assert ProcessExited(exit_code=3) in t.events()
    with pytest.raises(TransportClosed):
        await t.request(req(2), timeout=5)


async def test_stderr_ring_buffer_keeps_the_last_mib_sanitized(spawn: Spawn) -> None:
    t = await spawn("echo")
    await t.request(req(1, "stderr", text="0123456789", repeat=150_000), timeout=10)
    await t.request(req(2, "stderr", text="\x1b[31mred\x1b[0m END"), timeout=5)
    await wait_until(lambda: t.stderr_tail(4).endswith("END"))

    everything = t.stderr_tail(10 * 1024 * 1024)
    assert len(everything) <= 1024 * 1024
    assert len(everything) > 1024 * 1024 - 20  # only the escape bytes were stripped
    assert everything.endswith("789red END")
    assert "\x1b" not in everything
    assert t.stderr_tail(3) == "END"


async def test_timeout_raises_and_late_response_is_recorded_then_dropped(
    spawn: Spawn, tmp_path: Path
) -> None:
    recorder = Recorder(tmp_path / "trace.jsonl")
    t = await spawn("slow", recorder=recorder)
    with pytest.raises(RequestTimeout) as info:
        await t.request(req(1, delay=0.5), timeout=0.1)
    assert info.value.request_id == 1
    assert (await t.request(req(2, delay=0.8), timeout=5)).unwrap() == 2

    assert UnmatchedResponse(id=1, late=True) in t.events()
    records = read_trace(recorder.close())
    assert [r["body"]["id"] for r in records if r["dir"] == "c2s"] == [1, 2]
    assert sorted(r["body"]["id"] for r in records if r["dir"] == "s2c" and "id" in r["body"]) == [
        1,
        2,
    ]


async def test_response_with_unknown_id_is_recorded_not_fatal(spawn: Spawn) -> None:
    t = await spawn("echo")
    response = await t.request(req(1, "unknown_id"), timeout=5)
    assert response.unwrap() == {"method": "unknown_id", "params": {}}
    assert UnmatchedResponse(id="no-such-id", late=False) in t.events()


async def test_server_request_is_answered_by_the_handler(spawn: Spawn) -> None:
    t = await spawn("server_request")
    seen: list[Request] = []

    async def handler(request: Request) -> Any:
        seen.append(request)
        return {"roots": []}

    t.on_server_request(handler)
    result = (await t.request(req(1), timeout=5)).unwrap()
    assert seen == [Request("srv-1", "roots/list", {})]
    assert result["reply"] == {"jsonrpc": "2.0", "id": "srv-1", "result": {"roots": []}}


async def test_handler_json_rpc_error_becomes_an_error_reply(spawn: Spawn) -> None:
    t = await spawn("server_request")

    async def handler(request: Request) -> Any:
        raise JsonRpcError(-32602, "bad roots", {"why": "test"})

    t.on_server_request(handler)
    result = (await t.request(req(1), timeout=5)).unwrap()
    assert result["reply"]["error"] == {
        "code": -32602,
        "message": "bad roots",
        "data": {"why": "test"},
    }


async def test_server_request_without_handler_gets_method_not_found(spawn: Spawn) -> None:
    t = await spawn("server_request")
    result = (await t.request(req(1), timeout=5)).unwrap()
    assert result["reply"]["id"] == "srv-1"
    assert result["reply"]["error"]["code"] == -32601


async def test_deeply_nested_line_is_malformed_and_stream_survives(spawn: Spawn) -> None:
    t = await spawn("echo")
    response = await t.request(req(1, "deep", depth=200_000), timeout=10)
    assert response.unwrap()["method"] == "deep"
    assert any("nest" in e.reason for e in events_of(t, MalformedMessage))


async def test_wrong_shape_response_is_malformed_and_ignored(spawn: Spawn) -> None:
    t = await spawn("echo")
    response = await t.request(req(1, "bad_shape"), timeout=5)
    assert response.unwrap()["method"] == "bad_shape"
    assert len(events_of(t, MalformedMessage)) == 1


async def test_raw_line_is_written_verbatim_and_recorded(spawn: Spawn, tmp_path: Path) -> None:
    recorder = Recorder(tmp_path / "trace.jsonl")
    t = await spawn("echo", recorder=recorder)
    raw = b'{"jsonrpc":"2.0","id":9,"method":"raw"}\n'
    await t.raw_stdio_line(raw)
    await wait_until(lambda: UnmatchedResponse(id=9, late=False) in t.events())
    c2s = [r["body"] for r in read_trace(recorder.close()) if r["dir"] == "c2s"]
    assert c2s == [raw.decode()]


async def test_send_writes_a_notification_and_records_it(spawn: Spawn, tmp_path: Path) -> None:
    recorder = Recorder(tmp_path / "trace.jsonl")
    t = await spawn("echo", recorder=recorder)
    await t.send(Notification("notifications/initialized").to_obj())
    await t.request(req(1), timeout=5)
    records = read_trace(recorder.close())
    assert [(r["dir"], r["transport"]) for r in records] == [
        ("c2s", "stdio"),
        ("c2s", "stdio"),
        ("s2c", "stdio"),
    ]
    assert records[0]["body"] == {"jsonrpc": "2.0", "method": "notifications/initialized"}


async def test_request_rejects_non_requests_and_duplicate_pending_ids(spawn: Spawn) -> None:
    t = await spawn("slow")
    with pytest.raises(ValueError, match="request"):
        await t.request(Notification("n").to_obj(), timeout=1)
    first = asyncio.create_task(t.request(req(1, delay=0.3), timeout=5))
    await asyncio.sleep(0)
    with pytest.raises(ValueError, match="pending"):
        await t.request(req(1), timeout=1)
    assert (await first).unwrap() == 1


async def test_close_is_clean_when_server_exits_on_stdin_eof(spawn: Spawn) -> None:
    t = await spawn("echo")
    result = await t.close()
    assert (result.exit_code, result.terminated, result.killed) == (0, False, False)
    assert not t.alive()
    assert await t.close() == result


async def test_close_sends_sigterm_to_a_lingering_server(spawn: Spawn) -> None:
    t = await spawn("slow", "--linger")
    await asyncio.wait_for(anext(t.notifications()), 5)  # "ready": the server is up
    result = await t.close(grace_s=0.2)
    assert (result.exit_code, result.terminated, result.killed) == (-signal.SIGTERM, True, False)


async def test_close_kills_a_server_that_ignores_sigterm(spawn: Spawn) -> None:
    t = await spawn("slow", "--linger", "--ignore-term")
    await asyncio.wait_for(anext(t.notifications()), 5)
    result = await t.close(grace_s=0.2, kill_after_s=0.3)
    assert (result.exit_code, result.terminated, result.killed) == (-signal.SIGKILL, True, True)


async def test_wraps_an_existing_process(tmp_path: Path) -> None:
    process = await asyncio.create_subprocess_exec(
        *argv("echo"),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    t = StdioTransport(process)
    try:
        assert (await t.request(req(1), timeout=5)).unwrap()["method"] == "m"
    finally:
        await t.close()
