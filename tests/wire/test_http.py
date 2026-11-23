"""HttpTransport against a scripted local server (see fake_http.py)."""

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from probe.wire.errors import (
    MalformedMessage,
    OversizeMessage,
    ProtocolViolation,
    RequestTimeout,
    TransportClosed,
    UnmatchedResponse,
)
from probe.wire.jsonrpc import ErrorResponse, Notification, Request, ResultResponse
from probe.wire.recorder import Recorder, read_trace
from probe.wire.transport_http import HttpRequestFailed, HttpTransport
from tests.wire.fake_http import ServerState, serve

Connect = Callable[..., Awaitable[HttpTransport]]


@pytest.fixture
async def server() -> AsyncIterator[tuple[str, ServerState]]:
    async with serve() as running:
        yield running


@pytest.fixture
async def connect(server: tuple[str, ServerState]) -> AsyncIterator[Connect]:
    base, _ = server
    opened: list[HttpTransport] = []

    async def _connect(path: str, **kwargs: Any) -> HttpTransport:
        transport = HttpTransport(base + path, **kwargs)
        opened.append(transport)
        return transport

    yield _connect
    for transport in opened:
        await transport.close()


def req(id_: int | str, method: str = "m", **params: Any) -> dict[str, Any]:
    return Request(id_, method, params).to_obj()


def violations(t: HttpTransport) -> list[str]:
    return [e.rule for e in t.events() if isinstance(e, ProtocolViolation)]


async def test_json_response(connect: Connect, server: tuple[str, ServerState]) -> None:
    t = await connect("/json")
    assert (await t.request(req(1, "tools/list"), timeout=5)).unwrap() == {"echo": "tools/list"}
    sent = server[1].seen[0]["headers"]
    assert sent["content-type"] == "application/json"
    assert sent["accept"] == "application/json, text/event-stream"
    assert sent["accept-encoding"] == "identity"


async def test_notification_gets_202_and_no_response(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/json")
    result = await t.post(Notification("notifications/initialized").to_obj())
    assert result.status == 202
    assert result.responses == ()
    assert json.loads(server[1].seen[0]["body"])["method"] == "notifications/initialized"


async def test_extra_headers_are_sent_with_every_post(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/json", headers={"MCP-Protocol-Version": "2026-07-28"})
    await t.request(req(1), timeout=5)
    await t.post(req(2), headers={"Mcp-Method": "m"})
    first, second = (s["headers"] for s in server[1].seen)
    assert first["mcp-protocol-version"] == second["mcp-protocol-version"] == "2026-07-28"
    assert second["mcp-method"] == "m"


async def test_sse_stream_with_comments_crlf_and_multiline_data(connect: Connect) -> None:
    t = await connect("/sse")
    response = await t.request(req(7), timeout=5)
    assert response.unwrap() == {"ok": True}
    # The notification arrived on the same stream, before the response.
    async with asyncio.timeout(2):
        first = await anext(t.notifications())
    assert first == Notification("notifications/message", {"n": 1})


async def test_server_request_inside_sse_is_answered_with_a_separate_post(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/sse-ask")

    async def handler(request: Request) -> Any:
        assert request.method == "ping"
        return {}

    t.on_server_request(handler)
    assert (await t.request(req(1), timeout=5)).unwrap() == {"asked": True}
    assert server[1].replies == [{"jsonrpc": "2.0", "id": "srv-1", "result": {}}]


async def test_cut_off_sse_event_is_reported_and_fails_the_request(connect: Connect) -> None:
    t = await connect("/sse-truncated")
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert info.value.status == 200
    assert "sse_truncated_event" in violations(t)


async def test_odd_sse_events_are_reported_but_do_not_break_the_stream(connect: Connect) -> None:
    t = await connect("/sse-odd")
    assert (await t.request(req(1), timeout=5)).unwrap() == {"ok": 1}
    assert "sse_event_type" in violations(t)  # `event: ping` is not an MCP message
    malformed = [e for e in t.events() if isinstance(e, MalformedMessage)]
    assert [e.excerpt for e in malformed] == ["not json"]  # the priming event is silent


async def test_oversize_sse_stream_is_aborted_and_the_connection_closed(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/sse-big", max_stream_bytes=1024 * 1024)
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert "1048576" in (info.value.result.aborted or "")
    assert any(isinstance(e, OversizeMessage) and not e.complete for e in t.events())
    async with asyncio.timeout(5):
        await server[1].stream_closed.wait()


async def test_sse_event_flood_is_aborted(connect: Connect) -> None:
    t = await connect("/sse-many", max_stream_events=50)
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert "50 events" in (info.value.result.aborted or "")
    assert "sse_event_limit" in violations(t)


async def test_endless_stream_times_out_and_closing_it_cancels_the_call(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/sse-endless")
    with pytest.raises(RequestTimeout):
        await t.request(req(1), timeout=0.3)
    async with asyncio.timeout(5):
        await server[1].stream_closed.wait()


async def test_silent_server_times_out(connect: Connect) -> None:
    t = await connect("/hang")
    with pytest.raises(RequestTimeout) as info:
        await t.request(req(1), timeout=0.2)
    assert info.value.request_id == 1


async def test_oversize_json_body_is_aborted(connect: Connect) -> None:
    t = await connect("/json-big", max_message_bytes=100_000)
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert "100000" in (info.value.result.aborted or "")
    assert any(isinstance(e, OversizeMessage) and not e.complete for e in t.events())


async def test_error_status_without_a_json_rpc_body_raises_with_the_status(
    connect: Connect,
) -> None:
    t = await connect("/status/500")
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert info.value.status == 500
    assert info.value.result.body == b"<html>oops</html>"


async def test_error_status_with_a_json_rpc_body_is_still_a_response(connect: Connect) -> None:
    t = await connect("/modern-400")
    response = await t.request(req(1), timeout=5)
    assert isinstance(response, ErrorResponse)
    assert response.error.code == -32022
    result = await t.post(req(2))
    assert result.status == 400
    assert isinstance(result.responses[0], ErrorResponse)


async def test_response_with_the_wrong_id_fails_fast_and_is_reported(connect: Connect) -> None:
    t = await connect("/wrong-id")
    with pytest.raises(HttpRequestFailed):
        await t.request(req(1), timeout=5)
    assert UnmatchedResponse(id="someone-else", late=False) in t.events()


async def test_redirects_are_not_followed(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/redirect")
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert info.value.status == 307
    assert len(server[1].seen) == 1


async def test_content_encoding_is_never_decoded(connect: Connect) -> None:
    t = await connect("/gzip")
    with pytest.raises(HttpRequestFailed) as info:
        await t.request(req(1), timeout=5)
    assert info.value.result.body[:2] == b"\x1f\x8b"  # still compressed: no decompression bomb
    assert any(isinstance(e, MalformedMessage) for e in t.events())


async def test_unexpected_content_type_on_success_is_reported(connect: Connect) -> None:
    t = await connect("/text")
    with pytest.raises(HttpRequestFailed):
        await t.request(req(1), timeout=5)
    assert "http_unexpected_content_type" in violations(t)


async def test_session_id_is_captured_and_replayed(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/session")
    assert (await t.request(req(1), timeout=5)).unwrap() == {"seen": None}
    assert t.session_id == "sess-1"
    assert (await t.request(req(2), timeout=5)).unwrap() == {"seen": "sess-1"}


async def test_raw_http_sends_exactly_what_it_is_given(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/echo", headers={"MCP-Protocol-Version": "2026-07-28"})
    t.session_id = "sess-9"
    result = await t.raw_http({"Content-Type": "text/plain", "X-Odd": "1"}, b"\xff not json")
    assert result.status == 200
    seen = server[1].seen[0]
    assert seen["body"] == b"\xff not json"
    assert seen["headers"]["x-odd"] == "1"
    assert "mcp-protocol-version" not in seen["headers"]
    assert "mcp-session-id" not in seen["headers"]
    assert json.loads(result.body)["method"] == "POST"


async def test_raw_http_can_use_other_methods(connect: Connect) -> None:
    t = await connect("/echo")
    result = await t.raw_http({"Origin": "http://evil.example"}, b"", method="DELETE")
    assert json.loads(result.body)["method"] == "DELETE"


async def test_raw_http_reports_connection_failure_instead_of_raising(
    server: tuple[str, ServerState],
) -> None:
    t = HttpTransport("http://127.0.0.1:1/")  # nothing listens on port 1
    try:
        result = await t.raw_http({}, b"{}")
        assert result.status is None
        assert result.error is not None
        with pytest.raises(HttpRequestFailed) as info:
            await t.request(req(1), timeout=5)
        assert info.value.status is None
    finally:
        await t.close()


async def test_close_fails_an_in_flight_request(connect: Connect) -> None:
    t = await connect("/sse-endless")
    pending = asyncio.create_task(t.request(req(1), timeout=30))
    await asyncio.sleep(0.2)
    await t.close()
    with pytest.raises(TransportClosed):
        await pending
    with pytest.raises(TransportClosed):
        await t.request(req(2), timeout=1)
    assert not t.alive()


async def test_trace_has_http_metadata_and_redacts_credentials(
    connect: Connect, tmp_path: Path
) -> None:
    recorder = Recorder(tmp_path / "trace.jsonl")
    t = await connect("/json", headers={"Authorization": "Bearer hunter2-token"}, recorder=recorder)
    await t.request(req(1), timeout=5)
    await t.close()
    records = read_trace(recorder.close())
    c2s = next(r for r in records if r["dir"] == "c2s")
    s2c = next(r for r in records if r["dir"] == "s2c")
    assert c2s["transport"] == "http"
    assert "hunter2-token" not in json.dumps(records)
    assert c2s["http"]["headers"]["Content-Type"] == "application/json"
    assert s2c["http"]["status"] == 200
    assert isinstance(s2c["body"]["result"], dict)


async def test_json_rpc_replies_are_sent_as_posts_expecting_202(
    connect: Connect, server: tuple[str, ServerState]
) -> None:
    t = await connect("/json")
    reply = ResultResponse("srv-1", {}).to_obj()
    await t.send(reply)
    assert json.loads(server[1].seen[0]["body"]) == reply
