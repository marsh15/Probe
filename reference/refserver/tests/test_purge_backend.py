from __future__ import annotations

import json
import sqlite3

import httpx
import pytest
from mcp import Client, MCPError
from mcp.server.mcpserver import InvalidRequestState, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ElicitResult, InputRequiredResult
from refserver.config import Config
from refserver.server import HMACRequestStateCodec
from refserver.tools import backend

pytestmark = pytest.mark.anyio

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TOKEN = "probe_fake_backend_token_123"


def note_count(cfg: Config) -> int:
    conn = sqlite3.connect(cfg.db_path)
    try:
        return conn.execute("SELECT count(*) FROM notes").fetchone()[0]
    finally:
        conn.close()


def answer(action: str, confirm: bool | None = True):
    asked: list[str] = []

    async def callback(ctx: object, params: object) -> ElicitResult:
        asked.append(params.message)  # type: ignore[attr-defined]
        return ElicitResult(
            action=action, content=None if confirm is None else {"confirm": confirm}
        )

    return callback, asked


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_purge_confirmed(server: MCPServer, cfg: Config, mode: str) -> None:
    callback, asked = answer("accept")
    async with Client(server, elicitation_callback=callback, mode=mode) as client:
        result = await client.call_tool("purge_notes", {"older_than_days": 0})
    assert not result.is_error, result.content[0].text
    assert json.loads(result.content[0].text)["purged"] == 10_000
    assert asked and "older than 0 days" in asked[0]
    assert note_count(cfg) == 0


@pytest.mark.parametrize(
    ("action", "confirm"), [("decline", None), ("cancel", None), ("accept", False)]
)
async def test_purge_not_confirmed_deletes_nothing(
    server: MCPServer, cfg: Config, action: str, confirm: object
) -> None:
    callback, _ = answer(action, confirm)  # type: ignore[arg-type]
    async with Client(server, elicitation_callback=callback) as client:
        result = await client.call_tool("purge_notes", {"older_than_days": 0})
    assert json.loads(result.content[0].text)["purged"] == 0
    assert note_count(cfg) == 10_000


async def test_purge_request_state_is_signed_and_tamper_evident(
    server: MCPServer, cfg: Config
) -> None:
    callback, _ = answer(
        "accept"
    )  # declares the elicitation capability; the rounds are driven by hand
    async with Client(server, elicitation_callback=callback) as client:
        first = await client.session.call_tool(
            "purge_notes", {"older_than_days": 0}, allow_input_required=True
        )
        assert isinstance(first, InputRequiredResult)
        (key,) = first.input_requests
        responses = {key: ElicitResult(action="accept", content={"confirm": True})}
        assert first.request_state and first.request_state.startswith("rs1.")
        state = first.request_state
        payload, tag = state[4:].split(".")
        for forged in (
            state[:-2] + ("AA" if not state.endswith("AA") else "BB"),
            f"rs1.{payload}x.{tag}",
            "rs1.e30.AAAA",
        ):
            with pytest.raises(MCPError):
                await client.session.call_tool(
                    "purge_notes",
                    {"older_than_days": 0},
                    input_responses=responses,
                    request_state=forged,
                )
        assert note_count(cfg) == 10_000
        # State is bound to the arguments: replaying it for a different call is refused.
        with pytest.raises(MCPError):
            await client.session.call_tool(
                "purge_notes",
                {"older_than_days": 1},
                input_responses=responses,
                request_state=state,
            )
        done = await client.session.call_tool(
            "purge_notes", {"older_than_days": 0}, input_responses=responses, request_state=state
        )
    assert json.loads(done.content[0].text)["purged"] == 10_000


def test_hmac_codec() -> None:
    codec = HMACRequestStateCodec(b"k")
    token = codec.seal(b'{"x":1}')
    assert codec.unseal(token) == b'{"x":1}'
    for bad in (token + "A", token.replace("rs1.", "rs2."), "rs1.", "nonsense"):
        with pytest.raises(InvalidRequestState):
            codec.unseal(bad)
    with pytest.raises(InvalidRequestState):
        HMACRequestStateCodec(b"other").unseal(token)


def backend_cfg(cfg: Config, token: str | None = TOKEN) -> Config:
    return Config.for_data_root(cfg.data_root, backend_url="http://fakehttp", backend_token=token)


def scripted(response: httpx.Response, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return response

    return httpx.MockTransport(handler)


async def test_backend_sends_token_and_traceparent(cfg: Config) -> None:
    seen: list[httpx.Request] = []
    transport = scripted(httpx.Response(200, json={"id": 7, "name": "widget"}), seen)
    meta = {"traceparent": TRACEPARENT, "tracestate": "probe=1"}
    out = await backend.fetch_item(backend_cfg(cfg), 7, meta, transport)
    assert out["item"] == {"id": 7, "name": "widget"}
    sent = seen[0]
    assert str(sent.url) == "http://fakehttp/c/items/7"
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["traceparent"] == TRACEPARENT
    assert sent.headers["tracestate"] == "probe=1"


async def test_backend_drops_malformed_traceparent(cfg: Config) -> None:
    seen: list[httpx.Request] = []
    await backend.fetch_item(
        backend_cfg(cfg), 1, {"traceparent": "x\r\nevil: 1"}, scripted(httpx.Response(200), seen)
    )
    assert "traceparent" not in seen[0].headers


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(429, headers={"retry-after": "2"}), "retry after 2 seconds"),
        (httpx.Response(429), "retry after a few seconds"),
        (httpx.Response(404), "not found"),
        (httpx.Response(401, text=f"bad token {TOKEN}"), "credentials"),
        (httpx.Response(500, text=f"Traceback ... Authorization: Bearer {TOKEN}"), "HTTP 500"),
    ],
)
async def test_backend_errors_are_actionable_and_never_leak_token(
    cfg: Config, response: httpx.Response, expected: str
) -> None:
    with pytest.raises(ToolError) as info:
        await backend.fetch_item(backend_cfg(cfg), 1, None, scripted(response, []))
    assert expected in str(info.value)
    assert TOKEN not in str(info.value)


async def test_backend_redacts_echoed_token(cfg: Config) -> None:
    transport = scripted(httpx.Response(200, json={"echo": f"Bearer {TOKEN}"}), [])
    out = await backend.fetch_item(backend_cfg(cfg), 1, None, transport)
    assert TOKEN not in json.dumps(out)


async def test_backend_unreachable_and_unconfigured(cfg: Config) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect with {request.headers['authorization']}")

    with pytest.raises(ToolError) as info:
        await backend.fetch_item(backend_cfg(cfg), 1, None, httpx.MockTransport(boom))
    assert TOKEN not in str(info.value)
    with pytest.raises(ToolError, match="not configured"):
        await backend.fetch_item(backend_cfg(cfg, token=None), 1, None, None)


async def test_call_backend_tool_passes_request_meta(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    async def fake_fetch_item(
        cfg: Config, item_id: int, meta: dict[str, object] | None
    ) -> dict[str, object]:
        captured.update(meta or {})
        return {"item_id": item_id}

    monkeypatch.setattr(backend, "fetch_item", fake_fetch_item)
    result = await client.call_tool(
        "call_backend", {"item_id": 3}, meta={"traceparent": TRACEPARENT}
    )
    assert not result.is_error
    assert captured["traceparent"] == TRACEPARENT
