"""Streamable HTTP: per-identity tool lists, bearer auth, PRM, Origin, middleware transparency."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import ElicitResult
from refserver.config import Config
from refserver.server import build_server, http_app
from refserver.wire_bugs import WireBugMiddleware

pytestmark = pytest.mark.anyio

TOKENS = {"tok-alice-123": "alice", "tok-bob-456": "bob"}
SCOPES = ["notes:read", "notes:write"]


@contextmanager
def serving(app: object) -> Iterator[str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))  # type: ignore[arg-type]
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def authed_url(data_root: Path) -> Iterator[str]:
    cfg = Config.for_data_root(data_root, secret=b"s", tokens=dict(TOKENS))
    with serving(http_app(build_server(cfg))) as url:
        yield url


@pytest.fixture
def open_url(cfg: Config) -> Iterator[str]:
    with serving(http_app(build_server(cfg))) as url:
        yield url


async def http_request(method: str, url: str, **kwargs: object) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.request(method, url, **kwargs)  # type: ignore[arg-type]


@asynccontextmanager
async def connect(
    base: str, token: str | None = None, mode: str = "auto", **kwargs: object
) -> AsyncIterator[Client]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transport = streamable_http_client(
        f"{base}/mcp", http_client=httpx2.AsyncClient(headers=headers)
    )
    async with Client(transport, mode=mode, **kwargs) as client:  # type: ignore[arg-type]
        yield client


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_tools_list_differs_per_identity(authed_url: str, mode: str) -> None:
    names = {}
    for token, who in TOKENS.items():
        async with connect(authed_url, token, mode) as client:
            listing = await client.list_tools()
            names[who] = [t.name for t in listing.tools]
            if mode == "auto":
                assert client.protocol_version == "2026-07-28"
                assert listing.cache_scope == "private"
            else:
                assert client.protocol_version == "2025-11-25"
    assert "purge_notes" in names["alice"]
    assert names["bob"] == [n for n in names["alice"] if n != "purge_notes"]


async def test_bob_cannot_call_hidden_tool(authed_url: str) -> None:
    async with connect(authed_url, "tok-bob-456") as client:
        result = await client.call_tool("purge_notes", {"older_than_days": 0})
    assert result.is_error
    assert result.content[0].text == "Unknown tool: purge_notes"


async def test_alice_purge_over_http_uses_mrtr(authed_url: str) -> None:
    async def confirm(ctx: object, params: object) -> ElicitResult:
        return ElicitResult(action="accept", content={"confirm": True})

    async with connect(authed_url, "tok-alice-123", elicitation_callback=confirm) as client:
        result = await client.call_tool("purge_notes", {"older_than_days": 0})
    assert json.loads(result.content[0].text)["purged"] == 10_000


@pytest.mark.parametrize("header", [None, "Bearer wrong-token", "Basic dG9rLWFsaWNlLTEyMw=="])
async def test_requests_without_valid_token_rejected(authed_url: str, header: str | None) -> None:
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if header:
        headers["authorization"] = header
    response = await http_request(
        "POST",
        f"{authed_url}/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code == 401
    assert "bearer" in response.headers.get("www-authenticate", "").lower()


@pytest.mark.parametrize(
    "path", ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]
)
async def test_prm_document(authed_url: str, path: str) -> None:
    doc = (await http_request("GET", authed_url + path)).json()
    assert doc["resource"] == f"{authed_url}/mcp"
    assert doc["scopes_supported"] == SCOPES
    assert doc["authorization_servers"]


async def test_unauthenticated_mode(open_url: str) -> None:
    async with connect(open_url) as client:
        listing = await client.list_tools()
    assert listing.cache_scope == "public"
    assert "purge_notes" in [t.name for t in listing.tools]
    missing = await http_request("GET", open_url + "/.well-known/oauth-protected-resource")
    assert missing.status_code == 404


async def test_foreign_origin_rejected(open_url: str) -> None:
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "origin": "http://evil.example",
    }
    response = await http_request(
        "POST",
        f"{open_url}/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code == 403


async def test_wire_middleware_is_transparent(cfg: Config) -> None:
    wrapped = http_app(build_server(cfg))
    assert isinstance(wrapped, WireBugMiddleware)

    # Each app instance can be served once (its session manager runs once), so compare
    # a bare SDK app with a wrapped one built from the same config.
    bare = http_app(build_server(cfg)).inner
    results = []
    for app in (bare, wrapped):
        with serving(app) as url:
            async with connect(url) as client:
                listing = (await client.list_tools()).model_dump(by_alias=True)
                note = (await client.call_tool("notes_get", {"id": 9})).model_dump(by_alias=True)
        results.append((listing, note))
    assert results[0] == results[1]


async def test_wire_middleware_applies_hooks(cfg: Config) -> None:
    def tag_responses(app):
        async def wrapper(scope, receive, send):
            async def tagged_send(message):
                if message["type"] == "http.response.start":
                    message = {**message, "headers": [*message["headers"], (b"x-wire-hook", b"1")]}
                await send(message)

            await app(scope, receive, tagged_send)

        return wrapper

    inner = build_server(cfg).streamable_http_app()
    with serving(WireBugMiddleware(inner, hooks=[tag_responses])) as url:
        response = await http_request("GET", url + "/mcp", headers={"accept": "text/event-stream"})
    assert response.headers["x-wire-hook"] == "1"
