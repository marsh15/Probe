"""A scripted local MCP-over-HTTP server. Each path misbehaves in exactly one way.

It runs under uvicorn on a real socket, so aborted streams, timeouts and connection closes
are the real thing. ``state`` records what the server saw, for assertions.
"""

import asyncio
import gzip
import json
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route


@dataclass
class ServerState:
    seen: list[dict[str, Any]] = field(default_factory=list)
    replies: list[Any] = field(default_factory=list)
    reply_arrived: asyncio.Event = field(default_factory=asyncio.Event)
    stream_closed: asyncio.Event = field(default_factory=asyncio.Event)


def rpc(id_: Any, **fields: Any) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": id_, **fields}).encode()


NOTIFICATION = b'{"jsonrpc":"2.0","method":"notifications/message","params":{"n":1}}'


def build_app(state: ServerState) -> Starlette:
    async def body_json(request: Request) -> Any:
        raw = await request.body()
        state.seen.append({"method": request.method, "headers": dict(request.headers), "body": raw})
        return json.loads(raw) if raw else None

    def sse(chunks: AsyncIterator[bytes]) -> StreamingResponse:
        async def watched() -> AsyncIterator[bytes]:
            try:
                async for chunk in chunks:
                    yield chunk
            finally:
                state.stream_closed.set()

        return StreamingResponse(watched(), media_type="text/event-stream")

    async def json_ok(request: Request) -> Response:
        message = await body_json(request)
        if "method" not in message or "id" not in message:  # a notification or a client reply
            return Response(status_code=202)
        return Response(
            rpc(message["id"], result={"echo": message["method"]}), media_type="application/json"
        )

    async def sse_ok(request: Request) -> Response:
        message = await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            yield b": priming\r\n\r\n"
            yield b"event: message\r\ndata: " + NOTIFICATION + b"\r\n\r\n"
            # One JSON message spread over several data lines is still one message.
            yield (
                b'data: {"jsonrpc":"2.0",\ndata: "id":'
                + json.dumps(message["id"]).encode()
                + b',\ndata: "result":{"ok":true}}\n\n'
            )

        return sse(chunks())

    async def sse_ask(request: Request) -> Response:
        message = await body_json(request)
        if "method" not in message:  # the client's reply to our request
            state.replies.append(message)
            state.reply_arrived.set()
            return Response(status_code=202)

        async def chunks() -> AsyncIterator[bytes]:
            yield b'data: {"jsonrpc":"2.0","id":"srv-1","method":"ping"}\n\n'
            await asyncio.wait_for(state.reply_arrived.wait(), 5)
            yield b"data: " + rpc(message["id"], result={"asked": True}) + b"\n\n"

        return sse(chunks())

    async def sse_truncated(request: Request) -> Response:
        message = await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            yield b"data: " + rpc(message["id"], result={}) + b"\n"  # no blank line

        return sse(chunks())

    async def sse_odd_events(request: Request) -> Response:
        message = await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            yield b"event: ping\ndata: {}\n\n"
            yield b"id: 1\ndata:\n\n"  # a priming event
            yield b"data: not json\n\n"
            yield b"data: " + rpc(message["id"], result={"ok": 1}) + b"\n\n"

        return sse(chunks())

    async def sse_forever_big(request: Request) -> Response:
        await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            yield b"data: "
            while True:
                yield b"x" * 65536
                await asyncio.sleep(0)

        return sse(chunks())

    async def sse_many_events(request: Request) -> Response:
        await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            for _ in range(1000):
                yield b"data: " + NOTIFICATION + b"\n\n"

        return sse(chunks())

    async def sse_endless(request: Request) -> Response:
        await body_json(request)

        async def chunks() -> AsyncIterator[bytes]:
            while True:
                yield b": still here\n\n"
                await asyncio.sleep(0.01)

        return sse(chunks())

    async def hang(request: Request) -> Response:
        await body_json(request)
        await asyncio.sleep(60)
        return Response(status_code=204)

    async def json_big(request: Request) -> Response:
        await body_json(request)
        return Response(b'{"pad":"' + b"x" * 200_000 + b'"}', media_type="application/json")

    async def status(request: Request) -> Response:
        await body_json(request)
        return Response(
            "<html>oops</html>",
            status_code=int(request.path_params["code"]),
            media_type="text/html",
        )

    async def modern_400(request: Request) -> Response:
        message = await body_json(request)
        error = {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32022, "message": "bad version"},
        }
        return JSONResponse(error, status_code=400)

    async def wrong_id(request: Request) -> Response:
        await body_json(request)
        return Response(rpc("someone-else", result={}), media_type="application/json")

    async def redirect(request: Request) -> Response:
        await body_json(request)
        return Response(status_code=307, headers={"location": "/json"})

    async def gzip_body(request: Request) -> Response:
        message = await body_json(request)
        packed = gzip.compress(rpc(message["id"], result={}))
        return Response(packed, media_type="application/json", headers={"content-encoding": "gzip"})

    async def plain_text(request: Request) -> Response:
        await body_json(request)
        return Response("hello", media_type="text/plain")

    async def session(request: Request) -> Response:
        message = await body_json(request)
        seen = request.headers.get("mcp-session-id")
        return Response(
            rpc(message["id"], result={"seen": seen}),
            media_type="application/json",
            headers={"Mcp-Session-Id": "sess-1"},
        )

    async def echo(request: Request) -> Response:
        raw = await request.body()
        state.seen.append({"method": request.method, "headers": dict(request.headers), "body": raw})
        return JSONResponse({"method": request.method, "headers": dict(request.headers)})

    routes = [
        Route("/json", json_ok, methods=["POST"]),
        Route("/sse", sse_ok, methods=["POST"]),
        Route("/sse-ask", sse_ask, methods=["POST"]),
        Route("/sse-truncated", sse_truncated, methods=["POST"]),
        Route("/sse-odd", sse_odd_events, methods=["POST"]),
        Route("/sse-big", sse_forever_big, methods=["POST"]),
        Route("/sse-many", sse_many_events, methods=["POST"]),
        Route("/sse-endless", sse_endless, methods=["POST"]),
        Route("/hang", hang, methods=["POST"]),
        Route("/json-big", json_big, methods=["POST"]),
        Route("/status/{code:int}", status, methods=["POST"]),
        Route("/modern-400", modern_400, methods=["POST"]),
        Route("/wrong-id", wrong_id, methods=["POST"]),
        Route("/redirect", redirect, methods=["POST"]),
        Route("/gzip", gzip_body, methods=["POST"]),
        Route("/text", plain_text, methods=["POST"]),
        Route("/session", session, methods=["POST"]),
        Route("/echo", echo, methods=["POST", "GET", "DELETE", "OPTIONS"]),
    ]
    return Starlette(routes=routes)


@asynccontextmanager
async def serve() -> AsyncIterator[tuple[str, ServerState]]:
    """Start the app on a free localhost port; yield its base URL and recorded state."""
    state = ServerState()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(build_app(state), log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve([sock]))
    while not server.started:  # noqa: ASYNC110 - uvicorn exposes no startup event
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        server.should_exit = True
        server.force_exit = True
        await task
        sock.close()
