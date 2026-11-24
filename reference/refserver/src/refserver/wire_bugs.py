"""Protocol-level bug injection points, outside the SDK.

(a) `WireBugMiddleware` wraps the HTTP ASGI app. Each entry of `HTTP_HOOKS`
    is an ASGI wrapper (app -> app) applied outermost-last; with no hooks the
    request reaches the SDK app untouched.
(b) `run_stdio_proxy` serves stdio through an in-process front proxy: the SDK
    server talks NDJSON over an internal pipe pair, and the proxy relays each
    line between the real stdin/stdout and those pipes, passing it through
    `STDIO_HOOKS` first. With no hooks every line is relayed byte-for-byte.

Both lists are empty on the clean server. Which bugs do what is in `mutations.py` (response
rewrites, shared by both transports) and in the hook classes below (request-side bugs, stdout
noise, crashes).
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from typing import IO, TYPE_CHECKING, Any, Literal

import anyio
import anyio.to_thread
from mcp.server.stdio import stdio_server

from refserver import bugs, mutations
from refserver.tasks_layer import TasksLayer

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer
    from starlette.types import ASGIApp, Receive, Scope, Send

Direction = Literal["client_to_server", "server_to_client"]
# A stdio hook maps one NDJSON line (newline included) to zero or more lines to emit instead.
StdioHook = Callable[[Direction, bytes], list[bytes]]
HttpHook = Callable[["ASGIApp"], "ASGIApp"]


STDOUT_NOISE = b"DEBUG: handling request\n"
CRASH_EXIT_CODE = 3


def _parse(data: bytes) -> Any:
    try:
        return json.loads(data)
    except ValueError:
        return _UNPARSEABLE


_UNPARSEABLE = object()


def is_unparseable(data: bytes) -> bool:
    return data.strip() != b"" and _parse(data) is _UNPARSEABLE


class StdioMutationHook:
    """Applies the response bugs, b07 (stdout noise) and b08 (crash on invalid JSON) to stdio."""

    def __init__(self, active: frozenset[str]) -> None:
        self.active = active
        self.state = mutations.MutationState()
        self.tasks = TasksLayer(active)

    def answer(self, line: bytes) -> bytes | None:
        """A reply to send straight to the client instead of forwarding the request, or None.

        b01: the server has no server/discover. The SDK pins a connection to the modern era the
        moment it sees one, so merely rewriting its reply would leave a client that falls back
        to the legacy handshake refused; the request must never reach it.

        Tasks extension requests are answered here too: the SDK does not know them.
        """
        message = _parse(line)
        if "b25" in self.active and _is_cancellation(message):
            return b""  # the bug: cancellation notifications are swallowed
        if (task_reply := self.tasks.answer(message)) is not None:
            return json.dumps(task_reply, separators=(",", ":")).encode() + b"\n"
        if "b01" not in self.active:
            return None
        info = mutations.request_info(message)
        if info is None or info.method != "server/discover":
            return None
        reply = {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": "Method not found"},
        }
        return json.dumps(reply, separators=(",", ":")).encode() + b"\n"

    def __call__(self, direction: Direction, line: bytes) -> list[bytes]:
        message = _parse(line)
        if direction == "client_to_server":
            if message is _UNPARSEABLE:
                if "b08" in self.active and line.strip():
                    os._exit(CRASH_EXIT_CODE)  # the bug: a parse failure takes the process down
                return [line]
            info = mutations.request_info(message)
            if info is not None:
                self.state.pending[message["id"]] = info
            return [line]
        if message is _UNPARSEABLE or not isinstance(message, dict):
            return [line]
        info = self.state.pending.pop(message.get("id"), None) if "id" in message else None
        changed = mutations.mutate_response(self.active, info, message, self.state)
        changed = self.tasks.advertise(info.method if info else None, changed)
        out = line
        if changed is not message:
            out = json.dumps(changed, separators=(",", ":")).encode() + b"\n"
        if "b07" in self.active and "id" in message:
            return [STDOUT_NOISE, out]  # a debug print on the protocol stream
        return [out]


def _is_cancellation(message: Any) -> bool:
    return isinstance(message, dict) and message.get("method") == "notifications/cancelled"


def stdio_hooks() -> list[StdioHook]:
    """Hooks for the active bugs and the Tasks extension, in application order."""
    return [StdioMutationHook(bugs.active())]


def http_hooks() -> list[HttpHook]:
    """ASGI wrappers for the active bugs, innermost first."""
    active = bugs.active()
    return [lambda app: HttpMutationMiddleware(app, active)]


def apply_stdio_hooks(direction: Direction, line: bytes, hooks: list[StdioHook]) -> list[bytes]:
    lines = [line]
    for hook in hooks:
        lines = [out for item in lines for out in hook(direction, item)]
    return lines


class WireBugMiddleware:
    """ASGI middleware applying `http_hooks()` around the SDK's Starlette app."""

    def __init__(self, app: ASGIApp, hooks: list[HttpHook] | None = None) -> None:
        self.inner = app
        wrapped = app
        for hook in http_hooks() if hooks is None else hooks:
            wrapped = hook(wrapped)
        self.app = wrapped

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)


def _set_header(headers: list[tuple[bytes, bytes]], name: bytes, value: bytes) -> None:
    headers[:] = [(k, v) for k, v in headers if k.lower() != name]
    headers.append((name, value))


def _drop_header(headers: list[tuple[bytes, bytes]], name: bytes) -> None:
    headers[:] = [(k, v) for k, v in headers if k.lower() != name]


def _has_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bool:
    return any(k.lower() == name for k, _ in headers)


class HttpMutationMiddleware:
    """Applies the HTTP request bugs (b05, b06, b08, b51) and the response bugs to POSTs."""

    def __init__(self, app: ASGIApp, active: frozenset[str]) -> None:
        self.app = app
        self.active = active
        self.state = mutations.MutationState()
        self.tasks = TasksLayer(active)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        body = b""
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            body += event.get("body", b"")
            if not event.get("more_body"):
                break
        message = _parse(body)
        if message is _UNPARSEABLE and "b08" in self.active:
            os._exit(CRASH_EXIT_CODE)
        if (task_reply := self.tasks.answer(message)) is not None:
            await self._send_json(send, task_reply)
            return
        info = mutations.request_info(message)
        headers = list(scope["headers"])
        self._rewrite_request_headers(headers, message)

        sent = False

        async def replay() -> dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # the real client's disconnect, whenever it comes

        await self.app({**scope, "headers": headers}, replay, self._mutating_send(send, info))

    @staticmethod
    async def _send_json(send: Send, reply: dict[str, Any]) -> None:
        payload = json.dumps(reply, separators=(",", ":")).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    def _rewrite_request_headers(self, headers: list[tuple[bytes, bytes]], message: Any) -> None:
        if "b06" in self.active:
            _drop_header(headers, b"origin")  # the bug: Origin is never validated
        if not isinstance(message, dict):
            return
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        version = meta.get(mutations.PROTOCOL_VERSION_META) if isinstance(meta, dict) else None
        if "b05" in self.active:
            # The bug: the server trusts the body, so headers that disagree with it are repaired
            # before validation ever sees them. (Missing headers are still missing.)
            if isinstance(message.get("method"), str) and _has_header(headers, b"mcp-method"):
                _set_header(headers, b"mcp-method", message["method"].encode())
            if isinstance(version, str) and _has_header(headers, b"mcp-protocol-version"):
                _set_header(headers, b"mcp-protocol-version", version.encode())
        no_version_header = not _has_header(headers, b"mcp-protocol-version")
        if "b51" in self.active and isinstance(version, str) and no_version_header:
            _set_header(headers, b"mcp-protocol-version", version.encode())

    def _mutating_send(self, send: Send, info: mutations.RequestInfo | None) -> Send:
        start: dict[str, Any] | None = None
        chunks: list[bytes] = []

        def content_type(message: dict[str, Any]) -> bytes:
            return next(
                (v for k, v in message.get("headers", []) if k.lower() == b"content-type"), b""
            )

        async def wrapped(event: dict[str, Any]) -> None:
            nonlocal start
            if event["type"] == "http.response.start":
                if b"application/json" in content_type(event):
                    start = event  # held back: the body length may change
                else:
                    await send(event)
                return
            if event["type"] != "http.response.body":
                await send(event)
                return
            if start is None:  # not JSON: rewrite SSE data lines, pass everything else through
                await send(self._rewrite_sse(event, info))
                return
            chunks.append(event.get("body", b""))
            if event.get("more_body"):
                return
            payload = self._rewrite_json(b"".join(chunks), info)
            headers = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
            headers.append((b"content-length", str(len(payload)).encode()))
            await send({**start, "headers": headers})
            await send({"type": "http.response.body", "body": payload})

        return wrapped

    def _rewrite_json(self, payload: bytes, info: mutations.RequestInfo | None) -> bytes:
        parsed = _parse(payload)
        if parsed is _UNPARSEABLE:
            return payload
        method = info.method if info else None

        def rewrite(message: Any) -> Any:
            changed = mutations.mutate_response(self.active, info, message, self.state)
            return self.tasks.advertise(method, changed) if isinstance(changed, dict) else changed

        mutated = [rewrite(m) for m in parsed] if isinstance(parsed, list) else rewrite(parsed)
        return json.dumps(mutated, separators=(",", ":")).encode()

    def _rewrite_sse(
        self, event: dict[str, Any], info: mutations.RequestInfo | None
    ) -> dict[str, Any]:
        body = event.get("body", b"")
        if b"data:" not in body:
            return event
        lines = []
        for line in body.split(b"\n"):
            if line.startswith(b"data:"):
                lines.append(b"data: " + self._rewrite_json(line[5:].strip(), info))
            else:
                lines.append(line)
        return {**event, "body": b"\n".join(lines)}


def invalid_message_reply(line: bytes) -> bytes | None:
    """The JSON-RPC error for a line that is not a valid message, or None if it is one.

    The SDK's stdio transport drops such lines without answering, which JSON-RPC does not allow
    (parse errors get -32700, invalid requests -32600). The clean reference server answers them
    here, in front of the SDK, so it is conformant by construction. Blank lines are ignored.
    """
    text = line.strip()
    if not text:
        return b""
    code, message, request_id = -32600, "Invalid Request", None
    try:
        value = json.loads(text)
    except ValueError:
        code, message = -32700, "Parse error"
    else:
        if isinstance(value, dict):
            if isinstance(value.get("id"), str | int) and not isinstance(value.get("id"), bool):
                request_id = value["id"]
            has_method = isinstance(value.get("method"), str)
            has_reply = "result" in value or "error" in value
            if value.get("jsonrpc") == "2.0" and (has_method or has_reply):
                return None
        # Arrays (batches are not supported) and anything else that is not a message.
    reply = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    return json.dumps(reply, separators=(",", ":")).encode() + b"\n"


async def _pump(
    source: IO[bytes],
    sink: IO[bytes],
    direction: Direction,
    hooks: list[StdioHook],
    close_sink: bool,
    reply_to: IO[bytes] | None = None,
) -> None:
    """Relay lines from source to sink until EOF. Blocking reads run in a worker thread.

    With ``reply_to`` (the client-facing stream), lines that are not valid JSON-RPC messages are
    answered there with an error and not forwarded.
    """
    try:
        while True:
            line = await anyio.to_thread.run_sync(source.readline, abandon_on_cancel=True)
            if not line:
                return
            if reply_to is not None:
                for hook in hooks:
                    answer = getattr(hook, "answer", None)
                    if answer is not None and (direct := answer(line)) is not None:
                        reply_to.write(direct)
                        reply_to.flush()
                        break
                else:
                    direct = None
                if direct is not None:
                    continue
            shim = reply_to is not None and not bugs.is_on("b08")
            if shim and (reply := invalid_message_reply(line)) is not None:
                if reply and reply_to is not None:
                    reply_to.write(reply)
                    reply_to.flush()
                continue
            for out in apply_stdio_hooks(direction, line, hooks):
                sink.write(out)
            sink.flush()
    finally:
        if close_sink:
            sink.close()


def _claim_std_streams() -> tuple[IO[bytes], IO[bytes]]:
    """Take private copies of fd 0/1 for the wire and point fd 0 at /dev/null, fd 1 at stderr.

    Mirrors what the SDK's own stdio transport does, so a stray print() in tool
    code lands on stderr instead of corrupting the protocol stream.
    """
    sys.stdout.flush()
    wire_in = os.fdopen(os.dup(0), "rb", buffering=0)
    wire_out = os.fdopen(os.dup(1), "wb", buffering=0)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    os.dup2(2, 1)
    return wire_in, wire_out


async def run_stdio_proxy(
    mcp: MCPServer,
    wire_in: IO[bytes] | None = None,
    wire_out: IO[bytes] | None = None,
    hooks: list[StdioHook] | None = None,
) -> None:
    if wire_in is None or wire_out is None:
        wire_in, wire_out = _claim_std_streams()
    active = stdio_hooks() if hooks is None else hooks
    to_server_r, to_server_w = os.pipe()
    from_server_r, from_server_w = os.pipe()
    server_in = os.fdopen(to_server_r, "r", encoding="utf-8", errors="replace")
    server_out = os.fdopen(from_server_w, "w", encoding="utf-8")
    proxy_to_server = os.fdopen(to_server_w, "wb", buffering=0)
    proxy_from_server = os.fdopen(from_server_r, "rb", buffering=0)
    lowlevel = (
        mcp._lowlevel_server
    )  # no public API serves explicit streams through the dual-era loop

    async with anyio.create_task_group() as tg:
        tg.start_soon(_pump, wire_in, proxy_to_server, "client_to_server", active, True, wire_out)

        async def serve() -> None:
            try:
                async with stdio_server(
                    stdin=anyio.wrap_file(server_in), stdout=anyio.wrap_file(server_out)
                ) as (
                    read_stream,
                    write_stream,
                ):
                    await lowlevel.run(
                        read_stream, write_stream, lowlevel.create_initialization_options()
                    )
            finally:
                server_out.close()  # EOF for the outbound pump
                server_in.close()

        tg.start_soon(serve)
        await _pump(proxy_from_server, wire_out, "server_to_client", active, False)
        # The server has finished (client closed stdin); stop the inbound pump if still blocked.
        tg.cancel_scope.cancel()
    proxy_from_server.close()
