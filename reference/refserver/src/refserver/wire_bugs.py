"""Protocol-level bug injection points, outside the SDK.

(a) `WireBugMiddleware` wraps the HTTP ASGI app. Each entry of `HTTP_HOOKS`
    is an ASGI wrapper (app -> app) applied outermost-last; with no hooks the
    request reaches the SDK app untouched.
(b) `run_stdio_proxy` serves stdio through an in-process front proxy: the SDK
    server talks NDJSON over an internal pipe pair, and the proxy relays each
    line between the real stdin/stdout and those pipes, passing it through
    `STDIO_HOOKS` first. With no hooks every line is relayed byte-for-byte.

Both hook lists are empty until bugs are implemented; a bug registers its hook
here, gated on `bugs.is_on(...)`.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import IO, TYPE_CHECKING, Literal

import anyio
import anyio.to_thread
from mcp.server.stdio import stdio_server

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer
    from starlette.types import ASGIApp, Receive, Scope, Send

Direction = Literal["client_to_server", "server_to_client"]
# A stdio hook maps one NDJSON line (newline included) to zero or more lines to emit instead.
StdioHook = Callable[[Direction, bytes], list[bytes]]
HttpHook = Callable[["ASGIApp"], "ASGIApp"]


def stdio_hooks() -> list[StdioHook]:
    """Hooks for the active bugs, in application order (none implemented yet)."""
    return []


def http_hooks() -> list[HttpHook]:
    """ASGI wrappers for the active bugs, innermost first (none implemented yet)."""
    return []


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


async def _pump(
    source: IO[bytes],
    sink: IO[bytes],
    direction: Direction,
    hooks: list[StdioHook],
    close_sink: bool,
) -> None:
    """Relay lines from source to sink until EOF. Blocking reads run in a worker thread."""
    try:
        while True:
            line = await anyio.to_thread.run_sync(source.readline, abandon_on_cancel=True)
            if not line:
                return
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
        tg.start_soon(_pump, wire_in, proxy_to_server, "client_to_server", active, True)

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
