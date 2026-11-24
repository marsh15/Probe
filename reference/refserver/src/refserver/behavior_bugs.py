"""Bugs that live in how the server handles requests, as SDK middleware.

b19: notes_create does not validate: a call with no title creates a note anyway.
b20: a call with an unsafe-integer limit (2**53 + 1 and anything beyond) takes the process down.
b26: one lock is held for the whole of every request, so a slow call holds up all others.
b28: the first tool's description carries the process id, so two instances describe themselves
     differently (a stateless server must not).
b45: a tools/call whose _meta has a key the server does not know is refused.
b46: the process exits when more than 16 tools/call requests are in flight at once.
b57: search_notes refuses a valid query (one with a non-ASCII character) with -32602, a rule its
     schema does not state.
b58: the process exits on exactly its 100th tools/call (a rerun after restart does not repeat it).
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING, Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, ListToolsResult, TextContent

from refserver import bugs
from refserver.tools.notes import connect, now_iso

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from refserver.config import Config

CRASH_EXIT_CODE = 3
UNSAFE = 2**53 + 1
CRASH_ON_CALL = 100
INVALID_PARAMS = -32602
MCP_PREFIX = "io.modelcontextprotocol/"

MAX_IN_FLIGHT = 16
WORK_SECONDS = 0.05
KNOWN_META = frozenset({"traceparent", "tracestate", "baggage", "progressToken"})

_lock: asyncio.Lock | None = None
_tools_calls = 0
_in_flight = 0


def _global_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def _tag_first_description(tools: list[Any]) -> list[Any]:
    suffix = f" [pid {os.getpid()}]"
    if not tools:
        return tools
    first, rest = tools[0], tools[1:]
    if isinstance(first, dict):
        return [{**first, "description": f"{first.get('description') or ''}{suffix}"}, *rest]
    return [first.model_copy(update={"description": f"{first.description or ''}{suffix}"}), *rest]


def _create_without_validation(cfg: Config, arguments: dict[str, Any]) -> CallToolResult:
    stamp = now_iso()
    with connect(cfg.db_path) as conn:
        cur = conn.execute(
            "INSERT INTO notes (title, body, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (
                str(arguments.get("title", "")),
                str(arguments.get("body", "")),
                json.dumps(arguments.get("tags") or []),
                stamp,
                stamp,
            ),
        )
    text = json.dumps({"id": cur.lastrowid})
    return CallToolResult(content=[TextContent(type="text", text=text)])


def _before_the_call(cfg: Config, ctx: ServerRequestContext[Any, Any]) -> CallToolResult | None:
    """Request-side bugs for tools/call; an answer means the SDK never sees the request."""
    global _tools_calls
    params = ctx.params or {}
    name, arguments = params.get("name"), params.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    _tools_calls += 1
    if bugs.is_on("b58") and _tools_calls == CRASH_ON_CALL:
        os._exit(CRASH_EXIT_CODE)
    limit = arguments.get("limit")
    unsafe = isinstance(limit, int | float) and not isinstance(limit, bool) and abs(limit) >= UNSAFE
    if bugs.is_on("b20") and unsafe:
        os._exit(CRASH_EXIT_CODE)
    if bugs.is_on("b19") and name == "notes_create" and "title" not in arguments:
        return _create_without_validation(cfg, arguments)
    meta = params.get("_meta")
    if bugs.is_on("b45") and isinstance(meta, dict):
        unknown = [k for k in meta if k not in KNOWN_META and not k.startswith(MCP_PREFIX)]
        if unknown:
            raise MCPError(INVALID_PARAMS, f"Invalid params: unknown _meta key {unknown[0]!r}")
    query = arguments.get("query")
    ascii_only = not isinstance(query, str) or query.isascii()
    if bugs.is_on("b57") and name == "search_notes" and not ascii_only:
        raise MCPError(INVALID_PARAMS, "Invalid params: query")
    return None


def make(cfg: Config) -> Callable[[ServerRequestContext[Any, Any], CallNext], Awaitable[Any]]:
    async def behavior_bugs(
        ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method == "tools/call":
            if (early := _before_the_call(cfg, ctx)) is not None:
                return early
            return await _counted(ctx, call_next)
        return await _serve(ctx, call_next)

    async def _counted(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        global _in_flight
        _in_flight += 1
        try:
            if bugs.is_on("b46"):
                await asyncio.sleep(WORK_SECONDS)  # work that lets requests pile up
                if _in_flight > MAX_IN_FLIGHT:
                    os._exit(CRASH_EXIT_CODE)
            return await _serve(ctx, call_next)
        finally:
            _in_flight -= 1

    async def _serve(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if bugs.is_on("b26"):
            async with _global_lock():
                result = await call_next(ctx)
        else:
            result = await call_next(ctx)
        if bugs.is_on("b28") and ctx.method == "tools/list":
            if isinstance(result, ListToolsResult):
                return result.model_copy(update={"tools": _tag_first_description(result.tools)})
            if isinstance(result, dict):
                return {**result, "tools": _tag_first_description(list(result.get("tools", [])))}
        return result

    return behavior_bugs
