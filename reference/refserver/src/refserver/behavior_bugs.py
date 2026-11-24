"""Bugs that live in how the server handles requests, as SDK middleware.

b26: one lock is held for the whole of every request, so a slow call holds up all others.
b28: the first tool's description carries the process id, so two instances describe themselves
     differently (a stateless server must not).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.types import ListToolsResult

from refserver import bugs

_lock: asyncio.Lock | None = None


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


async def behavior_bugs(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
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
