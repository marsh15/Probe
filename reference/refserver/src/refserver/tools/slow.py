"""slow_report: a long-running read that reports progress and honors cancellation."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

import anyio
from mcp.server.mcpserver import Context
from pydantic import Field

from refserver.tools import READ

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

STEP = 0.25


def register(mcp: MCPServer, cfg: Config) -> None:
    @mcp.tool(structured_output=False, annotations=READ)
    async def slow_report(
        ctx: Context,
        seconds: Annotated[
            float, Field(ge=0, le=30, description="How long the report takes (0-30 s).")
        ] = 5,
    ) -> str:
        """Build a report slowly, sending progress notifications; cancellable at any time."""
        elapsed = 0.0
        await ctx.report_progress(0, seconds, "starting")
        # A plain await keeps cancellation working: the SDK cancels this task on
        # notifications/cancelled, and nothing here swallows the CancelledError.
        while elapsed < seconds:
            step = min(STEP, seconds - elapsed)
            await anyio.sleep(step)
            elapsed += step
            await ctx.report_progress(elapsed, seconds)
        return json.dumps({"seconds": seconds, "status": "complete"})
