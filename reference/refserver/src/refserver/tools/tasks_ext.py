"""long_export: export notes. Without the Tasks extension it simply runs and returns.

A client that declared `io.modelcontextprotocol/tasks` never reaches this function: the front
proxy (stdio) and middleware (HTTP) turn its call into a task (see `refserver.tasks_layer`).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from refserver.tools import hints

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config


def register(mcp: MCPServer, cfg: Config) -> None:
    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=False, destructive=False, idempotent=False),
    )
    def long_export(
        items: Annotated[
            list[Annotated[int, Field(ge=1)]],
            Field(min_length=1, max_length=1000, description="Note ids to export."),
        ],
    ) -> str:
        """Export notes; runs as a task when the client supports the Tasks extension."""
        return json.dumps({"exported": len(items), "items": items})
