"""Tasks extension (`io.modelcontextprotocol/tasks`) - skeleton only.

The SDK does not implement the Tasks extension. Plan section 12.2 puts the
real implementation in the front-proxy/middleware layer: task-augmented
`tools/call` for `long_export`, `tasks/get|update|cancel`, an in-memory task
table, and durable-before-return creation. Until that lands, `long_export` is
declared (so tools/list is complete) and answers with a clear tool error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver.tools import hints

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

EXTENSION_ID = "io.modelcontextprotocol/tasks"


class TaskTable:
    """Placeholder for the in-memory task table (taskId -> status/result); no behavior yet."""


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
        """Export notes as a long-running task (Tasks extension; not implemented yet)."""
        raise ToolError(
            "long_export is not implemented yet: it needs the Tasks extension, "
            "which this build lacks"
        )
