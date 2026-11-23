"""Tool modules. Each exposes `register(mcp, cfg)`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config


def hints(
    *, read_only: bool, destructive: bool, idempotent: bool, open_world: bool = False
) -> ToolAnnotations:
    """Annotations with every hint explicit, so no client falls back to a spec default."""
    return ToolAnnotations(
        read_only_hint=read_only,
        destructive_hint=destructive,
        idempotent_hint=idempotent,
        open_world_hint=open_world,
    )


READ = hints(read_only=True, destructive=False, idempotent=True)


def register_all(mcp: MCPServer, cfg: Config) -> None:
    from refserver.tools import backend, db, fetch, files, git, notes, purge, slow, tasks_ext

    # Registration order is the tools/list order, which must stay deterministic.
    for module in (notes, fetch, files, db, git, slow, purge, backend, tasks_ext):
        module.register(mcp, cfg)
