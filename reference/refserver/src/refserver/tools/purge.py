"""purge_notes: bulk delete guarded by an elicited confirmation.

The confirmation is a `Resolve(...)` dependency, so the SDK picks the era's
mechanism: an `InputRequiredResult` (MRTR) on 2026-07-28, a standalone
`elicitation/create` request on handshake-era sessions. The MRTR
`requestState` is sealed by the server-wide HMAC codec (see server.py).
"""

from __future__ import annotations

import datetime as dt
import json
from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver import AcceptedElicitation, Elicit, ElicitationResult, Resolve
from pydantic import BaseModel, Field

from refserver import bugs
from refserver.tools import hints
from refserver.tools.notes import connect

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

Days = Annotated[
    int, Field(ge=0, le=36_500, description="Delete notes created more than this many days ago.")
]


class PurgeConfirmation(BaseModel):
    confirm: bool = Field(description="Set to true to permanently delete the notes.")


def ask_confirmation(older_than_days: int) -> Elicit[PurgeConfirmation]:
    return Elicit(
        f"Permanently delete every note older than {older_than_days} days?", PurgeConfirmation
    )


def register(mcp: MCPServer, cfg: Config) -> None:
    db = cfg.db_path

    @mcp.tool(
        structured_output=False,
        # b49: a deleting tool that says destructiveHint is false (no annotations at all would
        # get the spec default, destructiveHint true, and clients would ask first)
        annotations=hints(read_only=False, destructive=not bugs.is_on("b49"), idempotent=True),
    )
    def purge_notes(
        older_than_days: Days,
        confirmation: Annotated[ElicitationResult[PurgeConfirmation], Resolve(ask_confirmation)],
    ) -> str:
        """Permanently delete all notes older than N days, after asking the user to confirm."""
        if not (isinstance(confirmation, AcceptedElicitation) and confirmation.data.confirm):
            return json.dumps({"purged": 0, "status": "not confirmed; no notes were deleted"})
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=older_than_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with connect(db) as conn:
            purged = conn.execute("DELETE FROM notes WHERE created_at < ?", (cutoff,)).rowcount
        return json.dumps({"purged": purged, "cutoff": cutoff, "status": "done"})
