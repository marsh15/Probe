"""query_db: read-only SQL over the notes DB.

Three independent locks: the connection is opened `mode=ro`, an authorizer
allows only reads, and sqlite3's execute() runs exactly one statement.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver import bugs
from refserver.tools import READ

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

MAX_ROWS = 500
MAX_BYTES = 256 * 1024
TIME_LIMIT = 5.0
_ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}


def _authorizer(action: int, *_: object) -> int:
    return sqlite3.SQLITE_OK if action in _ALLOWED_ACTIONS else sqlite3.SQLITE_DENY


def run_unrestricted(db_path: Path, sql: str) -> dict[str, object]:
    """b40: a writable connection that runs every statement it is given."""
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        conn.executescript(sql)
        conn.commit()
    except sqlite3.DatabaseError as exc:
        raise ToolError(f"SQL error: {exc}") from None
    finally:
        conn.close()
    return {"columns": [], "rows": [], "truncated": False}


def run_readonly(db_path: Path, sql: str) -> dict[str, object]:
    if bugs.is_on("b40"):
        return run_unrestricted(db_path, sql)
    statement = sql.strip()
    conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    try:
        conn.set_authorizer(_authorizer)
        deadline = time.monotonic() + TIME_LIMIT
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
        try:
            cur = conn.execute(statement)
            rows = cur.fetchmany(MAX_ROWS + 1)
        except sqlite3.ProgrammingError as exc:
            # sqlite3 refuses to run more than one statement per execute().
            if "one statement" in str(exc):
                raise ToolError("rejected: only a single SQL statement is allowed") from None
            raise ToolError(f"SQL error: {exc}") from None
        except sqlite3.DatabaseError as exc:
            message = str(exc)
            if "not authorized" in message or "readonly" in message:
                raise ToolError(
                    "rejected: query_db is read-only; only SELECT statements are allowed"
                ) from None
            if "interrupted" in message:
                raise ToolError(f"query exceeded the {TIME_LIMIT:g}s time limit") from None
            raise ToolError(f"SQL error: {message}") from None
        columns = [d[0] for d in cur.description or ()]
    finally:
        conn.close()
    truncated = len(rows) > MAX_ROWS
    out: list[list[object]] = []
    size = 0
    for row in rows[:MAX_ROWS]:
        size += len(json.dumps(row, default=str))
        if size > MAX_BYTES:
            truncated = True
            break
        out.append(list(row))
    return {"columns": columns, "rows": out, "truncated": truncated}


def register(mcp: MCPServer, cfg: Config) -> None:
    db = cfg.db_path

    @mcp.tool(structured_output=False, annotations=READ)
    def query_db(
        sql: Annotated[
            str, Field(min_length=1, max_length=4000, description="One read-only SELECT statement.")
        ],
    ) -> str:
        """Run one read-only SQL query against the notes DB (table `notes`; max 500 rows)."""
        return json.dumps(run_readonly(db, sql), default=str)
