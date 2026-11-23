"""Notes CRUD, paginated listing and search over the seeded sqlite DB."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

from refserver.tools import READ, hints

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

SEARCH_MAX_ITEMS = 100
SEARCH_MAX_BYTES = 256 * 1024
_SNIPPET = 160

NoteId = Annotated[
    int, Field(ge=1, le=2**31 - 1, description="Numeric note id, e.g. from notes_list.")
]
Title = Annotated[
    str, Field(min_length=1, max_length=200, description="Note title (1-200 characters).")
]
Body = Annotated[
    str, Field(max_length=10_000, description="Note body text (up to 10,000 characters).")
]


class Note(BaseModel):
    id: int
    title: str
    body: str
    tags: list[str]
    created_at: str
    updated_at: str


class NoteSummary(BaseModel):
    id: int
    title: str
    tags: list[str]
    created_at: str


class NotesPage(BaseModel):
    items: list[NoteSummary]
    next_cursor: str | None = Field(
        default=None, description="Pass back as `cursor` for the next page; null at the end."
    )


@contextmanager
def connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """One short-lived connection per call (sync tools run on threads); commits on success."""
    conn = sqlite3.connect(db_path, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def now_iso() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _note(row: sqlite3.Row) -> Note:
    return Note(
        id=row["id"],
        title=row["title"],
        body=row["body"],
        tags=json.loads(row["tags"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class CursorCodec:
    """Opaque keyset cursors: base64(json) + truncated HMAC, so clients cannot forge positions."""

    def __init__(self, secret: bytes) -> None:
        self._key = hmac.new(secret, b"refserver/cursor/v1", hashlib.sha256).digest()

    def _tag(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()[:16]

    def encode(self, after_id: int) -> str:
        payload = json.dumps({"after": after_id}, separators=(",", ":")).encode()
        return f"{_b64(payload)}.{_b64(self._tag(payload))}"

    def decode(self, cursor: str) -> int:
        try:
            payload_part, tag_part = cursor.split(".")
            payload, tag = _unb64(payload_part), _unb64(tag_part)
        except (ValueError, binascii.Error):
            raise ToolError("invalid cursor; call notes_list without a cursor to restart") from None
        if not hmac.compare_digest(tag, self._tag(payload)):
            raise ToolError("invalid cursor; call notes_list without a cursor to restart")
        after = json.loads(payload)["after"]
        if not isinstance(after, int):
            raise ToolError("invalid cursor; call notes_list without a cursor to restart")
        return after


def register(mcp: MCPServer, cfg: Config) -> None:
    db = cfg.db_path
    cursors = CursorCodec(cfg.secret)

    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=False, destructive=False, idempotent=False),
    )
    def notes_create(
        title: Title,
        body: Body,
        tags: Annotated[
            list[Annotated[str, Field(min_length=1, max_length=50)]],
            Field(
                default_factory=list,
                max_length=20,
                description="Up to 20 tags, 1-50 characters each.",
            ),
        ],
    ) -> str:
        """Create a new note. Every call creates a new row and returns its id."""
        if not title.strip():
            raise ToolError("title must contain non-whitespace characters")
        stamp = now_iso()
        with connect(db) as conn:
            cur = conn.execute(
                "INSERT INTO notes (title, body, tags, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (title, body, json.dumps(sorted(set(tags))), stamp, stamp),
            )
        return json.dumps({"id": cur.lastrowid})

    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=False, destructive=False, idempotent=True),
    )
    def notes_update(id: NoteId, title: Title | None = None, body: Body | None = None) -> str:
        """Set the title and/or body of a note. Replaying the same update changes nothing."""
        if title is None and body is None:
            raise ToolError("nothing to update; pass title and/or body")
        with connect(db) as conn:
            row = conn.execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
            if row is None:
                raise ToolError(f"note {id} not found; use notes_list or search_notes to find ids")
            new_title = row["title"] if title is None else title
            new_body = row["body"] if body is None else body
            # Only touch updated_at on a real change, so a replay leaves the row byte-identical.
            if (new_title, new_body) != (row["title"], row["body"]):
                conn.execute(
                    "UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ?",
                    (new_title, new_body, now_iso(), id),
                )
            row = conn.execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
        return _note(row).model_dump_json()

    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=False, destructive=True, idempotent=True),
    )
    def notes_delete(id: NoteId) -> str:
        """Delete a note permanently. Deleting an already-deleted note is a no-op."""
        with connect(db) as conn:
            deleted = conn.execute("DELETE FROM notes WHERE id = ?", (id,)).rowcount
        return json.dumps({"id": id, "deleted": bool(deleted)})

    @mcp.tool(annotations=READ)
    def notes_get(id: NoteId) -> Note:
        """Fetch one note by id."""
        with connect(db) as conn:
            row = conn.execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
        if row is None:
            raise ToolError(f"note {id} not found; use notes_list or search_notes to find ids")
        return _note(row)

    @mcp.tool(annotations=READ)
    def notes_list(
        cursor: Annotated[
            str | None, Field(description="Opaque cursor from a previous page.")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=50, description="Page size (1-50).")] = 20,
    ) -> NotesPage:
        """List notes in id order, one page at a time."""
        after = cursors.decode(cursor) if cursor else 0
        with connect(db) as conn:
            rows = conn.execute(
                "SELECT id, title, tags, created_at FROM notes WHERE id > ? ORDER BY id LIMIT ?",
                (after, limit + 1),
            ).fetchall()
        page = rows[:limit]
        items = [
            NoteSummary(
                id=r["id"], title=r["title"], tags=json.loads(r["tags"]), created_at=r["created_at"]
            )
            for r in page
        ]
        next_cursor = cursors.encode(page[-1]["id"]) if len(rows) > limit else None
        return NotesPage(items=items, next_cursor=next_cursor)

    @mcp.tool(structured_output=False, annotations=READ)
    def search_notes(
        query: Annotated[
            str, Field(min_length=1, max_length=200, description="Case-insensitive substring.")
        ],
        limit: Annotated[
            int, Field(ge=1, le=SEARCH_MAX_ITEMS, description="Maximum results (1-100).")
        ] = 20,
    ) -> str:
        """Search note titles and bodies. Output is capped at 100 items and 256 KiB."""
        with connect(db) as conn:
            rows = conn.execute(
                "SELECT id, title, body FROM notes "
                "WHERE instr(lower(title || ' ' || body), lower(?)) > 0 ORDER BY id LIMIT ?",
                (query, limit + 1),
            ).fetchall()
        items: list[dict[str, object]] = []
        size = 0
        truncated = len(rows) > limit
        for r in rows[:limit]:
            item = {"id": r["id"], "title": r["title"], "snippet": r["body"][:_SNIPPET]}
            size += len(json.dumps(item))
            if size > SEARCH_MAX_BYTES - 1024:
                truncated = True
                break
            items.append(item)
        return json.dumps({"items": items, "truncated": truncated})
