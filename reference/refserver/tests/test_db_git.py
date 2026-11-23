from __future__ import annotations

import hashlib

import anyio
import pytest
from mcp import Client
from refserver.config import Config
from refserver.tools.db import MAX_ROWS

from tests.helpers import call, call_json

pytestmark = pytest.mark.anyio


def db_hash(cfg: Config) -> str:
    return hashlib.sha256(cfg.db_path.read_bytes()).hexdigest()


async def test_select_works(client: Client) -> None:
    out = await call_json(
        client, "query_db", {"sql": "SELECT id, title FROM notes WHERE id <= 3 ORDER BY id"}
    )
    assert out["columns"] == ["id", "title"]
    assert [r[0] for r in out["rows"]] == [1, 2, 3]


async def test_semicolon_inside_literal_and_trailing_semicolon(client: Client) -> None:
    out = await call_json(client, "query_db", {"sql": "SELECT 'a;b' AS v;"})
    assert out["rows"] == [["a;b"]]


async def test_row_cap(client: Client) -> None:
    out = await call_json(client, "query_db", {"sql": "SELECT id FROM notes"})
    assert len(out["rows"]) == MAX_ROWS
    assert out["truncated"] is True


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM notes",
        "UPDATE notes SET title = 'x'",
        "INSERT INTO notes (title, body, created_at, updated_at) VALUES ('a', 'b', 'c', 'd')",
        "DROP TABLE notes",
        "CREATE TABLE t (x)",
        "SELECT 1; DELETE FROM notes",
        "SELECT 1; DROP TABLE notes;",
        "ATTACH DATABASE '/tmp/x.db' AS x",
        "PRAGMA journal_mode = WAL",
        "PRAGMA writable_schema = 1",
        "VACUUM",
        "REPLACE INTO notes (id, title, body, created_at, updated_at) "
        "VALUES (1, 'a', 'b', 'c', 'd')",
    ],
)
async def test_writes_rejected(client: Client, cfg: Config, sql: str) -> None:
    before = db_hash(cfg)
    is_error, text = await call(client, "query_db", {"sql": sql})
    assert is_error, sql
    assert "rejected" in text or "SQL error" in text
    assert db_hash(cfg) == before


async def test_git_log_main(client: Client) -> None:
    entries = await call_json(client, "git_log", {"ref": "main", "max_count": 2})
    assert [e["subject"] for e in entries] == ["Document usage", "Release 1.0"]


async def test_git_log_tag_and_branch(client: Client) -> None:
    assert (await call_json(client, "git_log", {"ref": "v1.0", "max_count": 1}))[0][
        "subject"
    ] == "Release 1.0"
    assert len(await call_json(client, "git_log", {"ref": "feature/notes"})) == 4


@pytest.mark.parametrize(
    "ref",
    [
        "--output=/tmp/refserver-pwn",
        "-p",
        "--all",
        "main;id",
        "$(id)",
        "main id",
        "`id`",
        "main\nid",
        "a|b",
    ],
)
async def test_git_ref_injection_rejected(client: Client, ref: str) -> None:
    is_error, text = await call(client, "git_log", {"ref": ref})
    assert is_error
    assert "invalid ref" in text
    assert not await anyio.Path("/tmp/refserver-pwn").exists()


async def test_git_unknown_ref_is_actionable(client: Client) -> None:
    is_error, text = await call(client, "git_log", {"ref": "no-such-branch"})
    assert is_error and "unknown ref" in text


async def test_git_max_count_bounds(client: Client) -> None:
    for bad in (0, 51):
        try:
            is_error, _ = await call(client, "git_log", {"ref": "main", "max_count": bad})
        except Exception:
            is_error = True
        assert is_error
