from __future__ import annotations

import base64
import json
import sqlite3

import pytest
from mcp import Client
from refserver.config import Config
from refserver.tools.notes import SEARCH_MAX_BYTES, CursorCodec

from tests.helpers import call, call_json

pytestmark = pytest.mark.anyio


def db_rows(cfg: Config) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(cfg.db_path)
    try:
        return conn.execute("SELECT * FROM notes ORDER BY id").fetchall()
    finally:
        conn.close()


async def test_get_returns_structured_content_with_text_mirror(client: Client) -> None:
    result = await client.call_tool("notes_get", {"id": 42})
    assert not result.is_error
    assert result.structured_content["id"] == 42
    assert json.loads(result.content[0].text) == result.structured_content


async def test_get_missing_note_is_actionable_error(client: Client) -> None:
    is_error, text = await call(client, "notes_get", {"id": 999_999})
    assert is_error
    assert "not found" in text and "notes_list" in text


async def test_create_adds_a_row_per_call(client: Client, cfg: Config) -> None:
    first = await call_json(client, "notes_create", {"title": "t", "body": "b", "tags": ["x"]})
    second = await call_json(client, "notes_create", {"title": "t", "body": "b", "tags": ["x"]})
    assert second["id"] == first["id"] + 1
    note = (await client.call_tool("notes_get", {"id": first["id"]})).structured_content
    assert note["tags"] == ["x"]
    assert len(db_rows(cfg)) == 10_002


@pytest.mark.parametrize(
    "args",
    [
        {"body": "no title"},
        {"title": "", "body": "b"},
        {"title": "   ", "body": "b"},
        {"title": "x" * 201, "body": "b"},
    ],
)
async def test_create_validates_input(client: Client, cfg: Config, args: dict[str, object]) -> None:
    before = db_rows(cfg)
    try:
        is_error, _ = await call(client, "notes_create", args)
    except Exception:  # a JSON-RPC invalid-params rejection is equally acceptable
        is_error = True
    assert is_error
    assert db_rows(cfg) == before


async def test_update_replay_changes_nothing(client: Client, cfg: Config) -> None:
    await call_json(client, "notes_update", {"id": 7, "title": "renamed"})
    after_first = db_rows(cfg)
    await call_json(client, "notes_update", {"id": 7, "title": "renamed"})
    assert db_rows(cfg) == after_first
    assert after_first[6][1] == "renamed"


async def test_update_requires_a_field(client: Client) -> None:
    is_error, text = await call(client, "notes_update", {"id": 7})
    assert is_error and "nothing to update" in text


async def test_delete_is_idempotent(client: Client, cfg: Config) -> None:
    assert (await call_json(client, "notes_delete", {"id": 5}))["deleted"] is True
    after = db_rows(cfg)
    assert (await call_json(client, "notes_delete", {"id": 5}))["deleted"] is False
    assert db_rows(cfg) == after
    assert len(after) == 9_999


async def test_pagination_visits_every_note_once_and_terminates(client: Client) -> None:
    seen: list[int] = []
    cursor = None
    for _ in range(300):
        args = {"limit": 50} | ({"cursor": cursor} if cursor else {})
        page = (await client.call_tool("notes_list", args)).structured_content
        seen.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert cursor is None, "pagination did not terminate"
    assert seen == list(range(1, 10_001))


async def test_limit_bounds(client: Client) -> None:
    for bad in (0, 51, 2**53 + 1):
        try:
            is_error, _ = await call(client, "notes_list", {"limit": bad})
        except Exception:
            is_error = True
        assert is_error, bad


def _flip(text: str) -> str:
    return text[:-1] + ("A" if text[-1] != "A" else "B")


async def test_cursor_tampering_rejected(client: Client) -> None:
    page = (await client.call_tool("notes_list", {"limit": 5})).structured_content
    cursor = page["next_cursor"]
    _, tag = cursor.split(".")
    forged_payload = base64.urlsafe_b64encode(b'{"after":9000}').decode().rstrip("=")
    for bad in (_flip(cursor), f"{forged_payload}.{tag}", "garbage", "a.b.c", ""):
        args = {"cursor": bad} if bad else {"cursor": "."}
        is_error, text = await call(client, "notes_list", args)
        assert is_error, bad
        assert "invalid cursor" in text


def test_cursor_codec_roundtrip_and_key_binding() -> None:
    codec = CursorCodec(b"k1")
    assert codec.decode(codec.encode(123)) == 123
    with pytest.raises(Exception, match="invalid cursor"):
        CursorCodec(b"k2").decode(codec.encode(123))


async def test_search_respects_limit_and_caps(client: Client) -> None:
    out = await call_json(client, "search_notes", {"query": "a", "limit": 100})
    assert len(out["items"]) == 100
    assert out["truncated"] is True
    is_error, text = await call(client, "search_notes", {"query": "a", "limit": 100})
    assert len(text.encode()) <= SEARCH_MAX_BYTES
    for bad in (0, 101):
        try:
            is_error, _ = await call(client, "search_notes", {"query": "a", "limit": bad})
        except Exception:
            is_error = True
        assert is_error, bad


async def test_search_default_limit_and_empty_result(client: Client) -> None:
    assert len((await call_json(client, "search_notes", {"query": "note"}))["items"]) == 20
    empty = await call_json(client, "search_notes", {"query": "zzz-no-such-text"})
    assert empty == {"items": [], "truncated": False}


async def test_search_treats_wildcards_literally(client: Client) -> None:
    assert (await call_json(client, "search_notes", {"query": "%"}))["items"] == []
