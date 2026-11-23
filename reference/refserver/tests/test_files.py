from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import Client
from refserver.config import Config
from refserver.tools.files import MAX_READ

from tests.helpers import call, call_json

pytestmark = pytest.mark.anyio

ESCAPES = [
    "../secret/SENTINEL",
    "notes/../../secret/SENTINEL",
    "link_out/SENTINEL",
    "link_out",
    "../allowed_evil/evil.txt",
    "/etc/passwd",
    "./../../../../etc/passwd",
    "notes/a.txt\x00.png",
]


async def test_read_inside_root(client: Client) -> None:
    out = await call_json(client, "read_file", {"path": "notes/a.txt"})
    assert out["content"] == "note a: the quick brown fox\n"
    assert out["truncated"] is False


async def test_read_absolute_path_inside_root(client: Client, cfg: Config) -> None:
    out = await call_json(client, "read_file", {"path": str(cfg.allowed_root / "readme.md")})
    assert out["path"] == "readme.md"


@pytest.mark.parametrize("path", ESCAPES)
async def test_read_escapes_rejected(client: Client, path: str) -> None:
    is_error, text = await call(client, "read_file", {"path": path})
    assert is_error
    assert "PROBE-SENTINEL" not in text and "root:" not in text


async def test_read_through_symlink_planted_in_root(
    client: Client, cfg: Config, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    os.symlink(outside, cfg.allowed_root / "planted")
    is_error, text = await call(client, "read_file", {"path": "planted"})
    assert is_error and "secret" not in text


async def test_big_file_is_truncated(client: Client) -> None:
    out = await call_json(client, "read_file", {"path": "big.log"})
    assert out["truncated"] is True
    assert len(out["content"]) == MAX_READ


async def test_missing_and_directory(client: Client) -> None:
    assert (await call(client, "read_file", {"path": "nope.txt"}))[0]
    is_error, text = await call(client, "read_file", {"path": "notes"})
    assert is_error and "directory" in text


async def test_write_then_overwrite(client: Client, cfg: Config) -> None:
    await call_json(client, "write_file", {"path": "notes/new.txt", "content": "one"})
    await call_json(client, "write_file", {"path": "notes/new.txt", "content": "two"})
    assert (cfg.allowed_root / "notes" / "new.txt").read_text() == "two"


@pytest.mark.parametrize("path", [*ESCAPES, "", "missing_dir/x.txt", "notes"])
async def test_write_escapes_rejected(client: Client, cfg: Config, path: str) -> None:
    before = (cfg.data_root / "secret" / "SENTINEL").read_bytes()
    try:
        is_error, _ = await call(client, "write_file", {"path": path, "content": "pwned"})
    except Exception:
        is_error = True
    assert is_error, path
    assert (cfg.data_root / "secret" / "SENTINEL").read_bytes() == before
    assert not (cfg.data_root / "allowed_evil" / "evil.txt").read_text().startswith("pwned")


async def test_write_through_planted_symlink_rejected(
    client: Client, cfg: Config, tmp_path: Path
) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("original")
    os.symlink(target, cfg.allowed_root / "victim")
    is_error, _ = await call(client, "write_file", {"path": "victim", "content": "pwned"})
    assert is_error
    assert target.read_text() == "original"
