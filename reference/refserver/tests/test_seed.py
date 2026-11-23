from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest
from refserver.seed.make_seed import BIG_LOG_BYTES, NOTE_COUNT, default_token, main, make_seed


def tree_digest(root: Path) -> dict[str, str]:
    """Hash every file (symlinks by target) outside .git; git state is compared via commit ids."""
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(
            filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        ):
            path = Path(dirpath, name)
            rel = str(path.relative_to(root))
            out[rel] = (
                "link:" + os.readlink(path)
                if path.is_symlink()
                else hashlib.sha256(path.read_bytes()).hexdigest()
            )
    return out


def git_refs(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "show-ref", "--head"], check=True, capture_output=True, text=True
    ).stdout


def test_same_seed_is_byte_identical(tmp_path: Path, pristine_seed: Path) -> None:
    again = make_seed(tmp_path / "again", seed=1)
    assert tree_digest(again) == tree_digest(pristine_seed)
    assert (again / "db" / "notes.db").read_bytes() == (
        pristine_seed / "db" / "notes.db"
    ).read_bytes()
    assert git_refs(again / "repo") == git_refs(pristine_seed / "repo")


def test_different_seed_differs(tmp_path: Path, pristine_seed: Path) -> None:
    other = make_seed(tmp_path / "other", seed=2)
    assert (other / "db" / "notes.db").read_bytes() != (
        pristine_seed / "db" / "notes.db"
    ).read_bytes()


def test_sentinel_layout(pristine_seed: Path) -> None:
    allowed = pristine_seed / "allowed"
    assert (allowed / "readme.md").is_file()
    assert (allowed / "notes" / "a.txt").is_file()
    assert (allowed / "big.log").stat().st_size == BIG_LOG_BYTES
    assert os.readlink(allowed / "link_out") == "../secret"
    assert (pristine_seed / "allowed_evil" / "evil.txt").is_file()
    assert (
        pristine_seed / "secret" / "SENTINEL"
    ).read_text() == f"PROBE-SENTINEL-{default_token(1)}"
    assert (pristine_seed / "probe-canary").is_dir()
    assert not any((pristine_seed / "probe-canary").iterdir())


def test_notes_db_shape(pristine_seed: Path) -> None:
    conn = sqlite3.connect(pristine_seed / "db" / "notes.db")
    try:
        assert conn.execute("SELECT count(*) FROM notes").fetchone()[0] == NOTE_COUNT
        lo, hi = conn.execute("SELECT min(length(body)), max(length(body)) FROM notes").fetchone()
        assert 180 <= lo <= hi <= 201
    finally:
        conn.close()
    size = (pristine_seed / "db" / "notes.db").stat().st_size
    assert 1_500_000 < size < 4_000_000


def test_git_repo_has_refs(pristine_seed: Path) -> None:
    refs = git_refs(pristine_seed / "repo")
    assert "refs/heads/main" in refs
    assert "refs/heads/feature/notes" in refs
    assert "refs/tags/v1.0" in refs


def test_token_override(tmp_path: Path) -> None:
    assert main(["--seed", "1", "--out", str(tmp_path / "s"), "--token", "abc123"]) == 0
    assert (tmp_path / "s" / "secret" / "SENTINEL").read_text() == "PROBE-SENTINEL-abc123"


def test_refuses_non_empty_out(tmp_path: Path) -> None:
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "file").write_text("x")
    with pytest.raises(FileExistsError):
        make_seed(tmp_path / "busy")
    assert main(["--out", str(tmp_path / "busy")]) == 2
