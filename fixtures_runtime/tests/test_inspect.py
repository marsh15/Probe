import json
import os
import sqlite3
import subprocess

import pytest

from fixtures_runtime.inspector import Inspector, diff


def test_snapshot_file_mode_symlink_changes_and_determinism(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "z").write_bytes(b"abc")
    (root / "dir").mkdir()
    (root / "dir" / "a").write_text("hello")
    (root / "link").symlink_to("../outside")
    inspector = Inspector(root)
    first = inspector.snapshot()
    assert list(first) == ["dir", "dir/a", "link", "z"]
    assert first["link"]["target"] == "../outside"
    assert inspector.snapshot() == first
    (root / "z").chmod(0o600)
    (root / "dir" / "a").write_text("changed")
    (root / "link").unlink()
    (root / "link").symlink_to("z")
    (root / "new").write_text("added")
    second = inspector.snapshot()
    assert diff(first, second) == {
        "added": ["new"],
        "changed": ["dir/a", "link", "z"],
        "removed": [],
    }
    (root / "z").unlink()
    assert diff(second, inspector.snapshot())["removed"] == ["z"]


def test_exists_confined_and_links_not_followed(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "file").write_text("ok")
    (root / "link").symlink_to(tmp_path)
    inspector = Inspector(root)
    assert inspector.exists("file") is True
    assert inspector.exists("absent") is False
    assert inspector.exists("absent/leaf") is False
    assert inspector.exists("link") is True
    for path in ("../escape", "/etc/passwd", "link/outside", "file/../file"):
        with pytest.raises(ValueError):
            inspector.exists(path)


def test_reset_restores_seed_without_traversing_data_symlinks(tmp_path):
    root, seed, outside = [tmp_path / name for name in ("data", "seed", "outside")]
    for directory in (root, seed, outside):
        directory.mkdir()
    (outside / "keep").write_text("untouched")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (seed / "sub").mkdir()
    (seed / "sub" / "file").write_bytes(b"seed")
    (seed / "sub" / "file").chmod(0o640)
    (seed / "link").symlink_to("sub/file")
    inspector = Inspector(root)
    inspector.reset(seed)
    assert (outside / "keep").read_text() == "untouched"
    assert inspector.snapshot() == Inspector(seed).snapshot()
    assert root.is_dir()
    inspector.reset(seed)
    assert inspector.snapshot() == Inspector(seed).snapshot()


def test_reset_rejects_invalid_roots_overlap_unsafe_seeds_before_deletion(tmp_path):
    root, seed = tmp_path / "data", tmp_path / "seed"
    root.mkdir()
    seed.mkdir()
    (root / "keep").write_text("safe")
    inspector = Inspector(root)
    for invalid in (root, root / "child", tmp_path, tmp_path / "missing"):
        with pytest.raises(ValueError):
            inspector.reset(invalid)
        assert (root / "keep").read_text() == "safe"
    (seed / "escape").symlink_to("../../outside")
    with pytest.raises(ValueError):
        inspector.reset(seed)
    assert (root / "keep").read_text() == "safe"
    linked = tmp_path / "linked"
    linked.symlink_to(root)
    for invalid in (linked, "/", "/tmp", "/Users", os.path.expanduser("~")):
        with pytest.raises(ValueError):
            Inspector(invalid)


def test_root_swap_cannot_redirect_inspection_or_reset(tmp_path):
    root, seed, outside = [tmp_path / x for x in ("data", "seed", "outside")]
    for directory in (root, seed, outside):
        directory.mkdir()
    (outside / "keep").write_text("safe")
    (root / "original").write_text("held")
    inspector = Inspector(root)
    root.rename(tmp_path / "old")
    root.symlink_to(outside)
    with pytest.raises(ValueError):
        inspector.reset(seed)
    with pytest.raises(ValueError):
        inspector.snapshot()
    assert (outside / "keep").read_text() == "safe"


def test_sqlite_deterministic_blob_identifiers_without_rowid_and_readonly(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    path = root / "db.sqlite"
    with sqlite3.connect(path) as db:
        db.execute(
            'CREATE TABLE "odd""; table" ("key" TEXT PRIMARY KEY, "data" BLOB) WITHOUT ROWID'
        )
        db.executemany(
            'INSERT INTO "odd""; table" VALUES (?, ?)', [("z", b"\x00\xff"), ("a", b"abc")]
        )
        db.execute("CREATE TABLE regular (v)")
        db.executemany("INSERT INTO regular VALUES (?)", [(1,), ("1",), (None,), (1.25,)])
        db.execute("CREATE VIEW ignored AS SELECT * FROM regular")
    inspector = Inspector(root)
    before = inspector.snapshot()
    result = inspector.sqlite_checksum("db.sqlite")
    assert list(result) == ['odd"; table', "regular"]
    assert result['odd"; table']["count"] == 2
    assert result["regular"]["count"] == 4
    assert len(result["regular"]["sha256"]) == 64
    assert inspector.sqlite_checksum("db.sqlite") == result
    assert inspector.snapshot() == before
    with sqlite3.connect(path) as db:
        db.execute('DELETE FROM "odd""; table" WHERE "key" = ?', ("a",))
        db.execute('INSERT INTO "odd""; table" VALUES (?, ?)', ("a", b"abc"))
    assert inspector.sqlite_checksum("db.sqlite") == result
    with sqlite3.connect(path) as db:
        db.execute("UPDATE regular SET v = 2 WHERE v IS NULL")
    assert inspector.sqlite_checksum("db.sqlite")["regular"] != result["regular"]
    (root / "link").symlink_to(path)
    with pytest.raises(ValueError):
        inspector.sqlite_checksum("link")


def test_cli_json_contract_and_errors(tmp_path):
    root, seed = tmp_path / "data", tmp_path / "seed"
    root.mkdir()
    seed.mkdir()
    (seed / "seeded").write_text("ok")
    base = ["fixtures", "inspect", "--root", str(root)]
    result = subprocess.run([*base, "hash"], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {}
    assert json.loads(subprocess.check_output([*base, "exists", "absent"])) == {"exists": False}
    assert json.loads(subprocess.check_output([*base, "reset", "--seed", str(seed)])) == {
        "reset": True
    }
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(subprocess.check_output([*base, "hash"]).decode())
    assert json.loads(subprocess.check_output([*base, "diff", str(snapshot), str(snapshot)])) == {
        "added": [],
        "changed": [],
        "removed": [],
    }
    error = subprocess.run([*base, "exists", "../bad"], capture_output=True, text=True, check=False)
    assert error.returncode == 2 and json.loads(error.stderr)["error"]
    assert "Traceback" not in error.stderr


def test_sqlite_wal_fails_closed_and_virtual_schema_is_not_executed(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    path = root / "db.sqlite"
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE t (value TEXT)")
        db.commit()
        with pytest.raises(ValueError, match="WAL"):
            Inspector(root).sqlite_checksum("db.sqlite")
    finally:
        db.close()
    with sqlite3.connect(path) as db:
        db.execute("CREATE VIEW dangerous AS SELECT load_extension('/missing')")
        db.execute("CREATE TABLE generated (v INTEGER, computed AS (abs(v)))")
        db.execute("INSERT INTO generated(v) VALUES (-1)")
    db.close()
    result = Inspector(root).sqlite_checksum("db.sqlite")
    assert result["generated"]["count"] == 1
    assert "dangerous" not in result


def test_reset_refuses_seed_symlink_chain_escape_without_reading_outside(tmp_path):
    root, seed = tmp_path / "data", tmp_path / "seed"
    root.mkdir()
    seed.mkdir()
    (root / "keep").write_text("safe")
    (seed / "sub").mkdir()
    (seed / "sub" / "parent").symlink_to("..")
    (seed / "trap").symlink_to("sub/parent/../outside")
    with pytest.raises(ValueError):
        Inspector(root).reset(seed)
    assert (root / "keep").read_text() == "safe"


def test_system_tree_subdirectories_are_not_data_roots():
    for path in ("/usr/local", "/etc/ssh", "/System/Library"):
        with pytest.raises(ValueError, match="unsafe"):
            Inspector(path)


def test_reset_repeats_readonly_seed_directories(tmp_path, monkeypatch):
    root, seed = tmp_path / "data", tmp_path / "seed"
    root.mkdir()
    (seed / "sub").mkdir(parents=True)
    (seed / "sub" / "file").write_text("seed")
    (seed / "sub").chmod(0o555)
    inspector = Inspector(root)
    inspector.reset(seed)
    # Enforce ordinary UID directory write permissions even if tests run as root.
    original = os.unlink

    def unlink(path, *, dir_fd=None):
        if dir_fd is not None and not os.fstat(dir_fd).st_mode & 0o200:
            raise PermissionError("readonly parent")
        return original(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", unlink)
    inspector.reset(seed)
    assert inspector.snapshot() == Inspector(seed).snapshot()


def test_hostile_tree_snapshot_and_reset_are_bounded(tmp_path, monkeypatch):
    import socket
    import tempfile

    import fixtures_runtime.inspector as module

    root, seed = tmp_path / "data", tmp_path / "seed"
    root.mkdir()
    seed.mkdir()
    (seed / "good").write_text("seed")
    os.mkfifo(root / "fifo")
    with tempfile.TemporaryDirectory(dir="/tmp") as short, socket.socket(socket.AF_UNIX) as sock:
        sock.bind(short + "/sock")
        os.rename(short + "/sock", root / "sock")
        with (root / "huge").open("wb") as stream:
            stream.truncate(module.MAX_FILE + 1)
        inspector = Inspector(root)
        assert inspector.snapshot()["huge"]["size"] == module.MAX_FILE + 1
        assert "fifo" not in inspector.snapshot() and "sock" not in inspector.snapshot()
        monkeypatch.setattr(module, "MAX_ENTRIES", 8)
        for i in range(10):
            (root / str(i)).write_text("x")
        assert len(inspector.snapshot()) <= 9
        inspector.reset(seed)
        assert inspector.snapshot() == Inspector(seed).snapshot()
