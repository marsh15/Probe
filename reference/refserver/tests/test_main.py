"""Start-up housekeeping of `refserver` itself."""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from pathlib import Path

import pytest
from refserver import __main__ as entry


def make_dir(root: Path, name: str, *, lock: bool = True) -> Path:
    path = root / name
    path.mkdir()
    (path / "payload").write_text("x" * 100)
    if lock:
        (path / entry.LOCK_NAME).touch()
    return path


def test_stale_seed_dirs_are_removed_and_live_or_foreign_ones_are_kept(
    tmp_path: Path,
) -> None:
    stale = make_dir(tmp_path, "refserver-stale")
    live = make_dir(tmp_path, "refserver-live")
    unlocked_legacy = make_dir(tmp_path, "refserver-legacy", lock=False)
    foreign = make_dir(tmp_path, "something-else")
    holder = os.open(live / entry.LOCK_NAME, os.O_RDWR)  # another running instance's lock
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        entry.clean_stale_seed_dirs(tmp_path)
    finally:
        os.close(holder)
    assert not stale.exists()
    assert live.exists() and unlocked_legacy.exists() and foreign.exists()


def test_a_dead_process_leaves_a_dir_that_the_next_start_removes(tmp_path: Path) -> None:
    code = (
        "import os, sys; from pathlib import Path; from refserver import __main__ as m;"
        "m.make_seed_dir(Path(sys.argv[1])); os._exit(0)"  # a crash: no atexit, no cleanup
    )
    subprocess.run([sys.executable, "-c", code, str(tmp_path)], check=True, timeout=30)
    leftovers = list(tmp_path.glob("refserver-*"))
    assert len(leftovers) == 1
    entry.clean_stale_seed_dirs(tmp_path)
    assert not list(tmp_path.glob("refserver-*"))


def test_prepare_data_cleans_stale_dirs_and_locks_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = make_dir(tmp_path, "refserver-crashed")
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr("tempfile.tempdir", None)
    monkeypatch.delenv("REFSERVER_DATA", raising=False)
    monkeypatch.setattr(entry, "DEFAULT_DATA", tmp_path / "no-such-data")

    def fake_seed(out: Path, seed: int = 1, token: str | None = None) -> Path:
        out.mkdir(parents=True)
        return out

    monkeypatch.setattr(entry, "make_seed", fake_seed)
    root = entry.prepare_data()
    assert not stale.exists()
    seed_dir = root.parent
    assert seed_dir.name.startswith("refserver-")
    lock = os.open(seed_dir / entry.LOCK_NAME, os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):  # held by this process, so no one else may reap it
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(lock)
