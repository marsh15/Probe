"""Fixtures for safety checks on a local refserver: the sandbox's layout, observed on disk.

The real FixtureSet watches /data inside Docker. This one watches a throwaway copy of the
reference server's seeded data (same layout: allowed/, allowed_evil/, secret/SENTINEL,
probe-canary/, db/), hashing every file, so the checks can be tested without Docker.
"""

import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from probe.sandbox.fixtures import FixtureSet, FixtureState
from tests.conftest import REFSERVER_SRC

TOKEN = "0123456789abcdef"


def seed_with_sentinel(directory: Path) -> Path:
    """A seeded data root whose secret file carries TOKEN."""
    data = directory / "data"
    subprocess.run(  # noqa: S603 - fixed argv, test interpreter
        [sys.executable, "-m", "refserver", "seed", "--out", str(data), "--token", TOKEN],
        check=True,
        env={**os.environ, "PYTHONPATH": str(REFSERVER_SRC)},
        timeout=120,
    )
    return data


class LocalFixtures:
    def __init__(self, data: Path, pristine: Path) -> None:
        self.data, self.pristine = data, pristine
        self.data_root = str(data)  # the sandbox's is /data; this copy lives in a temp directory
        self.token = TOKEN
        self.canary_ip = "127.0.0.1"

    def _hashes(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for path in sorted(self.data.rglob("*")):
            if ".git" in path.relative_to(self.data).parts or path.is_dir():
                continue
            if path.is_symlink():
                found[str(path)] = "link:" + os.readlink(path)
            else:
                found[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        return found

    def _notes(self) -> str:
        with sqlite3.connect(self.data / "db" / "notes.db") as conn:
            return hashlib.sha256(repr(conn.execute("SELECT * FROM notes").fetchall()).encode())\
                .hexdigest()  # fmt: skip

    async def reset(self) -> None:
        shutil.rmtree(self.data)
        shutil.copytree(self.pristine, self.data, symlinks=True)

    async def snapshot(self) -> FixtureState:
        return FixtureState(fs=self._hashes(), sqlite={"notes": self._notes()})

    def diff(self, a: Any, b: Any) -> Any:
        return FixtureSet.diff(a, b)

    async def canary_hits(self, since: int = 0) -> list[dict[str, Any]]:
        return []

    async def backend_log(self, since: int = 0) -> list[dict[str, Any]]:
        return []

    async def backend_fault(self, route: str | None, *, count: int = 1) -> bool:
        return False
