"""Scan a real refserver (stdio) with an injected bug, the way the detection tests need it."""

import dataclasses
import hashlib
import shutil
import sqlite3
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from probe.checks.context import ScanContext
from probe.config.profile import Profile
from probe.sandbox.fixtures import FixtureSet, FixtureState
from tests.checks.protocol.harness import Scan, stdio_scan, with_listing
from tests.conftest import refserver_env

# Known-good arguments for tools whose ids a generator cannot guess.
PROFILE = Profile.model_validate(
    {
        "version": 1,
        "inputs": {
            "notes_get": [{"id": 1}],
            "notes_update": [{"id": 1, "body": "probe replay body"}],
        },
    }
)
SLOW_TOOLS = frozenset({"slow_report"})


class SqliteFixtures:
    """Stands in for the sandbox's fixtures: watches the notes table of the throwaway data copy."""

    def __init__(self, data: Path, pristine: Path) -> None:
        self.db = data / "db" / "notes.db"
        self.pristine = pristine / "db" / "notes.db"
        self.token = "test-token"

    def _digest(self) -> str:
        with sqlite3.connect(self.db) as conn:
            rows = conn.execute("SELECT * FROM notes ORDER BY id").fetchall()
        return hashlib.sha256(repr(rows).encode()).hexdigest()

    async def reset(self) -> None:
        shutil.copyfile(self.pristine, self.db)

    async def snapshot(self) -> FixtureState:
        return FixtureState(sqlite={"notes": self._digest()})

    def diff(self, a: Any, b: Any) -> Any:
        return FixtureSet.diff(a, b)


@asynccontextmanager
async def refserver_scan(
    seeded_data: Path,
    tmp_path: Path,
    bug: str = "",
    *,
    mode: str = "standard",
    keep_slow_tools: bool = False,
) -> AsyncIterator[Scan]:
    """A scan on a private copy of the data (the campaign writes), with writing tools allowed."""
    data = tmp_path / "data"
    shutil.copytree(seeded_data, data)
    argv = [sys.executable, "-m", "refserver", "stdio"]
    async with stdio_scan(argv, tmp_path / "scan", env=refserver_env(data, bug), mode=mode) as scan:
        ctx: ScanContext = scan.ctx
        ctx.config = dataclasses.replace(ctx.config, allow_side_effects=True)
        ctx.profile = PROFILE
        ctx.fixtures = SqliteFixtures(data, seeded_data)  # type: ignore[assignment]
        await with_listing(scan)
        if not keep_slow_tools:  # slow_report sleeps by design and would only slow the campaign
            ctx.tools = [t for t in ctx.tools if t.name not in SLOW_TOOLS]
        yield scan
