"""Scan a real refserver (stdio) with an injected bug, using the sandbox layout on local disk."""

import dataclasses
import shutil
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from probe.config.profile import Profile
from tests.checks.protocol.harness import Scan, stdio_scan, with_listing
from tests.checks.safety.local_fixtures import LocalFixtures
from tests.conftest import refserver_env

SLOW_TOOLS = frozenset({"slow_report"})


@asynccontextmanager
async def safety_scan(
    sentinel_data: Path,
    tmp_path: Path,
    bug: str = "",
    *,
    mode: str = "standard",
    extra_inputs: dict[str, Any] | None = None,
) -> AsyncIterator[Scan]:
    data = tmp_path / "data"
    shutil.copytree(sentinel_data, data, symlinks=True)
    profile = Profile.model_validate(
        {
            "version": 1,
            "fixtures": {"fs": {"seed_dir": str(data), "allowed_roots": [str(data / "allowed")]}},
            "inputs": {
                "read_file": [{"path": str(data / "allowed" / "readme.md")}],
                "write_file": [{"path": str(data / "allowed" / "probe-ok.txt"), "content": "ok"}],
                "notes_get": [{"id": 1}],
                "notes_delete": [{"id": 5}],
                **(extra_inputs or {}),
            },
        }
    )
    argv = [sys.executable, "-m", "refserver", "stdio"]
    env = refserver_env(data, bug)
    async with stdio_scan(argv, tmp_path / "scan", env=env, mode=mode) as scan:
        ctx = scan.ctx
        ctx.config = dataclasses.replace(ctx.config, allow_side_effects=True)
        ctx.profile = profile
        ctx.fixtures = LocalFixtures(data, sentinel_data)  # type: ignore[assignment]
        await with_listing(scan)
        ctx.tools = [t for t in ctx.tools if t.name not in SLOW_TOOLS]
        yield scan
