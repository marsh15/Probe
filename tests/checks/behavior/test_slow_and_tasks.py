"""cancellation, head-of-line blocking, statelessness, MRTR and tasks, on the real refserver.

The clean server must pass all five; each injected bug (b25, b26, b28, b29, b30) must fail the
check built to find it.
"""

import dataclasses
import shutil
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

import probe.checks.behavior  # noqa: F401 - registers the checks
from probe.checks.behavior.mrtr import MrtrWellformed
from probe.checks.behavior.slow import CancellationHonored, NoHeadOfLineBlocking
from probe.checks.behavior.stateless import StatelessConsistent
from probe.checks.behavior.tasks import TasksLifecycle
from probe.engine.outcomes import Status
from probe.wire.tasks import wait_for_terminal
from tests.checks.protocol.harness import stdio_scan, with_listing
from tests.conftest import refserver_env

CHECKS = [
    CancellationHonored,
    NoHeadOfLineBlocking,
    StatelessConsistent,
    MrtrWellformed,
    TasksLifecycle,
]
BUGS = {
    "b25": CancellationHonored,
    "b26": NoHeadOfLineBlocking,
    "b28": StatelessConsistent,
    "b29": MrtrWellformed,
    "b30": TasksLifecycle,
}


async def run_all(
    seeded_data: Path, tmp_path: Path, bug: str = "", checks: list[Any] | None = None
) -> dict[str, Any]:
    argv = [sys.executable, "-m", "refserver", "stdio"]
    data = tmp_path / "data"  # the campaign deletes notes: never touch the shared seed
    shutil.copytree(seeded_data, data)
    async with stdio_scan(
        argv, tmp_path / "scan", env=refserver_env(data, bug), mode="deep"
    ) as scan:
        # Writing tools (the export) may be called; this is a throwaway data copy.
        scan.ctx.config = dataclasses.replace(scan.ctx.config, allow_side_effects=True)
        await with_listing(scan)
        return {check.meta.id: await scan.run(check) for check in checks or CHECKS}


def describe(results: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    return [(i, r.status, r.reason or [f.message for f in r.findings]) for i, r in results.items()]


async def test_the_clean_refserver_passes_all_five(seeded_data: Path, tmp_path: Path) -> None:
    results = await run_all(seeded_data, tmp_path)
    assert all(r.status is Status.PASS for r in results.values()), describe(results)


@pytest.mark.parametrize("bug", sorted(BUGS))
async def test_each_bug_fails_its_check(bug: str, seeded_data: Path, tmp_path: Path) -> None:
    check = BUGS[bug]
    results = await run_all(seeded_data, tmp_path, bug, [check])
    result = results[check.meta.id]
    assert result.status is Status.FAIL, describe(results)
    assert result.findings[0].repro.steps, "a finding must say how to reproduce it"


async def test_task_lifecycle_scales_the_polling_cap(
    seeded_data: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait = AsyncMock(wraps=wait_for_terminal)
    monkeypatch.setattr("probe.checks.behavior.tasks.wait_for_terminal", wait)
    argv = [sys.executable, "-m", "refserver", "stdio"]
    data = tmp_path / "data"
    shutil.copytree(seeded_data, data)
    async with stdio_scan(argv, tmp_path / "scan", env=refserver_env(data), mode="deep") as scan:
        scan.ctx.config = dataclasses.replace(
            scan.ctx.config, allow_side_effects=True, timeout_scale=2
        )
        await with_listing(scan)
        result = await scan.run(TasksLifecycle)
    assert result.status is Status.PASS, describe({result.check_id: result})
    assert wait.await_args_list[0].kwargs["deadline_s"] == 60.0
    assert wait.await_args_list[1].kwargs["deadline_s"] == 10.0
