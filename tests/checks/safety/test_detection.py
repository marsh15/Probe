"""The remaining safety checks, and the operability checks whose bugs run locally, against the
real reference server: clean passes, each injected bug fails the check built for it."""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.operability.burst import BurstResilient
from probe.checks.operability.lifecycle import CleanShutdown
from probe.checks.operability.logs import LogsNoSecrets
from probe.checks.operability.metadata import MetaTolerated
from probe.checks.safety.annotations import AnnotationsTruthful, DestructiveAnnotated
from probe.checks.safety.outputs import NoHiddenInstructions, NoStackTraces
from probe.checks.safety.state import RequestStateIntegrity
from probe.engine.outcomes import Status
from tests.checks.protocol.harness import Scan
from tests.checks.safety.scan import safety_scan


def summary(result: Any) -> Any:
    return (result.status, result.reason, [f.title for f in result.findings])


async def provoke_error(scan: Scan) -> None:
    await scan.ctx.call("notes_get", {"id": 99_999_999})  # not found: a tool error


async def search(scan: Scan) -> None:
    await scan.ctx.call("search_notes", {"query": "alpha", "limit": 3})


async def nothing(scan: Scan) -> None:
    return None


# bug, check, a call that makes the bug show (passive checks read what has happened)
CASES = [
    ("b37", NoStackTraces, provoke_error),
    ("b38", NoHiddenInstructions, search),
    ("b39", AnnotationsTruthful, nothing),
    ("b49", DestructiveAnnotated, nothing),
    ("b41", RequestStateIntegrity, nothing),
    ("b45", MetaTolerated, nothing),
    ("b46", BurstResilient, nothing),
    ("b47", LogsNoSecrets, nothing),
    ("b48", CleanShutdown, nothing),
]


@pytest.mark.parametrize("case", [pytest.param(c, id=f"{c[0]}-{c[1].meta.id}") for c in CASES])
async def test_each_bug_fails_its_check(case: Any, sentinel_data: Path, tmp_path: Path) -> None:
    bug, check, trigger = case
    async with safety_scan(sentinel_data, tmp_path, bug, mode="standard") as scan:
        await trigger(scan)
        result = await scan.run(check)
    assert result.status is Status.FAIL, summary(result)
    if check.meta.family.value == "safety":
        assert all(f.repro.steps for f in result.findings)


async def test_the_clean_server_passes_them_all(sentinel_data: Path, tmp_path: Path) -> None:
    async with safety_scan(sentinel_data, tmp_path, mode="standard") as scan:
        await provoke_error(scan)
        await search(scan)
        results = {c.meta.id: await scan.run(c) for _, c, _ in CASES}
    bad = {i: summary(r) for i, r in results.items() if r.status in (Status.FAIL, Status.ERROR)}
    assert not bad, bad
