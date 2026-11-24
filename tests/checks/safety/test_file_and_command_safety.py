"""path_contained, no_command_injection and readonly_enforced on the real reference server.

The clean server passes all three; each injected bug fails the check built for it.
"""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.safety.injection import NoCommandInjection, ReadonlyEnforced
from probe.checks.safety.paths import PathContained
from probe.engine.outcomes import Severity, Status
from tests.checks.safety.local_fixtures import TOKEN
from tests.checks.safety.scan import safety_scan

CHECKS = [PathContained, NoCommandInjection, ReadonlyEnforced]


def summary(result: Any) -> Any:
    return (result.status, result.reason, [f.title for f in result.findings])


async def test_the_clean_server_passes_all_three(sentinel_data: Path, tmp_path: Path) -> None:
    async with safety_scan(sentinel_data, tmp_path) as scan:
        results = {c.meta.id: await scan.run(c) for c in CHECKS}
    assert all(r.status is Status.PASS for r in results.values()), {
        k: summary(r) for k, r in results.items()
    }


CASES = [
    ("b34", PathContained, "prefix"),
    ("b35", PathContained, "symlink"),
    ("b40", ReadonlyEnforced, "sql"),
    ("b42", NoCommandInjection, "option"),
]


@pytest.mark.parametrize("case", [pytest.param(c, id=f"{c[0]}-{c[1].meta.id}") for c in CASES])
async def test_each_bug_fails_its_check(
    case: tuple[str, Any, str], sentinel_data: Path, tmp_path: Path
) -> None:
    bug, check, _ = case
    async with safety_scan(sentinel_data, tmp_path, bug) as scan:
        result = await scan.run(check)
    assert result.status is Status.FAIL, summary(result)
    assert all(f.repro.steps for f in result.findings)


async def test_b34_is_caught_for_reads_and_for_writes(sentinel_data: Path, tmp_path: Path) -> None:
    async with safety_scan(sentinel_data, tmp_path, "b34") as scan:
        result = await scan.run(PathContained)
    severities = {f.tool: f.severity for f in result.findings}
    assert severities["read_file"] is Severity.HIGH
    assert severities["write_file"] is Severity.CRITICAL


async def test_a_finding_names_the_marker_it_saw(sentinel_data: Path, tmp_path: Path) -> None:
    async with safety_scan(sentinel_data, tmp_path, "b35") as scan:
        result = await scan.run(PathContained)
    assert result.findings
    markers = {f.evidence.observations["marker"] for f in result.findings}
    assert markers == {f"PROBE-SENTINEL-{TOKEN}"}
