"""Each schema check must catch its injected refserver bug.

The bugs land in task T11. Until then the server refuses to start with them, so these are strict
xfails naming the bug; when one lands the test XPASSes and fails the run: delete its xfail mark.
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from probe.checks.base import Check
from probe.checks.schema.cache import CacheFieldsPresent, CacheTtlSane
from probe.checks.schema.definitions import (
    DescriptionsPresent,
    InputSchemaValid,
    RefsResolvable,
    ToolNamesValid,
    ToolsListValid,
    XMcpHeaderValid,
)
from probe.checks.schema.order import ToolOrderDeterministic
from probe.engine.outcomes import Status
from tests.checks.protocol.harness import stdio_scan, with_listing
from tests.conftest import refserver_env


@dataclass(frozen=True)
class Case:
    bug: str
    check: type[Check]


CASES = [
    Case("b53", ToolsListValid),
    Case("b10", InputSchemaValid),
    Case("b11", RefsResolvable),
    Case("b12", ToolOrderDeterministic),
    Case("b13", CacheFieldsPresent),
    Case("b55", CacheTtlSane),
    Case("b15", ToolNamesValid),
    Case("b16", DescriptionsPresent),
    Case("b56", XMcpHeaderValid),
]


def case_param(case: Case) -> Any:
    mark = pytest.mark.xfail(strict=True, reason=f"{case.bug} lands in T11")
    return pytest.param(case, id=f"{case.bug}-{case.check.meta.id}", marks=mark)


@pytest.mark.parametrize("case", [case_param(c) for c in CASES])
async def test_the_injected_bug_is_detected(case: Case, seeded_data: Path, tmp_path: Path) -> None:
    argv = [sys.executable, "-m", "refserver", "stdio"]
    async with stdio_scan(argv, tmp_path, env=refserver_env(seeded_data, case.bug)) as scan:
        await with_listing(scan)
        result = await scan.run(case.check)
    assert result.status is Status.FAIL, (result.status, result.reason)
    assert result.findings
