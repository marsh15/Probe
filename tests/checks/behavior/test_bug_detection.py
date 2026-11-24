"""Each behavior bug injected into the reference server must fail the check built to find it.

(b25, b26, b28, b29 and b30 are covered in test_slow_and_tasks.py.) Every check also passes on
the clean server in test_clean_refserver.py, so a failure here separates bug from clean.
"""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.behavior.concurrency import ConcurrencyConsistent
from probe.checks.behavior.idempotency import IdempotencyDeclared, ReplayIdempotent
from probe.checks.behavior.input_handling import (
    BoundaryRobust,
    ErrorsActionable,
    InvalidInputRejected,
    ValidInputAccepted,
)
from probe.checks.behavior.pagination import PaginationSound
from probe.checks.behavior.results import EmptyResultOk, OutputBounded
from probe.checks.behavior.survival import SurvivesCampaign
from probe.checks.schema.output import OutputConforms, StructuredTextMirror
from probe.engine.outcomes import Status
from tests.checks.behavior.refserver_scan import refserver_scan

CASES = [
    ("b09", OutputConforms),
    ("b54", StructuredTextMirror),
    ("b17", ReplayIdempotent),
    ("b18", IdempotencyDeclared),
    ("b19", InvalidInputRejected),
    ("b20", BoundaryRobust),
    ("b21", ErrorsActionable),
    ("b22", OutputBounded),
    ("b23", EmptyResultOk),
    ("b24", PaginationSound),
    ("b27", ConcurrencyConsistent),
    ("b57", ValidInputAccepted),
]


@pytest.mark.parametrize("case", [pytest.param(c, id=f"{c[0]}-{c[1].meta.id}") for c in CASES])
async def test_the_injected_bug_is_detected(
    case: tuple[str, Any], seeded_data: Path, tmp_path: Path
) -> None:
    bug, check = case
    # Deep mode puts every boundary rule in play; standard samples them (see test_b20).
    mode = "deep" if bug == "b20" else "standard"
    async with refserver_scan(seeded_data, tmp_path, bug, mode=mode) as scan:
        result = await scan.run(check)
    assert result.status is Status.FAIL, (result.status, result.reason)
    assert result.findings
    assert all(f.repro.steps for f in result.findings)


async def test_b58_fails_only_survival(seeded_data: Path, tmp_path: Path) -> None:
    """The 100th call kills the server once and never again: other checks must not blame their
    own cases for it, but the scan did lose the server."""
    async with refserver_scan(seeded_data, tmp_path, "b58") as scan:
        results = {
            check.meta.id: await scan.run(check)
            for check in (
                ValidInputAccepted,
                InvalidInputRejected,
                BoundaryRobust,
                SurvivesCampaign,
            )
        }
    failed = {i for i, r in results.items() if r.status is Status.FAIL}
    assert failed == {"behavior.survives_campaign"}, {
        i: (r.status, r.reason) for i, r in results.items()
    }


async def test_the_clean_server_passes_every_one_of_these(
    seeded_data: Path, tmp_path: Path
) -> None:
    async with refserver_scan(seeded_data, tmp_path, mode="deep") as scan:
        results = {check.meta.id: await scan.run(check) for _, check in CASES}
        survives = await scan.run(SurvivesCampaign)
    bad = {i: (r.status, r.reason, [f.message for f in r.findings]) for i, r in results.items()
           if r.status in (Status.FAIL, Status.ERROR)}  # fmt: skip
    assert not bad, bad
    assert survives.status is Status.PASS, (survives.status, survives.reason)
