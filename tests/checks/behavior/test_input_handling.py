"""Valid, boundary and malformed input checks against a stdio server that can be broken."""

import sys
from pathlib import Path
from typing import Any

import pytest

import probe.checks.behavior  # noqa: F401 - registers the checks
from probe.checks.behavior.input_handling import (
    BoundaryRobust,
    ErrorsActionable,
    InvalidInputRejected,
    ValidInputAccepted,
    actionable,
)
from probe.checks.behavior.survival import SurvivesCampaign
from probe.engine.budget import Budget
from probe.engine.outcomes import Severity, Status
from tests.checks.protocol.harness import Scan, stdio_scan, with_listing

SERVER = Path(__file__).parent / "tool_server.py"


def scan_of(behavior: str, tmp_path: Path, **env: str) -> Any:
    return stdio_scan(
        [sys.executable, str(SERVER)],
        tmp_path,
        env={"TOOL_BEHAVIOR": behavior, "PATH": "/usr/bin:/bin", **env},
        mode="standard",
    )


async def run(scan: Scan, check: Any) -> Any:
    await with_listing(scan)
    assert [t.kind for t in scan.ctx.tools] == ["read"]
    return await scan.run(check)


@pytest.mark.parametrize(
    "check",
    [ValidInputAccepted, InvalidInputRejected, BoundaryRobust, ErrorsActionable],
)
async def test_the_clean_server_passes(check: Any, tmp_path: Path) -> None:
    async with scan_of("clean", tmp_path) as scan:
        result = await run(scan, check)
    assert result.status is Status.PASS, (result.reason, [f.message for f in result.findings])


async def test_rejecting_valid_input_fails(tmp_path: Path) -> None:
    async with scan_of("reject_valid", tmp_path) as scan:
        result = await run(scan, ValidInputAccepted)
    assert result.status is Status.FAIL
    [finding] = result.findings
    assert finding.tool == "get_greeting" and "-32602" in finding.message
    assert finding.evidence.observations["count"] >= 2


async def test_accepting_invalid_input_fails(tmp_path: Path) -> None:
    async with scan_of("accept_invalid", tmp_path) as scan:
        result = await run(scan, InvalidInputRejected)
    assert result.status is Status.FAIL
    [finding] = result.findings
    assert finding.severity is Severity.HIGH and "accepted" in finding.message


async def test_invalid_input_needs_a_working_baseline(tmp_path: Path) -> None:
    async with scan_of("reject_valid", tmp_path) as scan:
        result = await run(scan, InvalidInputRejected)
    assert result.status is Status.NA and "baseline" in (result.reason or "")


async def test_a_reproducible_crash_at_a_boundary_fails(tmp_path: Path) -> None:
    async with scan_of("crash_at_max", tmp_path) as scan:
        await with_listing(scan)
        result = await scan.run(BoundaryRobust)
        survival = await scan.run(SurvivesCampaign)
    assert result.status is Status.FAIL
    assert "crash" in result.findings[0].message
    assert survival.status is Status.FAIL  # the crash is counted either way


async def test_a_crash_that_does_not_repeat_is_an_error_not_a_failure(tmp_path: Path) -> None:
    once = tmp_path / "once"
    async with scan_of("crash_once", tmp_path, TOOL_ONCE_FILE=str(once)) as scan:
        await with_listing(scan)
        result = await scan.run(BoundaryRobust)
        survival = await scan.run(SurvivesCampaign)
    assert result.status is Status.ERROR and "did not happen again" in (result.reason or "")
    assert survival.status is Status.FAIL


async def test_generic_error_messages_are_flagged(tmp_path: Path) -> None:
    async with scan_of("generic_errors", tmp_path) as scan:
        result = await run(scan, ErrorsActionable)
    assert result.status is Status.FAIL
    assert result.findings[0].severity is Severity.LOW


@pytest.mark.parametrize("check", [InvalidInputRejected, ErrorsActionable])
async def test_partial_malformed_campaign_cannot_pass(check: Any, tmp_path: Path) -> None:
    from probe.checks.behavior._campaign import campaign, outcomes

    async with scan_of("clean", tmp_path) as scan:
        await with_listing(scan)
        book = await campaign(scan.ctx)
        assert len(book.plans[0].malformed) > 3
        if check is InvalidInputRejected:
            await outcomes(scan.ctx, "valid")
        scan.ctx.budget = Budget(3)
        result = await scan.run(check)
        assert "malformed" in book.truncated
    assert result.status is Status.ERROR, result.reason
    assert not result.findings


async def test_a_server_that_never_crashes_survives(tmp_path: Path) -> None:
    async with scan_of("clean", tmp_path) as scan:
        await with_listing(scan)
        result = await scan.run(SurvivesCampaign)
    assert result.status is Status.PASS


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("", False),
        ("Error", False),
        ("internal error.", False),
        ("Failed", False),
        ("'name' is a required property", True),
        ("limit must be between 1 and 100", True),
        ("something went wrong with limit", True),
        ("Expected a string", True),
        ("it broke", False),
    ],
)
def test_what_counts_as_an_actionable_message(text: str, ok: bool) -> None:
    assert actionable(text, {"limit", "name"}) is ok


class FakeFixtures:
    """Reports that something changed (or not) around every watched call."""

    def __init__(self, changes: list[str]) -> None:
        self.changes = changes

    async def reset(self) -> None: ...

    async def snapshot(self) -> Any:
        from probe.sandbox.fixtures import FixtureState

        return FixtureState()

    def diff(self, a: Any, b: Any) -> Any:
        from probe.sandbox.fixtures import StateDiff

        return StateDiff(changed=self.changes, added=[], removed=[], backend_writes=[])


@pytest.mark.parametrize(
    ("changes", "status"), [(["/data/allowed/x"], Status.FAIL), ([], Status.PASS)]
)
async def test_a_refused_call_must_not_change_state(
    changes: list[str], status: Status, tmp_path: Path
) -> None:
    from probe.checks.context import ScanConfig

    async with scan_of("clean", tmp_path) as scan:
        await with_listing(scan)
        scan.ctx.config = ScanConfig(mode="standard", allow_side_effects=True)
        scan.ctx.tools = [t.model_copy(update={"kind": "write"}) for t in scan.ctx.tools]
        scan.ctx.fixtures = FakeFixtures(changes)
        result = await scan.run(InvalidInputRejected)
    assert result.status is status
    if changes:
        assert "changed state" in result.findings[0].message
