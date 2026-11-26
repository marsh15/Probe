"""Delegated conformance: parsing the suite's output and turning it into results.

``data/stream.txt`` supplies pass, fail, and informational records in the format
used by ``images/conformance/run.sh``.
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from probe.checks.official.conformance import (
    LEGACY_VERSION,
    MODERN_VERSION,
    OfficialConformance,
    command_for,
    parse_checks,
    parse_stream,
    scenario_name,
    severity_for,
)
from probe.engine.budget import Budget
from probe.engine.outcomes import Era, Severity, Status
from probe.sandbox.conformance import ConformanceImageUnavailable

STREAM = (Path(__file__).parent / "data" / "stream.txt").read_text()


def test_scenario_names_drop_the_prefix_and_timestamp() -> None:
    assert scenario_name("server-initialize-2026-12-01T10-00-00-000Z") == "initialize"
    assert scenario_name("server-auth-metadata-2026-12-01T10-00-05-000Z") == "auth-metadata"
    assert scenario_name("server-plain") == "plain"
    assert scenario_name("something-else") == "something-else"


def test_stream_is_parsed_into_statuses_per_scenario() -> None:
    stream = parse_stream(STREAM)
    assert stream.exit_status == 1 and stream.error is None
    by_id = {c.check_id: c for c in stream.checks}
    assert (
        by_id["server-initialize"].status == "pass"
        and by_id["server-initialize"].scenario == "initialize"
    )
    assert by_id["server-protocol-version"].status == "fail"
    assert by_id["server-protocol-version"].message == "Server returned protocolVersion 1999-01-01"
    assert by_id["auth-note"].status == "other" and by_id["tools-skipped"].status == "other"
    assert by_id["server-initialize"].spec_refs == ["MCP-Lifecycle"]


def test_bad_input_is_an_error_or_empty_never_a_crash() -> None:
    assert parse_stream("").checks == []
    broken = parse_stream(
        "@@PROBE-SCENARIO@@ server-x-2026-12-01T10-00-00Z\n{not json\n@@PROBE-END@@ 0"
    )
    assert broken.error and "unreadable" in broken.error
    assert parse_checks("x", {"not": "a list"}) == [] and parse_checks("x", [1, "a"]) == []
    assert parse_stream("@@PROBE-ERROR@@ no conformance binary under /opt/c116").error


def test_command_depends_on_the_era() -> None:
    assert command_for(True, "http://target:3000/mcp") == [
        "/opt/c020a11", "http://target:3000/mcp", "--requirements", "2026-07-28",
    ]  # fmt: skip
    assert command_for(False, "http://target:3000/mcp") == [
        "/opt/c116", "http://target:3000/mcp", "--suite", "active",
    ]  # fmt: skip


def test_auth_scenarios_are_high_the_rest_medium() -> None:
    assert severity_for("auth-metadata") is Severity.HIGH
    assert severity_for("server_auth/metadata") is Severity.HIGH
    assert severity_for("author-metadata") is Severity.MEDIUM
    assert severity_for("tools-list") is Severity.MEDIUM


class FakeRunner:
    def __init__(self, output: str = STREAM, fail: bool = False) -> None:
        self.output, self.fail, self.commands = output, fail, []  # type: ignore[var-annotated]

    async def run(self, command: list[str], timeout_s: float) -> str:
        self.commands.append((command, timeout_s))
        if self.fail:
            raise RuntimeError("docker exploded with a secret path /home/x")
        return self.output


def context(
    runner: Any, *, era: Era = Era.MODERN, url: str | None = "http://127.0.0.1:3000/mcp"
) -> Any:
    target = SimpleNamespace(conformance_url=lambda: url)
    config = SimpleNamespace(target_identity={"url": "u"}, timeout_scale=1.0)
    return SimpleNamespace(
        era=era,
        conformance=runner,
        runner=target,
        config=config,
        profile=None,
        budget=Budget(10),
        liveness=AsyncMock(return_value=True),
    )


async def run(ctx: Any) -> Any:
    return await OfficialConformance().run(ctx)


async def test_failed_official_checks_become_findings_with_the_suite_version() -> None:
    runner = FakeRunner()
    outcome = await run(context(runner))
    assert outcome.status is None and len(outcome.findings) == 2  # status derives to FAIL
    by_case = {f.repro.case_id: f for f in outcome.findings}
    plain = by_case["official:initialize:server-protocol-version"]
    assert plain.severity is Severity.MEDIUM and f"v{MODERN_VERSION}" in plain.message
    auth = by_case["official:auth-metadata:auth-resource-metadata"]
    assert auth.severity is Severity.HIGH
    assert runner.commands[0][0][0] == "/opt/c020a11" and runner.commands[0][1] == 300


async def test_legacy_targets_use_the_legacy_suite_and_label() -> None:
    runner = FakeRunner()
    outcome = await run(context(runner, era=Era.LEGACY))
    assert runner.commands[0][0][0] == "/opt/c116"
    assert f"v{LEGACY_VERSION}" in outcome.findings[0].message


async def test_all_passing_is_a_pass() -> None:
    passing = STREAM.replace("FAILURE", "SUCCESS")
    outcome = await run(context(FakeRunner(passing)))
    assert outcome.findings == [] and outcome.status is None


async def test_a_harness_error_is_an_error_not_a_failure() -> None:
    stream = (
        "@@PROBE-SCENARIO@@ server-wire-2026-12-01T10-00-00Z\n"
        '[{"id": "wire-schema-harness-error", "name": "Harness", "status": "FAILURE"}]\n'
        "@@PROBE-END@@ 1\n"
    )
    outcome = await run(context(FakeRunner(stream)))
    assert outcome.findings == [] and outcome.status is Status.ERROR


async def test_not_applicable_or_error_when_the_suite_cannot_run() -> None:
    assert (await run(context(None))).status is Status.NA
    assert (await run(context(FakeRunner(), url=None))).status is Status.NA
    crashed = await run(context(FakeRunner(fail=True)))
    assert crashed.status is Status.ERROR and "/home/x" not in (crashed.reason or "")
    assert (await run(context(FakeRunner("")))).status is Status.ERROR


async def test_missing_image_is_not_applicable() -> None:
    runner = SimpleNamespace(run=AsyncMock(side_effect=ConformanceImageUnavailable))
    outcome = await run(context(runner))
    assert outcome.status is Status.NA and "image is unavailable" in outcome.reason


async def test_bearer_profile_is_na_without_passing_its_token_to_the_suite() -> None:
    runner = FakeRunner()
    ctx = context(runner)
    ctx.profile = SimpleNamespace(
        auth=SimpleNamespace(type="bearer", identities=[SimpleNamespace(token="fake-baseline")])
    )
    outcome = await run(ctx)
    assert outcome.status is Status.NA and "bearer" in outcome.reason.lower()
    assert "fake-baseline" not in outcome.reason and runner.commands == []


async def test_dead_target_does_not_run_the_suite() -> None:
    runner = FakeRunner()
    ctx = context(runner)
    ctx.liveness.return_value = False
    outcome = await run(ctx)
    assert outcome.status is Status.ERROR and "liveness" in outcome.reason
    ctx.liveness.assert_awaited_once()
    assert runner.commands == []


@pytest.mark.parametrize(("remaining", "scale", "expected"), [(30, 2, 30), (900, 0.5, 150)])
async def test_suite_timeout_uses_remaining_budget_and_timeout_scale(
    remaining: float, scale: float, expected: float
) -> None:
    runner = FakeRunner()
    ctx = context(runner)
    now = [0.0]
    ctx.budget = Budget(10, remaining + 3, clock=lambda: now[0])
    ctx.config.timeout_scale = scale

    async def liveness() -> bool:
        now[0] = 3.0
        return True

    ctx.liveness.side_effect = liveness
    await run(ctx)
    assert runner.commands[0][1] == expected


async def test_expired_budget_does_not_run_the_suite() -> None:
    runner = FakeRunner()
    ctx = context(runner)
    ctx.budget = Budget(10, 0)
    outcome = await run(ctx)
    assert outcome.status is Status.ERROR and "budget" in outcome.reason
    assert runner.commands == []


@pytest.mark.parametrize(
    "http_error",
    [
        "HTTP 421",
        "HTTP 403: Invalid Host header",
        "Expected HTTP 2xx for valid localhost Host/Origin headers, got 421",
        "Expected HTTP 2xx for valid localhost Host/Origin headers, got 403",
    ],
)
async def test_host_rejection_is_an_error(http_error: str) -> None:
    data = (
        "@@PROBE-SCENARIO@@ server-initialize\n"
        '[{"id": "initialize", "status": "FAILURE", '
        f'"errorMessage": "Error POSTing to endpoint ({http_error})"}}]\n'
        "@@PROBE-END@@ 1\n"
    )
    outcome = await run(context(FakeRunner(data)))
    assert outcome.status is Status.ERROR and "Host" in outcome.reason
    assert outcome.findings == []


async def test_a_failed_rebinding_check_that_expected_a_421_is_still_a_finding() -> None:
    data = (
        "@@PROBE-SCENARIO@@ server-dns-rebinding-protection\n"
        '[{"id": "dns-rebinding", "status": "FAILURE", '
        '"errorMessage": "Expected HTTP 421 for a hostile Host, got 200"}]\n'
        "@@PROBE-END@@ 1\n"
    )
    outcome = await run(context(FakeRunner(data)))
    assert len(outcome.findings) == 1


@pytest.mark.parametrize(
    "broken", ["@@PROBE-SCENARIO@@ server-other\n{not json\n", "@@PROBE-ERROR@@ harness broke\n"]
)
async def test_partial_suite_keeps_valid_findings(broken: str) -> None:
    outcome = await run(context(FakeRunner(broken + STREAM)))
    assert outcome.status is None and len(outcome.findings) == 2
    empty = await run(context(FakeRunner(broken)))
    assert empty.status is Status.ERROR and empty.findings == []


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_it_runs_in_standard_and_deep_only(mode: str) -> None:
    assert mode in OfficialConformance.meta.modes and "quick" not in OfficialConformance.meta.modes


@pytest.mark.parametrize(
    "broken", ["@@PROBE-SCENARIO@@ server-other\n{not json\n", "@@PROBE-ERROR@@ harness broke\n"]
)
async def test_an_incomplete_run_with_only_passes_is_an_error_not_a_pass(broken: str) -> None:
    passing = (
        "@@PROBE-SCENARIO@@ server-initialize\n"
        '[{"id": "initialize", "status": "SUCCESS"}]\n'
        "@@PROBE-END@@ 0\n"
    )
    outcome = await run(context(FakeRunner(broken + passing)))
    assert outcome.status is Status.ERROR and outcome.findings == []
