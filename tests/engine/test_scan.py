"""The engine loop with dummy checks: every status path, ordering, fixtures, crashes, liveness."""

from typing import Any

import pytest

from probe.checks import context as context_module
from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanConfig, ScanContext
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed
from probe.engine.outcomes import Severity, Status
from probe.engine.scan import run_checks
from tests.checks.helpers import evidence, make_meta, repro
from tests.engine.fakes import DyingServer, FakeFixtures, FakeRunner, make_context


def dummy(check_id: str, body: Any = None, *, applicable: Any = None, **meta: Any) -> type[Check]:
    """A check class whose run() is `body(self, ctx)` (default: a clean pass)."""

    class Dummy(Check):
        def applicable(self, ctx: ScanContext) -> Applicability:
            return applicable(ctx) if applicable else Applicability.yes()

        async def run(self, ctx: ScanContext) -> CheckOutcome:
            return await body(self, ctx) if body else CheckOutcome()

    Dummy.meta = make_meta(check_id, **meta)
    Dummy.__name__ = check_id
    return Dummy


def with_finding(severity: Severity, check_id: str | None = None) -> Any:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        finding = self.finding(
            ctx, severity=severity, title="t", message="m", evidence=evidence(), repro=repro()
        )
        if check_id is not None:
            finding = finding.model_copy(update={"check_id": check_id})
        return CheckOutcome([finding])

    return body


async def run_one(check: type[Check], **kwargs: Any) -> Any:
    ctx, _ = await make_context(**kwargs)
    [result] = await run_checks(ctx, [check])
    return result


# --- status paths ----------------------------------------------------------------------


async def test_clean_check_passes() -> None:
    result = await run_one(dummy("protocol.clean"))
    assert (result.status, result.reason, result.findings) == (Status.PASS, None, [])


@pytest.mark.parametrize(
    "severity", [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
)
async def test_finding_of_severity_low_or_more_fails(severity: Severity) -> None:
    result = await run_one(dummy("protocol.bad", with_finding(severity)))
    assert result.status is Status.FAIL
    assert result.findings[0].check_id == "protocol.bad"


async def test_info_findings_are_observations_and_never_fail() -> None:
    result = await run_one(dummy("protocol.note", with_finding(Severity.INFO)))
    assert result.status is Status.PASS
    assert len(result.findings) == 1  # kept for the report


async def test_check_specific_inapplicability_is_na() -> None:
    check = dummy("protocol.na", applicable=lambda ctx: Applicability.no("nothing to look at"))
    result = await run_one(check)
    assert (result.status, result.reason) == (Status.NA, "nothing to look at")


async def test_explicit_na_from_run_such_as_a_missing_baseline() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        return CheckOutcome.na("could not establish a successful baseline call")

    result = await run_one(dummy("behavior.needs_baseline", body))
    assert (result.status, result.reason) == (
        Status.NA,
        "could not establish a successful baseline call",
    )


async def test_na_without_a_reason_still_gets_one() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        return CheckOutcome(status=Status.NA)

    assert (await run_one(dummy("protocol.x", body))).reason == "no reason given"


async def test_mode_exclusion_is_skipped() -> None:
    check = dummy("protocol.deep_only", modes=frozenset({"deep"}))
    result = await run_one(check, config=ScanConfig(mode="quick"))
    assert (result.status, result.reason) == (Status.SKIPPED, "not part of quick mode")


async def test_an_exception_in_run_is_error_never_fail() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        raise ValueError("boom")

    result = await run_one(dummy("protocol.buggy", body))
    assert result.status is Status.ERROR
    assert result.reason == "check raised ValueError: boom"
    assert result.findings == []


async def test_error_reasons_are_sanitized_and_clipped() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        raise RuntimeError("\x1b[31mred\x1b[0m " + "x" * 1000)

    reason = (await run_one(dummy("protocol.noisy", body))).reason
    assert reason is not None
    assert "\x1b" not in reason
    assert len(reason) <= 300
    assert reason.endswith("…")


async def test_budget_exhaustion_escaping_a_check_is_error() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        await ctx.request("tools/list")
        return CheckOutcome()

    result = await run_one(dummy("protocol.greedy", body), budget_calls=1 + 0)
    assert result.status is Status.PASS  # exactly one call fits

    ctx, _ = await make_context(budget_calls=1)
    ctx.budget.take()  # nothing left

    [exhausted] = await run_checks(ctx, [dummy("protocol.greedy", body)])
    assert exhausted.status is Status.ERROR
    assert "budget exhausted" in (exhausted.reason or "")


async def test_a_check_can_catch_budget_exhaustion_and_report_what_it_saw() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        findings = []
        try:
            while True:
                await ctx.request("tools/list")
                if ctx.calls == 1:
                    findings.append(
                        self.finding(
                            ctx,
                            severity=Severity.LOW,
                            title="t",
                            message="m",
                            evidence=evidence(),
                            repro=repro(),
                        )
                    )
        except BudgetExhausted:
            return CheckOutcome(findings)

    result = await run_one(dummy("protocol.partial", body), budget_calls=3)
    assert result.status is Status.FAIL
    assert result.calls == 3


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        (CheckOutcome(status=Status.FAIL), "FAIL without a finding"),
        (CheckOutcome(status=Status.NA, reason="r", findings=[]), None),
    ],
)
async def test_fail_must_be_backed_by_a_finding(body: CheckOutcome, fragment: str | None) -> None:
    async def run(self: Check, ctx: ScanContext) -> CheckOutcome:
        return body

    result = await run_one(dummy("protocol.liar", run))
    if fragment:
        assert result.status is Status.ERROR
        assert fragment in (result.reason or "")


async def test_pass_with_failing_findings_is_inconsistent() -> None:
    inner = with_finding(Severity.HIGH)

    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        outcome = await inner(self, ctx)
        outcome.status = Status.PASS
        return outcome

    result = await run_one(dummy("protocol.liar", body))
    assert result.status is Status.ERROR
    assert "PASS" in (result.reason or "")


async def test_na_with_findings_is_inconsistent() -> None:
    inner = with_finding(Severity.HIGH)

    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        outcome = await inner(self, ctx)
        outcome.status, outcome.reason = Status.NA, "r"
        return outcome

    assert (await run_one(dummy("protocol.liar", body))).status is Status.ERROR


async def test_a_finding_for_another_check_is_error() -> None:
    result = await run_one(dummy("protocol.a", with_finding(Severity.HIGH, "protocol.other")))
    assert result.status is Status.ERROR
    assert "different check id" in (result.reason or "")


async def test_calls_and_duration_are_measured_per_check() -> None:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        await ctx.request("tools/list")
        await ctx.request("tools/list")
        return CheckOutcome()

    ctx, _ = await make_context()
    first, second = await run_checks(ctx, [dummy("protocol.a", body), dummy("protocol.b")])
    assert (first.calls, second.calls) == (2, 0)
    assert first.duration_ms >= 0


# --- order and phases ------------------------------------------------------------------


async def test_checks_run_in_phase_then_id_order() -> None:
    order: list[str] = []

    def recording(check_id: str, phase: str) -> type[Check]:
        async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
            order.append(check_id)
            return CheckOutcome()

        return dummy(check_id, body, phase=phase)

    ctx, _ = await make_context()
    results = await run_checks(
        ctx,
        [
            recording("operability.post", "post"),
            recording("behavior.stress", "active.stress"),
            recording("protocol.b", "static"),
            recording("behavior.passive", "passive"),
            recording("protocol.a", "static"),
            recording("behavior.safe", "active.safe"),
        ],
    )
    expected = [
        "protocol.a",
        "protocol.b",
        "behavior.safe",
        "behavior.stress",
        "behavior.passive",
        "operability.post",
    ]
    assert order == expected
    assert [r.check_id for r in results] == expected


async def test_gated_checks_are_reported_in_order_too() -> None:
    ctx, _ = await make_context(config=ScanConfig(mode="quick"))
    results = await run_checks(
        ctx,
        [dummy("protocol.a"), dummy("protocol.b", modes=frozenset({"deep"})), dummy("protocol.c")],
    )
    assert [(r.check_id, r.status) for r in results] == [
        ("protocol.a", Status.PASS),
        ("protocol.b", Status.SKIPPED),
        ("protocol.c", Status.PASS),
    ]


async def test_fixtures_are_reset_before_each_active_phase_only() -> None:
    fixtures = FakeFixtures()
    seen: list[tuple[str, int]] = []

    def recording(check_id: str, phase: str) -> type[Check]:
        async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
            seen.append((check_id, fixtures.resets))
            return CheckOutcome()

        return dummy(check_id, body, phase=phase)

    ctx, _ = await make_context(fixtures=fixtures)
    await run_checks(
        ctx,
        [
            recording("protocol.static", "static"),
            recording("behavior.safe1", "active.safe"),
            recording("behavior.safe2", "active.safe"),
            recording("behavior.write", "active.write"),
            recording("behavior.passive", "passive"),
        ],
    )
    assert seen == [
        ("protocol.static", 0),
        ("behavior.safe1", 1),
        ("behavior.safe2", 1),  # same phase: no second reset
        ("behavior.write", 2),
        ("behavior.passive", 2),
    ]


async def test_a_phase_whose_checks_are_all_gated_out_does_not_reset_fixtures() -> None:
    fixtures = FakeFixtures()
    ctx, _ = await make_context(fixtures=fixtures)
    await run_checks(ctx, [dummy("behavior.w", phase="active.write", requires=frozenset({"llm"}))])
    assert fixtures.resets == 0


# --- crashes ---------------------------------------------------------------------------


def crashing(check_id: str, **meta: Any) -> type[Check]:
    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        await ctx.call("boom", case_id=f"{check_id}:case")
        return CheckOutcome()

    return dummy(check_id, body, phase="active.safe", **meta)


async def test_a_crash_is_recorded_restarted_and_the_check_ends_in_error() -> None:
    runner = FakeRunner(lambda: DyingServer(boom_crashes=len(runner.transports) == 0))
    ctx, _ = await make_context(runner=runner)
    [result] = await run_checks(ctx, [crashing("behavior.survives")])
    assert result.status is Status.ERROR
    assert "crash recorded" in (result.reason or "")
    [event] = ctx.crashes.events
    assert (event.check_id, event.case_id) == ("behavior.survives", "behavior.survives:case")
    assert event.exit_code is None  # the fake runner still says running; the transport died
    assert runner.restarts == 1
    # The context now talks to the restarted server.
    assert (await ctx.call("read_it")).ok


async def test_a_check_can_attribute_a_crash_only_if_it_reproduces() -> None:
    verdicts: dict[str, bool] = {}

    async def body(self: Check, ctx: ScanContext) -> CheckOutcome:
        try:
            await ctx.call("boom")
        except TargetCrashed:
            verdicts[self.meta.id] = await ctx.reproduces_crash(
                "tools/call", {"name": "boom", "arguments": {}}
            )
        return CheckOutcome()

    # Always crashing: reproduces.
    ctx, _ = await make_context()
    await run_checks(ctx, [dummy("behavior.always", body, phase="active.safe")])
    # Crashes once, then the restarted server is fine: not reproduced.
    runner = FakeRunner(lambda: DyingServer(boom_crashes=len(runner.transports) == 0))
    ctx2, _ = await make_context(runner=runner)
    await run_checks(ctx2, [dummy("behavior.once", body, phase="active.safe")])
    assert verdicts == {"behavior.always": True, "behavior.once": False}


async def test_three_crashes_make_the_target_unstable_and_stop_active_checks() -> None:
    ran: list[str] = []

    async def passive_body(self: Check, ctx: ScanContext) -> CheckOutcome:
        ran.append(self.meta.id)
        return CheckOutcome()

    ctx, runner = await make_context()
    results = await run_checks(
        ctx,
        [
            dummy("protocol.static", passive_body),
            crashing("behavior.c1"),
            crashing("behavior.c2"),
            crashing("behavior.c3"),
            dummy("behavior.never", passive_body, phase="active.safe"),
            dummy("safety.adv", passive_body, phase="active.adversarial"),
            dummy("behavior.passive", passive_body, phase="passive"),
        ],
    )
    by_id = {r.check_id: r for r in results}
    assert runner.restarts == 3
    assert ctx.crashes.unstable
    assert [by_id[c].status for c in ("behavior.c1", "behavior.c2", "behavior.c3")] == [
        Status.ERROR
    ] * 3
    for blocked in ("behavior.never", "safety.adv"):
        assert (by_id[blocked].status, by_id[blocked].reason) == (Status.ERROR, "target_unstable")
    assert ran == ["protocol.static", "behavior.passive"]  # static and passive still run


# --- liveness --------------------------------------------------------------------------


async def test_liveness_probe_after_an_active_check_catches_a_hung_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(context_module, "LIVENESS_TIMEOUT_S", 0.2)
    runner = FakeRunner(
        lambda: DyingServer(boom_crashes=False, hang_list=len(runner.transports) == 0)
    )
    ctx, _ = await make_context(runner=runner)
    results = await run_checks(
        ctx,
        [
            dummy("behavior.a_first", phase="active.safe"),
            dummy("behavior.b_second", phase="active.safe"),
        ],
    )
    assert [r.status for r in results] == [Status.PASS, Status.PASS]
    [event] = ctx.crashes.events
    assert event.check_id == "behavior.a_first"  # the check that left the target hung
    assert runner.restarts == 1


async def test_static_checks_get_no_liveness_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = FakeRunner(lambda: DyingServer(boom_crashes=False, hang_list=True))
    ctx, _ = await make_context(runner=runner)
    await run_checks(ctx, [dummy("protocol.static")])
    assert ctx.crashes.events == []


async def test_a_dead_target_is_restarted_when_the_next_active_phase_begins() -> None:
    runner = FakeRunner()
    ctx, _ = await make_context(runner=runner)
    runner.kill(exit_code=9)
    [result] = await run_checks(ctx, [dummy("behavior.a", phase="active.safe")])
    assert result.status is Status.PASS
    [event] = ctx.crashes.events
    assert (event.check_id, event.exit_code) == ("engine", 9)
    assert runner.restarts == 1
