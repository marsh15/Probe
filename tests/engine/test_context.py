"""The scan context: budgeted calls, baselines, crash bookkeeping, and finding ids."""

import pytest

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanConfig, ScanContext
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
from probe.engine.outcomes import Era, Severity
from tests.checks.helpers import evidence, make_meta, repro
from tests.engine.fakes import FakeRunner, make_context, tool


async def test_negotiated_facts_are_exposed() -> None:
    ctx, _ = await make_context()
    assert ctx.era is Era.MODERN
    assert ctx.negotiated_version == "2026-07-28"
    assert ctx.discover is not None
    assert ctx.discover["supportedVersions"] == ["2026-07-28"]
    assert ctx.server_extensions == frozenset()
    legacy, _ = await make_context(era="legacy")
    assert legacy.era is Era.LEGACY
    assert legacy.discover is not None
    assert legacy.discover["protocolVersion"] == "2025-11-25"


async def test_tool_lookup() -> None:
    ctx, _ = await make_context(tools=[tool("a"), tool("b")])
    assert ctx.tool("b") is not None
    assert ctx.tool("zzz") is None


async def test_every_request_is_counted_and_budgeted() -> None:
    ctx, _ = await make_context(budget_calls=2)
    ctx.begin_check("protocol.x")
    await ctx.request("tools/list")
    await ctx.call("read_it")
    assert (ctx.calls, ctx.budget.used) == (2, 2)
    with pytest.raises(BudgetExhausted):
        await ctx.request("tools/list")
    assert ctx.calls == 2  # the refused call was neither sent nor counted


async def test_begin_check_resets_the_per_check_call_count() -> None:
    ctx, _ = await make_context()
    ctx.begin_check("protocol.a")
    await ctx.request("tools/list")
    ctx.begin_check("protocol.b")
    assert ctx.calls == 0


async def test_call_returns_a_classified_result() -> None:
    ctx, _ = await make_context()
    ok = await ctx.call("read_it", {"x": 1})
    assert ok.ok and not ok.is_error
    assert ok.result is not None
    failed = await ctx.call("fails")
    assert failed.is_error and not failed.ok
    assert ok.elapsed_ms >= 0


async def test_baseline_is_cached_after_the_first_success() -> None:
    ctx, _ = await make_context()
    read = tool("read_it")
    assert ctx.baseline("read_it") is None
    first = await ctx.establish_baseline(read, {"x": 1})
    used = ctx.budget.used
    again = await ctx.establish_baseline(read, {"x": 2})
    assert first is again
    assert ctx.baseline("read_it") is first
    assert ctx.budget.used == used  # no second call


async def test_a_failed_baseline_is_remembered_and_not_retried() -> None:
    ctx, _ = await make_context(tools=[tool("fails")])
    assert await ctx.establish_baseline(tool("fails"), {}) is None
    used = ctx.budget.used
    assert await ctx.establish_baseline(tool("fails"), {}) is None
    assert ctx.baseline("fails") is None
    assert ctx.budget.used == used


async def test_rng_is_seeded_from_the_config() -> None:
    a, _ = await make_context(config=ScanConfig(seed=7))
    b, _ = await make_context(config=ScanConfig(seed=7))
    c, _ = await make_context(config=ScanConfig(seed=8))
    draws = [[ctx.rng.random() for _ in range(3)] for ctx in (a, b, c)]
    assert draws[0] == draws[1] != draws[2]


async def test_a_fourth_crash_cannot_be_restarted_and_ends_all_calls() -> None:
    runner = FakeRunner()
    ctx, _ = await make_context(runner=runner)
    for _ in range(3):
        with pytest.raises(TargetCrashed):
            await ctx.call("boom")
    assert ctx.crashes.restarts == 3
    with pytest.raises(TargetCrashed):  # the fourth death: recorded, no restart left
        await ctx.call("boom")
    assert runner.restarts == 3
    with pytest.raises(TargetUnstable):
        await ctx.call("read_it")
    assert await ctx.liveness() is False


async def test_crash_event_carries_the_runner_exit_code_and_stderr() -> None:
    runner = FakeRunner()
    ctx, _ = await make_context(runner=runner)
    runner.kill(exit_code=139)
    ctx.begin_check("behavior.survives_campaign")
    with pytest.raises(TargetCrashed) as info:
        await ctx.call("boom", case_id="boom:1")
    event = info.value.event
    assert (event.check_id, event.case_id, event.exit_code) == (
        "behavior.survives_campaign",
        "boom:1",
        139,
    )
    assert event.stderr_tail  # at least the reason the transport closed


async def test_finding_ids_are_stable_and_depend_on_the_target() -> None:
    class Probe(Check):
        meta = make_meta("safety.dummy")

        async def run(self, ctx: ScanContext) -> CheckOutcome:
            return CheckOutcome()

    def make(identity: dict[str, str], case: str = "c1", tool: str | None = "t") -> str:
        ctx_config = ScanConfig(target_identity=identity)
        ctx = type("Ctx", (), {"config": ctx_config})()
        finding = Probe().finding(
            ctx,  # type: ignore[arg-type]
            severity=Severity.HIGH,
            title="t",
            message="m",
            evidence=evidence(),
            repro=repro(case),
            tool=tool,
        )
        assert (finding.check_id, finding.family.value) == ("safety.dummy", "safety")
        return finding.finding_id

    assert make({"package": "a"}) == make({"package": "a"})
    assert len(make({"package": "a"})) == 16
    assert make({"package": "a"}) != make({"package": "b"})
    assert make({"package": "a"}) != make({"package": "a"}, case="c2")
    assert make({"package": "a"}) != make({"package": "a"}, tool=None)


async def test_read_tools_are_callable_but_writers_need_permission_or_a_sandbox() -> None:
    tools = [
        tool("r"),
        tool("w", kind="write"),
        tool("d", kind="destructive"),
        tool("e", kind="exec"),
        tool("u", kind="unknown"),
    ]
    ctx, _ = await make_context(tools=tools)
    assert [t.name for t in ctx.callable_tools()] == ["r"]
    assert ctx.side_effects_allowed is False

    allowed, _ = await make_context(tools=tools, config=ScanConfig(allow_side_effects=True))
    assert [t.name for t in allowed.callable_tools()] == ["r", "w", "d", "e", "u"]

    sandboxed = FakeRunner()
    sandboxed.sandboxed = True  # type: ignore[misc]
    boxed, _ = await make_context(tools=tools, runner=sandboxed)
    assert len(boxed.callable_tools()) == 5
