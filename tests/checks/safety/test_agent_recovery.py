"""behavior.agent_recovery on the real reference server, with the deterministic fake judge."""

from pathlib import Path

import pytest

from probe.checks.behavior._campaign import SCRATCH_KEY, Campaign, Outcome
from probe.checks.behavior.agent_recovery import STATS_KEY, AgentRecovery
from probe.engine.outcomes import Status
from probe.engine.scan import run_checks
from probe.llm import FakeJudge
from probe.schema.cases import Case
from probe.wire.jsonrpc import ErrorObject, ErrorResponse
from probe.wire.session import Exchange
from tests.checks.safety.scan import safety_scan
from tests.engine.fakes import make_context, tool


async def run(sentinel_data: Path, tmp_path: Path, bug: str, judge: FakeJudge | None) -> tuple:
    async with safety_scan(sentinel_data, tmp_path, bug) as scan:
        scan.ctx.llm = judge
        result = await scan.run(AgentRecovery)
        return result, scan.ctx.scratch.get(STATS_KEY)


async def test_clean_server_messages_help_the_agent(sentinel_data: Path, tmp_path: Path) -> None:
    judge = FakeJudge()
    result, stats = await run(sentinel_data, tmp_path, "", judge)
    assert result.status is Status.PASS
    [finding] = result.findings
    assert finding.severity.value == "info" and "lift" in finding.message
    assert stats is not None and stats["model"] == "fake-judge" and stats["cases"] > 0
    assert stats["lift"] > 0 and stats["recovery_rate"] > 0
    assert {with_error for _, with_error in judge.calls} == {True, False}  # both arms asked


async def test_useless_error_messages_have_no_lift(sentinel_data: Path, tmp_path: Path) -> None:
    clean = (await run(sentinel_data, tmp_path / "a", "", FakeJudge()))[1]
    result, bad = await run(sentinel_data, tmp_path / "b", "b21", FakeJudge())  # errors say "Error"
    assert result.status is Status.PASS and bad is not None and clean is not None
    assert bad["lift"] == 0 and bad["lift"] < clean["lift"]


async def test_reads_only_without_a_sandbox(sentinel_data: Path, tmp_path: Path) -> None:
    async with safety_scan(sentinel_data, tmp_path, "") as scan:
        scan.ctx.llm = FakeJudge()
        scan.ctx.fixtures = None
        await scan.run(AgentRecovery)
        asked = {name for name, _ in scan.ctx.llm.calls}  # type: ignore[attr-defined]
        kinds = {t.name: t.kind for t in scan.ctx.tools}
        assert asked and all(kinds[name] == "read" for name in asked)


async def test_a_judge_that_gives_up_counts_as_no_recovery(
    sentinel_data: Path, tmp_path: Path
) -> None:
    async with safety_scan(sentinel_data, tmp_path, "") as scan:
        names = {t.name for t in scan.ctx.tools}
        scan.ctx.llm = FakeJudge(fail_on=names)
        result = await scan.run(AgentRecovery)
        stats = scan.ctx.scratch[STATS_KEY]
    assert result.status is Status.PASS and stats["recovery_rate"] == 0 and stats["lift"] == 0


async def test_without_a_judge_the_check_is_skipped(sentinel_data: Path, tmp_path: Path) -> None:
    result, stats = await run(sentinel_data, tmp_path, "", None)
    assert result.status is Status.SKIPPED and stats is None
    assert "--llm" in (result.reason or "")


@pytest.mark.parametrize("interruption", ["budget", "crash"])
async def test_recovery_keeps_completed_pairs_when_a_later_attempt_is_interrupted(
    interruption: str,
) -> None:
    names = ["read_it", "boom" if interruption == "crash" else "read_more"]
    tools = [tool(name) for name in names]
    for read in tools:
        read.input_schema = {"type": "object", "required": ["name"]}
    ctx, _ = await make_context(
        tools=tools, budget_calls=1 if interruption == "budget" else 4, llm=FakeJudge()
    )
    ctx.scratch[SCRATCH_KEY] = Campaign(
        outcomes={
            "malformed": [
                Outcome(
                    Case(name, "malformed", "missing-name", 0, {}),
                    exchange=Exchange(ErrorResponse(1, ErrorObject(-32602, "name is required"))),
                )
                for name in names
            ]
        }
    )

    [result] = await run_checks(ctx, [AgentRecovery])
    assert result.status is Status.PASS, result.reason
    assert result.calls == ctx.budget.used == (1 if interruption == "budget" else 2)
    assert len(ctx.crashes.events) == (1 if interruption == "crash" else 0)
    assert ctx.scratch[STATS_KEY]["cases"] == 1
    assert ctx.scratch[STATS_KEY]["recovery_rate"] == 100
    assert "1 case(s) were not run" in result.findings[0].message


@pytest.mark.parametrize("quick", [True])
def test_quick_mode_leaves_it_out(quick: bool) -> None:
    assert "quick" not in AgentRecovery.meta.modes and quick
