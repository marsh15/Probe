"""behavior.agent_recovery: do the server's error messages help an agent fix its call?

The experiment (``--llm``): for up to three malformed calls per tool that the server answered
with an error, ask the judge for corrected arguments twice. Arm A sees the server's error
message, arm B (the control) does not. A proposal that fits the input schema is run; the call
recovered if the server accepts it. ``lift`` is A minus B, the marginal value of the messages.
The check is informational and has no weight in the score.
"""

from dataclasses import dataclass
from typing import Any

import jsonschema

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import Outcome, campaign, outcomes
from probe.checks.context import ScanContext
from probe.checks.protocol._support import ALL_MODES
from probe.checks.registry import register
from probe.checks.support import make_finding
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Severity,
    ToolInfo,
    Transport,
)
from probe.llm.budget import LlmBudgetExhausted
from probe.llm.judge import Judge, JudgeError, JudgeResult

CASES_PER_TOOL = 3
STATS_KEY = "llm_stats"
_MODES = ALL_MODES - {"quick"}


@dataclass(slots=True)
class Tally:
    cases: int = 0
    recovered_with_error: int = 0
    recovered_without_error: int = 0
    cache_hits: int = 0
    cost_usd: float = 0.0
    skipped: int = 0

    def rate(self, count: int) -> float:
        return round(100 * count / self.cases, 1) if self.cases else 0.0


def _fits(schema: dict[str, Any], args: dict[str, Any]) -> bool:
    try:
        jsonschema.Draft202012Validator(schema).validate(args)
    except jsonschema.SchemaError:
        return True  # a broken schema cannot rule the proposal out
    except jsonschema.ValidationError:
        return False
    return True


def _may_run(ctx: ScanContext, tool: ToolInfo) -> bool:
    """Read tools always; anything that could write only where a sandbox contains it."""
    if tool.kind == "read":
        return True
    return ctx.fixtures is not None


async def _ask(
    judge: Judge, tool: ToolInfo, args: dict[str, Any], error: str | None, tally: Tally
) -> JudgeResult:
    proposal = await judge.propose_fix(tool, args, error)
    tally.cost_usd += proposal.cost_usd
    tally.cache_hits += 1 if proposal.cached else 0
    return proposal


async def _attempt(
    ctx: ScanContext, tool: ToolInfo, outcome: Outcome, proposal: JudgeResult
) -> bool:
    if proposal.args is None or not _fits(tool.input_schema, proposal.args):
        return False
    reply = await ctx.call(tool.name, proposal.args, case_id=f"recovery:{outcome.case.id}")
    return reply.ok


@register
class AgentRecovery(Check):
    meta = CheckMeta(
        id="behavior.agent_recovery",
        family=Family.BEHAVIOR,
        title="Error messages help an agent correct its call",
        severity=Severity.INFO,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools", "llm"}),
        modes=_MODES,
        phase="post",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "An agent that gets an error has only the message to go on. This measures how often "
            "a model recovers from malformed calls with the server's message and without it; "
            "the difference is what the message is worth."
        ),
        remediation=(
            "Say which parameter is wrong and what is expected, for example: "
            "'limit must be an integer between 1 and 100'."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        judge = ctx.llm
        if judge is None:  # the engine gates on this; guard anyway
            return CheckOutcome.na("requires --llm")
        await campaign(ctx)
        failed = [
            o
            for o in await outcomes(ctx, "malformed")
            if isinstance(o.case.arguments, dict)
            and (o.tool_error or o.rpc_error is not None)
            and not o.failed_hard
        ]
        tools = {t.name: t for t in ctx.tools}
        taken: dict[str, int] = {}
        tally = Tally()
        for outcome in failed:
            tool = tools.get(outcome.case.tool)
            if tool is None or taken.get(tool.name, 0) >= CASES_PER_TOOL or not _may_run(ctx, tool):
                continue
            taken[tool.name] = taken.get(tool.name, 0) + 1
            try:
                args = outcome.case.arguments
                with_error = await _ask(judge, tool, args, outcome.text(), tally)
                without = await _ask(judge, tool, args, None, tally)
                recovered_with = await _attempt(ctx, tool, outcome, with_error)
                recovered_without = await _attempt(ctx, tool, outcome, without)
            except (BudgetExhausted, LlmBudgetExhausted, TargetUnstable):
                tally.skipped += 1
                break
            except (JudgeError, TargetCrashed):
                tally.skipped += 1
                if ctx.crashes.unstable:
                    break
                continue
            tally.cases += 1
            tally.recovered_with_error += recovered_with
            tally.recovered_without_error += recovered_without
        recovery_a = tally.rate(tally.recovered_with_error)
        recovery_b = tally.rate(tally.recovered_without_error)
        if tally.cases or tally.cost_usd or tally.cache_hits:
            ctx.scratch[STATS_KEY] = {
                "model": judge.model,
                "recovery_rate": recovery_a,
                "lift": round(recovery_a - recovery_b, 1),
                "cases": tally.cases,
                "cache_hits": tally.cache_hits,
                "cost_usd": round(tally.cost_usd, 6),
            }
        if not tally.cases:
            return CheckOutcome.na(
                "no recovery case completed"
                if tally.skipped
                else "no malformed call produced an error to learn from"
            )
        summary = (
            f"An agent recovered from {tally.recovered_with_error} of {tally.cases} malformed "
            f"calls with the server's error message and {tally.recovered_without_error} without "
            f"it (lift {recovery_a - recovery_b:+.1f} points)"
            + (f"; {tally.skipped} case(s) were not run." if tally.skipped else ".")
        )
        finding = make_finding(
            self,
            ctx,
            severity=Severity.INFO,
            title="Agent recovery from malformed calls",
            message=summary,
            case_id="recovery:summary",
            steps=[],
            expect={"error_message_lift": "positive: messages help an agent fix its call"},
            observations=ctx.scratch[STATS_KEY],
        )
        return CheckOutcome([finding])
