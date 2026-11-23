"""The generated-input campaign: plan the cases once, run each kind once, share the outcomes.

Several checks judge the same calls (valid, boundary and malformed inputs per tool). Running
them once and handing the outcomes around keeps the call budget for the checks that need their
own calls, and keeps every check looking at the same evidence. Outcomes are cached on the
context; a crash during a case is recorded by the context, then the exact case is repeated on
the restarted target so a check can tell a reproducible crash from a one-off.
"""

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from probe.checks.context import CallResult, ScanContext
from probe.checks.support import request_step
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
from probe.engine.outcomes import Mode, ToolInfo
from probe.sandbox.fixtures import StateDiff
from probe.schema.cases import Case, CaseKind
from probe.schema.mutate import boundary_cases, malformed_cases
from probe.schema.valid_gen import generate_valid
from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse
from probe.wire.limits import request_timeout
from probe.wire.session import Exchange

SCRATCH_KEY = "behavior.campaign"
WRITE_KINDS = frozenset({"write", "destructive", "exec", "unknown"})
_GENERATORS_AT_ONCE = 4
_CASE_TIMEOUT_S = 10.0  # per generated case, so one slow tool cannot eat the scan
_SLOW_TOOL_S = 12.0  # total time on one tool and kind, after which its other cases are skipped
_CAMPAIGN_SHARE = 0.6  # of the calls left when the campaign is planned
# (valid, boundary, malformed, per-tool cap) from the design's section 9
_SHAPE: dict[Mode, tuple[int, int, int, int]] = {
    "quick": (4, 2, 2, 8),
    "standard": (10, 8, 6, 24),
    "deep": (25, 20, 15, 60),
}
_RISK = {"exec": 0, "destructive": 1, "write": 2, "unknown": 3, "read": 4}


@dataclass(slots=True)
class ToolPlan:
    tool: ToolInfo
    valid: list[Case] = field(default_factory=list)
    boundary: list[Case] = field(default_factory=list)
    malformed: list[Case] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def cases(self, kind: CaseKind) -> list[Case]:
        return {"valid": self.valid, "boundary": self.boundary, "malformed": self.malformed}[kind]


@dataclass(slots=True)
class Outcome:
    """What one case did to the target."""

    case: Case
    elapsed_ms: float = 0.0
    exchange: Exchange | None = None
    crashed: bool = False
    hung: bool = False
    slow: bool = False  # no answer in time, but the target is alive
    reproduced: bool = False  # the crash or hang happened again when the case was repeated
    diff: StateDiff | None = None

    @property
    def params(self) -> dict[str, Any]:
        return {"name": self.case.tool, "arguments": self.case.arguments}

    @property
    def step(self) -> dict[str, Any]:
        return request_step("tools/call", self.params)

    @property
    def response(self) -> Response | None:
        return self.exchange.response if self.exchange is not None else None

    @property
    def result(self) -> dict[str, Any] | None:
        response = self.response
        if isinstance(response, ResultResponse) and isinstance(response.result, dict):
            return response.result
        return None

    @property
    def rpc_error(self) -> ErrorResponse | None:
        response = self.response
        return response if isinstance(response, ErrorResponse) else None

    @property
    def tool_error(self) -> bool:
        result = self.result
        return result is not None and result.get("isError") is True

    @property
    def ok(self) -> bool:
        """A successful result: not an error response, not flagged ``isError``."""
        return self.result is not None and not self.tool_error

    @property
    def http_status(self) -> int | None:
        http = self.exchange.http if self.exchange is not None else None
        return http.status if http is not None else None

    @property
    def failed_hard(self) -> bool:
        """The target died or stopped answering."""
        return self.crashed or self.hung

    def text(self) -> str:
        """The error message, or the text content of the result."""
        error = self.rpc_error
        if error is not None:
            return error.error.message
        result = self.result or {}
        blocks = result.get("content")
        if not isinstance(blocks, list):
            return ""
        parts = [
            b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)
        ]
        return "\n".join(parts)


@dataclass
class Campaign:
    plans: list[ToolPlan] = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)
    outcomes: dict[CaseKind, list[Outcome]] = field(default_factory=dict)
    truncated: set[CaseKind] = field(default_factory=set)  # stopped early: budget spent
    unstable: set[CaseKind] = field(default_factory=set)  # stopped early: the target kept dying
    notes: list[str] = field(default_factory=list)

    def plan_for(self, tool: str) -> ToolPlan | None:
        return next((p for p in self.plans if p.tool.name == tool), None)


def _priority(tool: ToolInfo) -> tuple[int, int, str]:
    flagged = tool.kind == "read" and bool(tool.flags & {"url_param", "path_param"})
    return (_RISK.get(tool.kind, 3) - (1 if flagged else 0), 0, tool.name)


def _allocation(mode: Mode, tools: int, budget: int) -> tuple[int, int, int, int]:
    """(valid, boundary, malformed, tools kept): shrink the per-tool counts to fit the budget,
    keeping at least two valid and one malformed case per tool, then drop the lowest-risk tools
    if even that does not fit."""
    valid, boundary, malformed, per_tool = _SHAPE[mode]
    cap = max(int(budget * _CAMPAIGN_SHARE), 3)
    want = valid + boundary + malformed
    scale = min(1.0, per_tool / want, cap / (max(tools, 1) * want))
    v, b, m = max(2, int(valid * scale)), int(boundary * scale), max(1, int(malformed * scale))
    return v, b, m, min(tools, max(1, cap // (v + b + m)))


async def _plan_tool(
    ctx: ScanContext, tool: ToolInfo, counts: tuple[int, int, int], slots: asyncio.Semaphore
) -> ToolPlan:
    valid_n, boundary_n, malformed_n = counts
    plan = ToolPlan(tool)
    roots: Sequence[str] = ()
    async with slots:
        generated = await asyncio.to_thread(
            generate_valid,
            tool,
            seed=ctx.config.seed,
            mode=ctx.config.mode,
            profile=ctx.profile,
            allowed_roots=roots,
        )
    plan.valid = generated.cases[:valid_n]
    plan.notes += generated.notes
    base = next((c.arguments for c in plan.valid if isinstance(c.arguments, dict)), None)
    if boundary_n:
        boundary = boundary_cases(tool, base, seed=ctx.config.seed, mode=ctx.config.mode)
        plan.boundary = boundary.cases[:boundary_n]
        plan.notes += boundary.notes
    if malformed_n:
        malformed = malformed_cases(tool, base, seed=ctx.config.seed, mode=ctx.config.mode)
        plan.malformed = malformed.cases[:malformed_n]
        plan.notes += malformed.notes
    return plan


async def campaign(ctx: ScanContext) -> Campaign:
    """The planned campaign for this scan, built on first use."""
    existing = ctx.scratch.get(SCRATCH_KEY)
    if isinstance(existing, Campaign):
        return existing
    tools = sorted(ctx.callable_tools(), key=_priority)
    valid, boundary, malformed, kept = _allocation(
        ctx.config.mode, len(tools), ctx.budget.remaining
    )
    built = Campaign(skipped_tools=[t.name for t in tools[kept:]])
    if built.skipped_tools:
        built.notes.append(
            f"{len(built.skipped_tools)} lower-risk tool(s) were left out to fit the call budget"
        )
    slots = asyncio.Semaphore(_GENERATORS_AT_ONCE)
    built.plans = list(
        await asyncio.gather(
            *(_plan_tool(ctx, t, (valid, boundary, malformed), slots) for t in tools[:kept])
        )
    )
    ctx.scratch[SCRATCH_KEY] = built
    return built


async def _send(ctx: ScanContext, case: Case) -> Outcome:
    outcome = Outcome(case)
    params = outcome.params
    timeout = min(request_timeout(ctx.config.mode, ctx.config.timeout_scale), _CASE_TIMEOUT_S)
    try:
        exchange = await ctx.exchange("tools/call", params, timeout=timeout, case_id=case.id)
    except TargetCrashed:
        outcome.crashed = True
        try:
            outcome.reproduced = await ctx.reproduces_crash("tools/call", params, case_id=case.id)
        except TargetUnstable:
            outcome.reproduced = True  # it died again and cannot be restarted: that is a repeat
        return outcome
    outcome.exchange = exchange
    if not exchange.timed_out:
        return outcome
    # Taking long is not hanging: a slow tool that still answers other requests is merely slow.
    if await ctx.liveness():
        outcome.slow = True
        return outcome
    outcome.hung = True
    again = await ctx.exchange("tools/call", params, timeout=timeout, case_id=case.id)
    outcome.reproduced = again.timed_out
    if again.timed_out:
        await ctx.liveness()
    return outcome


async def run_case(ctx: ScanContext, case: Case, *, watch_state: bool = False) -> Outcome:
    """Send one case; with ``watch_state`` the fixtures are compared before and after."""
    fixtures = ctx.fixtures
    before = await fixtures.snapshot() if watch_state and fixtures is not None else None
    started = asyncio.get_running_loop().time()
    outcome = await _send(ctx, case)
    outcome.elapsed_ms = (asyncio.get_running_loop().time() - started) * 1000
    if fixtures is not None and before is not None and not outcome.failed_hard:
        outcome.diff = fixtures.diff(before, await fixtures.snapshot())
    return outcome


def changed_anything(diff: StateDiff | None) -> bool:
    return diff is not None and bool(
        diff.changed
        or diff.added
        or diff.removed
        or diff.backend_writes
        or diff.sqlite_changed
        or diff.collections_changed
    )


async def outcomes(ctx: ScanContext, kind: CaseKind) -> list[Outcome]:
    """Every planned case of ``kind``, run once per scan. Stops early when the budget is spent;
    ``Campaign.truncated`` then names the kind."""
    book = await campaign(ctx)
    if kind in book.outcomes:
        return book.outcomes[kind]
    done: list[Outcome] = []
    book.outcomes[kind] = done  # a target that becomes unstable mid-way keeps what it has
    for plan in book.plans:
        watch = kind == "malformed" and plan.tool.kind in WRITE_KINDS
        spent_ms = 0.0
        for case in plan.cases(kind):
            if spent_ms > _SLOW_TOOL_S * 1000:
                book.notes.append(
                    f"{plan.tool.name}: slow, so its remaining {kind} cases were skipped"
                )
                break
            try:
                outcome = await run_case(ctx, case, watch_state=watch)
            except BudgetExhausted:
                book.truncated.add(kind)
                return done
            except TargetUnstable:
                if not done:
                    raise
                book.unstable.add(kind)
                return done
            done.append(outcome)
            spent_ms += outcome.elapsed_ms
            if kind == "valid" and outcome.response is not None:
                ctx.record_baseline(
                    plan.tool.name, CallResult(outcome.response, outcome.elapsed_ms)
                )
    return done


def baseline_tools(valid: Sequence[Outcome]) -> set[str]:
    """Tools with at least one successful valid call."""
    return {o.case.tool for o in valid if o.ok}


def by_tool(items: Sequence[Outcome]) -> Mapping[str, list[Outcome]]:
    grouped: dict[str, list[Outcome]] = {}
    for item in items:
        grouped.setdefault(item.case.tool, []).append(item)
    return grouped
