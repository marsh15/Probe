"""behavior.cancellation_honored, behavior.no_head_of_line_blocking"""

import asyncio
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._slow import (
    BLOCKING_SECONDS,
    SlowCase,
    abandon,
    cancel_call,
    slow_case,
    start_call,
)
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step
from probe.engine.crash import TargetCrashed
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity
from probe.engine.outcomes import Transport as TransportKind
from probe.wire.errors import TransportClosed
from probe.wire.jsonrpc import ErrorResponse
from probe.wire.transport_http import HttpTransport

_CANCEL_AFTER_S = 0.3
_QUIET_S = 2.0  # how long a cancelled request must stay silent, at least
_LIST_LIMIT_S = 2.0  # tools/list slower than this, while a slow call runs, counts as blocked
_SPEC = "2026-07-28/basic/patterns/cancellation#behavior-requirements"


def _slow_applicable(ctx: ScanContext) -> Applicability:
    if slow_case(ctx) is None:
        return Applicability.no(
            "no slow-capable tool (name one with tools.<name>.slow_case in the profile)"
        )
    return Applicability.yes()


@register
class CancellationHonored(Check):
    meta = CheckMeta(
        id="behavior.cancellation_honored",
        family=Family.BEHAVIOR,
        title="A cancelled request is dropped and the server stays responsive",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools", "slow_case"}),
        modes=frozenset({"quick", "standard", "deep"}),
        phase="active.stress",
        spec_refs=[_SPEC],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients cancel requests the user no longer wants. A server that keeps working and "
            "then answers anyway wastes resources and confuses clients that already moved on."
        ),
        remediation=(
            "Stop the work when a stdio notifications/cancelled arrives or an HTTP response "
            "stream closes, and send nothing further for that request."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return _slow_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        case = slow_case(ctx)
        if case is None:
            return CheckOutcome.na("no slow-capable tool")
        window = max(_QUIET_S, case.seconds - _CANCEL_AFTER_S + 0.7)
        call = await start_call(ctx, case, timeout=window + case.seconds + 5)
        problems: list[str] = []
        try:
            await asyncio.sleep(_CANCEL_AFTER_S)
            if call.task.done():
                return CheckOutcome.na("the slow call finished before it could be cancelled")
            await cancel_call(ctx, call)
            if not isinstance(ctx.client.transport, HttpTransport):
                # Over HTTP the stream is gone; on stdio a late answer would still arrive.
                try:
                    response = await asyncio.wait_for(asyncio.shield(call.task), window)
                except (TimeoutError, TransportClosed):
                    pass  # silence is the right answer (a dead target is judged below)
                else:
                    kind = "an error" if isinstance(response, ErrorResponse) else "a result"
                    problems.append(f"the server answered the cancelled request with {kind}")
        finally:
            await abandon(call)
        try:
            alive = await ctx.liveness()
        except TargetCrashed:
            alive = False
        if not alive:
            problems.append("the server stopped answering after the cancellation")
        if not problems:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title=f"Cancelling {case.tool.name} was not honored",
                    message="; ".join(problems),
                    tool=case.tool.name,
                    case_id=f"cancellation:{case.tool.name}",
                    steps=[
                        request_step(
                            "tools/call", {"name": case.tool.name, "arguments": case.arguments}
                        ),
                        {"kind": "cancel", "after_ms": int(_CANCEL_AFTER_S * 1000)},
                    ],
                    expect={
                        "after_cancel": "no further message for the request; server responsive"
                    },
                    observations={"problems": problems, "waited_s": round(window, 1)},
                )
            ]
        )


@register
class NoHeadOfLineBlocking(Check):
    meta = CheckMeta(
        id="behavior.no_head_of_line_blocking",
        family=Family.BEHAVIOR,
        title="One slow call does not hold up other requests",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools", "slow_case"}),
        modes=frozenset({"standard", "deep"}),
        phase="active.stress",
        spec_refs=["https://www.jsonrpc.org/specification#request_object"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A client that has one long call in flight still needs to list tools or make "
            "quick calls. A server that handles requests strictly one after another makes "
            "every other request wait for the slow one."
        ),
        remediation=(
            "Handle requests concurrently (async handlers or a worker pool) and keep locks "
            "short; never hold one across a long operation."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if slow_case(ctx, BLOCKING_SECONDS) is None:
            return Applicability.no(
                "no slow-capable tool (name one with tools.<name>.slow_case in the profile)"
            )
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        case = slow_case(ctx, BLOCKING_SECONDS)
        if case is None:
            return CheckOutcome.na("no slow-capable tool")
        scale = ctx.config.timeout_scale
        list_limit = _LIST_LIMIT_S * scale
        call = await start_call(ctx, case, timeout=case.seconds + 15 * scale)
        try:
            await asyncio.sleep(_CANCEL_AFTER_S)
            if call.task.done():
                return CheckOutcome.na("the slow call finished too quickly to overlap")
            started = asyncio.get_running_loop().time()
            exchange = await ctx.exchange("tools/list", timeout=case.seconds + 10 * scale)
            elapsed = asyncio.get_running_loop().time() - started
            await cancel_call(ctx, call)
        finally:
            await abandon(call)
        if not exchange.timed_out and elapsed <= list_limit:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title=f"tools/list waited for a slow {case.tool.name} call",
                    message=(
                        f"tools/list took {elapsed:.1f} s while {case.tool.name} was running "
                        f"(limit {list_limit:g} s)"
                    ),
                    tool=case.tool.name,
                    case_id=f"head-of-line:{case.tool.name}",
                    steps=[
                        request_step(
                            "tools/call", {"name": case.tool.name, "arguments": case.arguments}
                        ),
                        request_step("tools/list"),
                    ],
                    expect={"tools_list_s": f"under {list_limit:g}"},
                    observations=_observed(case, elapsed, exchange.timed_out),
                )
            ]
        )


def _observed(case: SlowCase, elapsed: float, timed_out: bool) -> dict[str, Any]:
    return {
        "tools_list_s": round(elapsed, 2),
        "timed_out": timed_out,
        "slow_call_s": case.seconds,
    }
