"""behavior.concurrency_consistent"""

import asyncio
import re
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import WRITE_KINDS, campaign
from probe.checks.behavior._support import clip
from probe.checks.context import ScanContext
from probe.checks.normalize_volatile import normalize_volatile
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    ToolInfo,
)
from probe.engine.outcomes import Transport as TransportKind
from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse
from probe.wire.session import Exchange

_CALLS = 8
_TOOLS_JUDGED = 3  # tools that get a burst
_TOOLS_TRIED = 8  # tools looked at to find those
_RATE_LIMIT = re.compile(
    r"\b(?:rate[ _-]?limit(?:ed|ing)?|too many requests|(?:http|status(?: code)?)[ /:=]*429)\b",
    re.IGNORECASE,
)


def _comparable(response: Response | None) -> Any:
    """What two answers to the same call must share: the result body, or the error code."""
    if isinstance(response, ResultResponse) and isinstance(response.result, dict):
        keep = {k: response.result.get(k) for k in ("content", "structuredContent", "isError")}
        return normalize_volatile(keep)
    if isinstance(response, ErrorResponse):
        return {"error": response.error.code, "message": response.error.message}
    return None


def _rate_limited(reply: Exchange | BaseException) -> bool:
    if not isinstance(reply, Exchange):
        return False
    if reply.http is not None and reply.http.status == 429:
        return True
    response = reply.response
    if isinstance(response, ErrorResponse):
        return response.error.code == 429 or _RATE_LIMIT.search(response.error.message) is not None
    if isinstance(response, ResultResponse) and isinstance(response.result, dict):
        blocks = response.result.get("content")
        if response.result.get("isError") is True and isinstance(blocks, list):
            return any(
                isinstance(block, dict)
                and isinstance(text := block.get("text"), str)
                and _RATE_LIMIT.search(text)
                for block in blocks
            )
    return False


async def _burst(
    ctx: ScanContext, tool: ToolInfo, arguments: dict[str, Any]
) -> list[Exchange | BaseException]:
    params = {"name": tool.name, "arguments": arguments}
    ctx.spend(_CALLS)  # one budgeted unit per call; the requests themselves go straight out
    return list(
        await asyncio.gather(
            *(ctx.client.exchange("tools/call", params) for _ in range(_CALLS)),
            return_exceptions=True,
        )
    )


@register
class ConcurrencyConsistent(Check):
    meta = CheckMeta(
        id="behavior.concurrency_consistent",
        family=Family.BEHAVIOR,
        title="Concurrent identical calls get identical answers",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools"}),
        modes=frozenset({"standard", "deep"}),
        phase="active.stress",
        spec_refs=["https://www.jsonrpc.org/specification#request_object"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients issue several requests at once. A server that mixes up shared state "
            "between concurrent calls returns one caller's data to another, or garbled results."
        ),
        remediation=(
            "Keep per-request state out of module-level variables, and guard shared state "
            "with locks or per-request copies."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(t.kind == "read" for t in ctx.callable_tools()):
            return Applicability.no("no read tool can be called")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        findings: list[Finding] = []
        judged = tried = 0
        rate_limited = False
        for plan in book.plans:
            tool = plan.tool
            args = next((c.arguments for c in plan.valid if isinstance(c.arguments, dict)), None)
            if tool.kind in WRITE_KINDS or args is None:
                continue
            if judged >= _TOOLS_JUDGED or tried >= _TOOLS_TRIED:
                break
            tried += 1
            first = await ctx.establish_baseline(tool, args)
            if first is None:
                continue
            again = await ctx.call(tool.name, args)  # a tool that disagrees with itself is skipped
            baseline = _comparable(first.response)
            if _comparable(again.response) != baseline:
                continue
            compared, finding = await self._judge(ctx, tool, args, baseline)
            judged += compared
            rate_limited |= not compared
            if finding is not None:
                findings.append(finding)
        if not judged:
            if rate_limited:
                return CheckOutcome.na("rate limiting prevented a conclusive burst comparison")
            return CheckOutcome.na("could not establish a successful, repeatable baseline call")
        return CheckOutcome(findings)

    async def _judge(
        self, ctx: ScanContext, tool: ToolInfo, arguments: dict[str, Any], baseline: Any
    ) -> tuple[bool, Finding | None]:
        problems: list[str] = []
        for _ in range(2):  # a mismatch must show up twice to count
            replies = await _burst(ctx, tool, arguments)
            comparable = [reply for reply in replies if not _rate_limited(reply)]
            problems = self._problems(comparable, baseline)
            if not await ctx.liveness():  # a dead target is recorded and restarted here
                problems.append("the server stopped answering")
            if not problems:
                return bool(comparable), None
        return True, make_finding(
            self,
            ctx,
            severity=Severity.MEDIUM,
            title=f"Concurrent calls to {tool.name} disagreed",
            message=clip("; ".join(sorted(set(problems))), 400),
            tool=tool.name,
            case_id=f"concurrency:{tool.name}",
            steps=[request_step("tools/call", {"name": tool.name, "arguments": arguments})],
            expect={"answers": f"{_CALLS} identical answers"},
            observations={"calls": _CALLS, "problems": sorted(set(problems))[:5]},
        )

    @staticmethod
    def _problems(replies: list[Exchange | BaseException], baseline: Any) -> list[str]:
        problems = []
        for reply in replies:
            if isinstance(reply, BaseException):
                problems.append(f"a call failed: {type(reply).__name__}")
            elif reply.timed_out:
                problems.append("a call got no answer in time")
            elif reply.response is None:
                problems.append("a call returned no response")
            elif _comparable(reply.response) != baseline:
                problems.append("an answer differed from the single-call answer")
        return problems
