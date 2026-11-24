"""Concurrent read calls, including backend rate limiting when fixtures observe a route."""

import asyncio
import json
import re
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.operability._support import arguments, baseline, metadata, observation
from probe.checks.registry import register
from probe.checks.support import slug
from probe.engine.crash import TargetCrashed
from probe.engine.outcomes import Finding, Severity, ToolInfo
from probe.schema.spec import definition_problems
from probe.wire.errors import MalformedMessage, OversizeMessage, StdoutNoise
from probe.wire.jsonrpc import ResultResponse
from probe.wire.session import Exchange

_RATE = re.compile(r"\b(?:rate|limit(?:ed|ing)?|retry|429)\b", re.IGNORECASE)
_SERVER_ERROR = re.compile(r"\b(?:HTTP[ /:]*|status(?: code)?[ :=]*)5\d\d\b", re.IGNORECASE)


def problem(reply: Exchange, version: str) -> str | None:
    if reply.http is not None:
        status = reply.http.status
        headers = {k.lower(): v for k, v in reply.http.headers.items()}
        if status == 429 and headers.get("retry-after"):
            return None
        if status is not None and (status >= 500 or status == 429):
            return f"HTTP {status} without acceptable rate-limit handling"
    if reply.timed_out:
        return "burst call exceeded its deadline"
    response = reply.response
    if not isinstance(response, ResultResponse):
        return "burst call returned no well-formed tool result"
    result = response.result
    problems = definition_problems(result, "CallToolResult", version)
    if problems:
        return f"garbled tool result: {'; '.join(problems)}"
    if isinstance(result, dict):
        text = json.dumps(result.get("content", []), ensure_ascii=False)
        if _SERVER_ERROR.search(text):
            return "burst call reported a backend 5xx error"
        if result.get("isError") is True and not _RATE.search(text):
            return "tool error did not explain rate limiting or retry"
    return None


@register
class BurstResilient(Check):
    meta = metadata(
        "burst_resilient",
        "Read tools withstand concurrent bursts",
        Severity.LOW,
        "active.stress",
        "A short traffic spike should yield usable results or explicit rate-limit errors.",
        "Bound concurrency and return well-formed results or rate-limit errors "
        "with retry guidance.",
        requires=frozenset({"tools"}),
    )

    async def _burst(
        self,
        ctx: ScanContext,
        tool: ToolInfo,
        args: dict[str, Any],
        count: int,
        case: str,
        *,
        fault_routes: tuple[str, ...] = (),
    ) -> list[Finding]:
        params = {"name": tool.name, "arguments": args}

        async def send() -> list[Exchange | BaseException]:
            return list(
                await asyncio.gather(
                    *(ctx.exchange("tools/call", params, case_id=case) for _ in range(count)),
                    return_exceptions=True,
                )
            )

        event_cursor = len(ctx.wire_events())
        replies = await send()
        crashes = [reply for reply in replies if isinstance(reply, TargetCrashed)]
        if crashes:
            if ctx.budget.remaining < count:
                raise crashes[0]
            if ctx.fixtures is not None:
                for route in fault_routes:
                    await ctx.fixtures.backend_fault(route, count=count)
            repeated = await send()
            if not any(isinstance(reply, TargetCrashed) for reply in repeated):
                raise crashes[0]
            issues = ["the same concurrent burst crashed the restarted target again"]
        else:
            issues = []
            for reply in replies:
                if isinstance(reply, BaseException):
                    raise reply
                if issue := problem(reply, ctx.negotiated_version):
                    issues.append(issue)
            if any(
                isinstance(e, MalformedMessage | OversizeMessage | StdoutNoise)
                for e in ctx.wire_events()[event_cursor:]
            ):
                issues.append("garbled wire output during the burst")
        if not issues:
            return []
        return [
            observation(
                self,
                ctx,
                "; ".join(sorted(set(issues))),
                case=case,
                tool=tool.name,
                params=params,
                data={
                    "concurrent_calls": count,
                    "problems": sorted(set(issues)),
                    "reproduced_crash": bool(crashes),
                },
            )
        ]

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        reads = [t for t in ctx.callable_tools() if t.kind == "read"]
        candidates = []
        for tool in reads:
            if ctx.budget.remaining <= 1:
                break
            args = await arguments(ctx, tool)
            if args is None:
                continue
            before = await ctx.fixtures.backend_log() if ctx.fixtures is not None else []
            cursor = max((r["sequence"] for r in before), default=0)
            result = await baseline(ctx, tool, args, observe=ctx.fixtures is not None)
            if result is None:
                continue
            requests = await ctx.fixtures.backend_log(cursor) if ctx.fixtures is not None else []
            candidates.append((result.elapsed_ms, tool.name, tool, args, requests))
        if not candidates:
            return CheckOutcome.na("could not establish a successful baseline call on a read tool")
        candidates.sort(key=lambda c: (c[0], c[1]))
        desired = 200 if ctx.config.mode == "deep" else 50
        count = min(desired, ctx.budget.remaining)
        if count < 1:
            return CheckOutcome.error("no budget remains for a concurrent burst")
        findings = self._budget_note(ctx, desired, count, "burst-budget")
        _, _, tool, args, _ = candidates[0]
        findings += await self._burst(ctx, tool, args, count, f"burst:{slug(tool.name)}")
        for _, _, tool, args, requests in candidates:
            if ctx.fixtures is None or not requests:
                continue
            count = min(desired, ctx.budget.remaining)
            findings += self._budget_note(
                ctx, desired, count, f"burst-429-budget:{slug(tool.name)}"
            )
            if count == 0:
                continue
            routes = sorted({r["path"] for r in requests})
            armed = False
            try:
                for route in routes:
                    armed |= await ctx.fixtures.backend_fault(route, count=count)
                if armed:
                    findings += await self._burst(
                        ctx,
                        tool,
                        args,
                        count,
                        f"burst-429:{slug(tool.name)}",
                        fault_routes=tuple(routes),
                    )
            finally:
                if armed:
                    await ctx.fixtures.backend_fault(None)
        return CheckOutcome(findings)

    def _budget_note(self, ctx: ScanContext, desired: int, count: int, case: str) -> list[Finding]:
        if count == desired:
            return []
        return [
            observation(
                self,
                ctx,
                f"Budget reduced the burst from {desired} to {count} concurrent calls.",
                case=case,
                severity=Severity.INFO,
                data={"requested": desired, "actual": count},
            )
        ]
