"""Request metadata tolerance and outbound trace continuity."""

import re

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import CallResult, ScanContext
from probe.checks.operability._support import arguments, baseline, metadata, observation, trace_meta
from probe.checks.registry import register
from probe.checks.support import slug
from probe.engine.budget import BudgetExhausted
from probe.engine.outcomes import Severity

_TRACEPARENT = re.compile(r"[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}")


@register
class TracePropagated(Check):
    meta = metadata(
        "trace_propagated",
        "Outbound calls preserve the trace id",
        Severity.LOW,
        "active.safe",
        "A continuous trace lets operators follow a tool call into its backend.",
        "Forward a valid traceparent with the incoming trace id on outbound requests.",
        requires=frozenset({"tools", "fixtures"}),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("no fixtures")
        meta = trace_meta(ctx)
        expected = meta["traceparent"].split("-")[1]
        findings = []
        observed = 0
        for tool in ctx.callable_tools():
            args = await arguments(ctx, tool)
            if args is None:
                continue
            before = await fixtures.backend_log()
            cursor = max((r["sequence"] for r in before), default=0)
            params = {"name": tool.name, "arguments": args}
            try:
                await ctx.exchange("tools/call", params, meta={"traceparent": meta["traceparent"]})
            except BudgetExhausted:
                break
            requests = await fixtures.backend_log(cursor)
            observed += len(requests)
            bad = []
            for request in requests:
                headers = {k.lower(): v for k, v in request.get("headers", {}).items()}
                parent = headers.get("traceparent")
                match = _TRACEPARENT.fullmatch(parent) if isinstance(parent, str) else None
                if match is None or match[1] != expected:
                    bad.append({"path": request.get("path"), "traceparent": parent})
            if bad:
                findings.append(
                    observation(
                        self,
                        ctx,
                        "Outbound requests lack the incoming trace id.",
                        case=f"trace:{slug(tool.name)}",
                        tool=tool.name,
                        params={**params, "_meta": {"traceparent": meta["traceparent"]}},
                        data={"expected_trace_id": expected, "requests": bad},
                    )
                )
        if not observed:
            return CheckOutcome.na("no outbound requests observed in the fakehttp call windows")
        return CheckOutcome(findings)


@register
class MetaTolerated(Check):
    meta = metadata(
        "meta_tolerated",
        "Tools tolerate tracing and unknown metadata",
        Severity.MEDIUM,
        "active.safe",
        "Tracing and vendor metadata must not break otherwise valid calls.",
        "Accept traceparent, tracestate and baggage, and ignore unknown vendor metadata.",
        requires=frozenset({"tools"}),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings = []
        tested = 0
        for tool in ctx.callable_tools():
            args = await arguments(ctx, tool)
            if args is None:
                continue
            try:
                if await baseline(ctx, tool, args) is None:
                    continue
                params = {"name": tool.name, "arguments": args}
                exchange = await ctx.exchange("tools/call", params, meta=trace_meta(ctx))
            except BudgetExhausted:
                break
            tested += 1
            if exchange.response is None or not CallResult(exchange.response, 0).ok:
                findings.append(
                    observation(
                        self,
                        ctx,
                        "A successful baseline call was rejected with extra metadata.",
                        case=f"metadata:{slug(tool.name)}",
                        tool=tool.name,
                        params={**params, "_meta": trace_meta(ctx)},
                        data={
                            "timed_out": exchange.timed_out,
                            "response": exchange.response.to_obj() if exchange.response else None,
                            "http_status": exchange.http.status if exchange.http else None,
                        },
                    )
                )
        return (
            CheckOutcome(findings)
            if tested
            else CheckOutcome.na("could not establish a successful baseline call")
        )
