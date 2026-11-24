"""Shared metadata, valid arguments and evidence for operability probes."""

import asyncio
import hashlib
from typing import Any

from probe.checks.base import Check
from probe.checks.context import CallResult, ScanContext
from probe.checks.support import ALL_MODES, make_finding, request_step
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Phase,
    Requirement,
    Severity,
    ToolInfo,
    Transport,
)
from probe.schema.valid_gen import generate_valid
from probe.wire.errors import RequestTimeout
from probe.wire.transport_http import HttpRequestFailed


def metadata(
    name: str,
    title: str,
    severity: Severity,
    phase: Phase,
    rationale: str,
    remediation: str,
    *,
    requires: frozenset[Requirement] = frozenset(),
) -> CheckMeta:
    return CheckMeta(
        id=f"operability.{name}",
        family=Family.OPERABILITY,
        title=title,
        severity=severity,
        eras=frozenset(Era),
        transports=frozenset({Transport.STDIO})
        if name == "clean_shutdown"
        else frozenset(Transport),
        requires=requires,
        modes=frozenset({"standard", "deep"}) if name == "burst_resilient" else ALL_MODES,
        phase=phase,
        spec_refs=[
            {
                "trace_propagated": "2026-07-28/schema#request",
                "meta_tolerated": "2026-07-28/schema#request",
                "burst_resilient": "2026-07-28/server/tools#error-handling",
                "logs_no_secrets": "2026-07-28/server/utilities/logging#security-considerations",
                "clean_shutdown": "2026-07-28/basic/lifecycle#shutdown",
                "startup_time": "2026-07-28/basic/lifecycle#initialization",
            }[name]
        ],
        disclosure=DisclosureTier.PUBLIC,
        rationale=rationale,
        remediation=remediation,
    )


def trace_meta(ctx: ScanContext) -> dict[str, str]:
    digest = hashlib.sha256(f"probe-operability:{ctx.config.seed}".encode()).hexdigest()
    return {
        "traceparent": f"00-{digest[:32]}-{digest[32:48]}-01",
        "tracestate": "probe=operability",
        "baggage": "probe=operability",
        "com.example/x": "probe",
    }


async def arguments(ctx: ScanContext, tool: ToolInfo) -> dict[str, Any] | None:
    generated = await asyncio.to_thread(
        generate_valid, tool, seed=ctx.config.seed, mode="quick", profile=ctx.profile
    )
    return next(
        (case.arguments for case in generated.cases if isinstance(case.arguments, dict)), None
    )


def observation(
    check: Check,
    ctx: ScanContext,
    message: str,
    *,
    case: str,
    tool: str | None = None,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    severity: Severity | None = None,
    excerpt: str | None = None,
) -> Finding:
    return make_finding(
        check,
        ctx,
        severity=severity or check.meta.severity,
        title=check.meta.title,
        message=message,
        case_id=case,
        tool=tool,
        steps=[request_step("tools/call", params)] if params is not None else [],
        expect={"behavior": check.meta.remediation},
        observations=data,
        excerpt=excerpt,
    )


async def baseline(
    ctx: ScanContext, tool: ToolInfo, args: dict[str, Any], *, observe: bool = False
) -> CallResult | None:
    try:
        if observe and ctx.baseline(tool.name) is not None:
            result = await ctx.call(tool.name, args, case_id=f"{tool.name}:baseline")
            return result if result.ok else None
        return await ctx.establish_baseline(tool, args)
    except (RequestTimeout, HttpRequestFailed):
        return None
