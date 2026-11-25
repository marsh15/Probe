"""Protocol checks that read what already happened: result types, error codes, stdout."""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import ALL_MODES, main_messages, make_finding, response_methods
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.wire.errors import StdoutNoise

_SAMPLE = 5
# Codes -32023..-32099 are reserved for the spec and none are defined there yet (modern era
# only: in legacy MCP the whole -32000..-32099 range is implementation-defined).
_RESERVED_LOW, _RESERVED_HIGH = -32099, -32023
_LEGACY_RESOURCE_NOT_FOUND = -32002


def _results(ctx: ScanContext) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [(r, m) for r, m in main_messages(ctx, "s2c") if "result" in m and "error" not in m]


def _errors(ctx: ScanContext) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [(r, m) for r, m in main_messages(ctx, "s2c") if isinstance(m.get("error"), dict)]


@register
class ResultTypePresent(Check):
    meta = CheckMeta(
        id="protocol.result_type_present",
        family=Family.PROTOCOL,
        title="Every modern result carries resultType",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["2026-07-28/schema#result"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "resultType tells a client whether a result is complete or needs more input. Without "
            "it, clients cannot tell a finished result from an input request."
        ),
        remediation='Include resultType ("complete" or "input_required") in every result.',
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if ctx.trace is None:
            return Applicability.no("no trace was recorded")
        if not _results(ctx):
            return Applicability.no("no results were recorded")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        methods = response_methods(ctx)
        missing = [
            (r, m)
            for r, m in _results(ctx)
            if not isinstance(m["result"], dict) or "resultType" not in m["result"]
        ]
        if not missing:
            return CheckOutcome()
        seen = sorted({methods.get(r["seq"], "(unknown)") for r, _ in missing})
        listed = ", ".join(seen)
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title="Results without resultType",
                    message=f"{len(missing)} result(s) lacked resultType (methods: {listed})",
                    case_id="result-type:missing",
                    steps=[],
                    expect={"resultType": "present in every result"},
                    observations={
                        "count": len(missing),
                        "methods": seen,
                        "trace_seq": [r["seq"] for r, _ in missing[:_SAMPLE]],
                    },
                )
            ]
        )


@register
class ErrorCodeRanges(Check):
    meta = CheckMeta(
        id="protocol.error_code_ranges",
        family=Family.PROTOCOL,
        title="Error codes stay inside the ranges the spec allows",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["2026-07-28/schema#errors"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "-32020 to -32099 belong to the spec and -32000 to -32019 to implementations. A "
            "server that uses a reserved code, or an integer-less one, breaks clients that "
            "switch on error codes."
        ),
        remediation=(
            "Use the standard JSON-RPC codes, the spec-defined -32020 to -32022, or a code in "
            "-32000..-32019. Report a missing resource as -32602 in the modern era."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return Applicability.yes() if ctx.trace is not None else Applicability.no("no trace")

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        # A scan that sends only valid requests never sees an invalid-params error, which is
        # exactly the code servers most often get wrong; provoke one so there is one to judge.
        await ctx.exchange("tools/call", {}, case_id="error-code:invalid-params")
        bad: list[tuple[dict[str, Any], str]] = []
        for record, message in _errors(ctx):
            code = message["error"].get("code")
            if isinstance(code, bool) or not isinstance(code, int):
                bad.append((record, "code is not an integer"))
            elif ctx.era is Era.MODERN and _RESERVED_LOW <= code <= _RESERVED_HIGH:
                bad.append((record, f"{code} is in the range reserved for the spec"))
            elif code == _LEGACY_RESOURCE_NOT_FOUND and ctx.era is Era.MODERN:
                bad.append((record, "-32002 was replaced by -32602 in the modern era"))
        if not bad:
            return CheckOutcome()
        reasons = sorted({reason for _, reason in bad})
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title="Error codes outside the allowed ranges",
                    message="; ".join(reasons),
                    case_id="error-code:range",
                    steps=[],
                    expect={"codes": "standard, -32020..-32022, or -32000..-32019"},
                    observations={
                        "count": len(bad),
                        "reasons": reasons,
                        "trace_seq": [r["seq"] for r, _ in bad[:_SAMPLE]],
                    },
                )
            ]
        )


@register
class StdoutClean(Check):
    meta = CheckMeta(
        id="protocol.stdout_clean",
        family=Family.PROTOCOL,
        title="Standard output carries only MCP messages",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset({Transport.STDIO}),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["2026-07-28/basic/transports/stdio"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "On stdio, stdout is the protocol channel. A stray print or banner there corrupts "
            "the stream for every client."
        ),
        remediation="Write logs and diagnostics to stderr; keep stdout for JSON-RPC messages only.",
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        noise = [e for e in ctx.wire_events() if isinstance(e, StdoutNoise)]
        if not noise:
            return CheckOutcome()
        excerpts = [e.excerpt for e in noise[:_SAMPLE]]
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title="Non-JSON-RPC output on stdout",
                    message=f"{len(noise)} line(s) on stdout were not JSON-RPC messages",
                    case_id="stdout:noise",
                    steps=[],
                    expect={"stdout": "JSON-RPC messages only"},
                    observations={"count": len(noise), "samples": excerpts},
                    excerpt="\n".join(excerpts),
                )
            ]
        )
