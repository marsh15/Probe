"""How a tool treats valid, extreme and invalid input."""

import re
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import (
    baseline_tools,
    campaign,
    changed_anything,
    outcomes,
)
from probe.checks.behavior._support import (
    ALL_MODES,
    Verdict,
    clip,
    conclude,
    tool_findings,
)
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport

_INVALID_PARAMS = -32602
_GENERIC = re.compile(r"(error|internal error|failed|exception)\.?", re.IGNORECASE)
_EXPECTATION = re.compile(
    r"\b(must|expected|invalid|required|missing|should|not allowed|cannot|unexpected|"
    r"too (long|short|large|small|many|few)|type|schema|validation)\b",
    re.IGNORECASE,
)
_TYPE_WORDS = re.compile(r"\b(string|number|integer|boolean|array|object|null)\b", re.IGNORECASE)
_MIN_ERRORS = 3
_SHARE_BAD = 0.5
_SAMPLES = 5


def _no_cases(kind: str) -> CheckOutcome:
    return CheckOutcome.na(f"no {kind} inputs could be generated for the callable tools")


@register
class ValidInputAccepted(Check):
    meta = CheckMeta(
        id="behavior.valid_input_accepted",
        family=Family.BEHAVIOR,
        title="Input that fits the schema is not rejected",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.write",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A client builds arguments from the published inputSchema. If the server answers "
            "-32602 (invalid params) to input that schema allows, or dies on it, the schema "
            "does not describe what the server accepts."
        ),
        remediation=(
            "Make the inputSchema match what the tool accepts, or accept everything it allows. "
            "Report problems with the data itself as a tool error (isError), not -32602."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        valid = await outcomes(ctx, "valid")
        if not valid:
            return _no_cases("valid")
        bad: dict[str, list[Verdict]] = {}
        unreproduced = []
        for o in valid:
            error = o.rpc_error
            if error is not None and error.error.code == _INVALID_PARAMS:
                reason = f"-32602 for valid input: {clip(error.error.message, 120)}"
            elif o.failed_hard and o.reproduced:
                reason = "the server stopped answering, also when the call was repeated"
            elif o.failed_hard:
                unreproduced.append(o)
                continue
            else:
                continue
            bad.setdefault(o.case.tool, []).append(Verdict(o, reason))
        findings = tool_findings(
            self,
            ctx,
            bad,
            severity=Severity.MEDIUM,
            title="Valid input rejected or fatal",
            case_prefix="valid-input",
            expect={"not": "-32602 or a dead server for input that fits inputSchema"},
        )
        return conclude(findings, unreproduced, book, "valid")


@register
class InvalidInputRejected(Check):
    meta = CheckMeta(
        id="behavior.invalid_input_rejected",
        family=Family.BEHAVIOR,
        title="Input that breaks the schema is refused and changes nothing",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A server that accepts input its own schema forbids has no validation at all: "
            "bad values reach file systems, databases and downstream services."
        ),
        remediation=(
            "Validate arguments against the inputSchema before acting and answer violations "
            "with -32602 or a tool error. A refused call must not change any state."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        valid = await outcomes(ctx, "valid")
        trusted = baseline_tools(valid)
        book = await campaign(ctx)
        required = {p.tool.name: bool(p.tool.input_schema.get("required")) for p in book.plans}
        malformed = [
            o
            for o in await outcomes(ctx, "malformed")
            # ``arguments`` is optional, so null is the same as leaving it out: not a violation
            # for a tool that needs no arguments.
            if o.case.tool in trusted
            and not (o.case.arguments is None and not required[o.case.tool])
        ]
        if not malformed:
            return CheckOutcome.na("could not establish a successful baseline call")
        bad: dict[str, list[Verdict]] = {}
        for o in malformed:
            if changed_anything(o.diff):
                reason = "a call with invalid arguments changed state"
            elif o.ok:
                reason = f"invalid arguments ({o.case.rule}) were accepted"
            else:
                continue
            bad.setdefault(o.case.tool, []).append(Verdict(o, reason))
        findings = tool_findings(
            self,
            ctx,
            bad,
            severity=Severity.HIGH,
            title="Invalid input accepted",
            case_prefix="invalid-input",
            expect={"result": "an error, and no change in state"},
        )
        return CheckOutcome(findings)


@register
class BoundaryRobust(Check):
    meta = CheckMeta(
        id="behavior.boundary_robust",
        family=Family.BEHAVIOR,
        title="Extreme but allowed input does not crash the server",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Empty strings, very long values, huge numbers and big arrays are ordinary "
            "inputs for an attacker. A server must answer them, even with an error, "
            "and keep running."
        ),
        remediation=(
            "Handle the limits of every parameter: bound sizes, check numeric ranges and "
            "return an error instead of crashing, hanging or answering HTTP 5xx."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        boundary = await outcomes(ctx, "boundary")
        if not boundary:
            return _no_cases("boundary")
        bad: dict[str, list[Verdict]] = {}
        unreproduced = []
        for o in boundary:
            status = o.http_status
            if o.failed_hard and o.reproduced:
                kind = "hang" if o.hung else "crash"
                reason = f"the server {kind} on {o.case.rule}, also when the call was repeated"
            elif o.failed_hard:
                unreproduced.append(o)
                continue
            elif status is not None and status >= 500:
                reason = f"HTTP {status} for {o.case.rule}"
            else:
                continue
            bad.setdefault(o.case.tool, []).append(Verdict(o, reason))
        findings = tool_findings(
            self,
            ctx,
            bad,
            severity=Severity.MEDIUM,
            title="Boundary input broke the server",
            case_prefix="boundary",
            expect={"alive": True, "http_status": "below 500"},
        )
        return conclude(findings, unreproduced, book, "boundary")


def _vocabulary(schema: Any) -> set[str]:
    """Names a helpful message could mention: the tool's parameter names."""
    properties = schema.get("properties") if isinstance(schema, dict) else None
    return {name for name in properties if isinstance(name, str)} if properties else set()


def actionable(text: str, parameters: set[str]) -> bool:
    """Does an error message say what is wrong, or at least name what to fix?"""
    cleaned = text.strip()
    if not cleaned or _GENERIC.fullmatch(cleaned):
        return False
    lowered = cleaned.lower()
    return bool(
        any(name.lower() in lowered for name in parameters)
        or _TYPE_WORDS.search(cleaned)
        or _EXPECTATION.search(cleaned)
    )


@register
class ErrorsActionable(Check):
    meta = CheckMeta(
        id="behavior.errors_actionable",
        family=Family.BEHAVIOR,
        title="Error messages tell the caller what to fix",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "An agent can only correct a failed call if the error says what was wrong. "
            '"Error" or an empty message sends it into a retry loop.'
        ),
        remediation=(
            "Name the parameter and the rule it broke, e.g. 'limit must be between 1 and 100'."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        malformed = await outcomes(ctx, "malformed")
        failed = [o for o in malformed if (o.rpc_error is not None or o.tool_error)]
        if len(failed) < _MIN_ERRORS:
            return CheckOutcome.na(
                f"fewer than {_MIN_ERRORS} malformed calls were answered with an error"
            )
        schemas = {p.tool.name: p.tool.input_schema for p in book.plans}
        bad = [o for o in failed if not actionable(o.text(), _vocabulary(schemas[o.case.tool]))]
        if len(bad) / len(failed) <= _SHARE_BAD:
            return CheckOutcome()
        samples = [{"case": o.case.id, "message": clip(o.text(), 120)} for o in bad[:_SAMPLES]]
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title="Errors do not say what is wrong",
                    message=(
                        f"{len(bad)} of {len(failed)} error replies to invalid input were empty, "
                        "generic, or named neither the parameter nor the rule."
                    ),
                    case_id="errors-actionable",
                    steps=[bad[0].step],
                    expect={"message": "names the parameter or the violated rule"},
                    observations={"bad": len(bad), "errors": len(failed), "samples": samples},
                )
            ]
        )
