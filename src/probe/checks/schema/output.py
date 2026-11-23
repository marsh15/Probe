"""Checks on the structured results of tool calls that succeeded."""

import json
from typing import Any

from jsonschema.validators import Draft202012Validator, validator_for

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import Outcome, by_tool, campaign, outcomes
from probe.checks.behavior._support import Verdict, tool_findings
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.schema._support import ALL_MODES
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport

_MAX_PROBLEMS = 3


def output_problems(schema: Any, value: Any) -> list[str]:
    """Why ``value`` does not satisfy ``schema`` (empty if it does or cannot be judged)."""
    try:
        validator = validator_for(schema, default=Draft202012Validator)(schema)
        errors = sorted(validator.iter_errors(value), key=lambda e: list(e.absolute_path))
    except Exception:  # an unresolvable ref or an exotic schema: not the server's fault here
        return []
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message[:160]}"
        for e in errors[:_MAX_PROBLEMS]
    ]


def _with_output_schema(ctx: ScanContext) -> set[str]:
    return {t.name for t in ctx.tools if t.output_schema is not None}


def _structured_calls(ctx: ScanContext, succeeded: list[Outcome]) -> list[Outcome]:
    names = _with_output_schema(ctx)
    return [o for o in succeeded if o.ok and o.case.tool in names]


@register
class OutputConforms(Check):
    meta = CheckMeta(
        id="schema.output_conforms",
        family=Family.SCHEMA,
        title="Structured results match the tool's outputSchema",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.write",
        spec_refs=["2026-07-28/server/tools#output-schema"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A client validates structuredContent against the published outputSchema and "
            "rejects results that do not fit. A server that breaks its own schema makes "
            "otherwise working calls fail on the client."
        ),
        remediation=(
            "Return structuredContent on every successful call of a tool with an outputSchema, "
            "and make it satisfy the schema (or fix the schema)."
        ),
        min_version="2025-06-18",
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not _with_output_schema(ctx):
            return Applicability.no("no tool declares an outputSchema")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        calls = _structured_calls(ctx, await outcomes(ctx, "valid"))
        if not calls:
            return CheckOutcome.na("no call of a tool with an outputSchema succeeded")
        schemas = {t.name: t.output_schema for t in ctx.tools}
        bad: dict[str, list[Verdict]] = {}
        for o in calls:
            structured = (o.result or {}).get("structuredContent")
            if structured is None:
                reason = "structuredContent is missing"
            else:
                problems = output_problems(schemas[o.case.tool], structured)
                if not problems:
                    continue
                reason = "; ".join(problems)
            bad.setdefault(o.case.tool, []).append(Verdict(o, reason))
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                bad,
                severity=Severity.HIGH,
                title="Result does not match the outputSchema",
                case_prefix="output-conforms",
                expect={"structuredContent": "present and valid under outputSchema"},
            )
        )


def _mirrors(result: dict[str, Any]) -> bool:
    """Is the structured content also present as JSON text (the compatibility rule)?"""
    structured = result.get("structuredContent")
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return False
    for block in blocks:
        text = block.get("text") if isinstance(block, dict) else None
        if not isinstance(text, str):
            continue
        try:
            if json.loads(text) == structured:
                return True
        except ValueError:
            continue
    return False


@register
class StructuredTextMirror(Check):
    meta = CheckMeta(
        id="schema.structured_text_mirror",
        family=Family.SCHEMA,
        title="Structured results are also returned as JSON text",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.write",
        spec_refs=["2026-07-28/server/tools#structured-content"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients that do not read structuredContent rely on the text content. Without "
            "an equivalent JSON text block they see nothing useful."
        ),
        remediation="Also return the structured value as JSON in a text content block.",
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        await campaign(ctx)
        valid = await outcomes(ctx, "valid")
        calls = [o for o in valid if o.ok and (o.result or {}).get("structuredContent") is not None]
        if not calls:
            return CheckOutcome.na("no successful call returned structuredContent")
        bad: dict[str, list[Verdict]] = {}
        for tool, group in by_tool(calls).items():
            missing = [o for o in group if not _mirrors(o.result or {})]
            if missing:
                bad[tool] = [Verdict(o, "no text block holds the same JSON") for o in missing]
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                bad,
                severity=Severity.LOW,
                title="Structured result has no JSON text mirror",
                case_prefix="structured-mirror",
                expect={"content": "a text block with the JSON of structuredContent"},
            )
        )
