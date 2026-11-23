"""Helpers shared by the schema checks."""

from collections.abc import Mapping, Sequence
from typing import Any

from probe.checks.base import Applicability, Check
from probe.checks.context import ScanContext
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.engine.outcomes import Finding, Severity

MAX_FINDINGS = 25

__all__ = [
    "ALL_MODES",
    "MAX_FINDINGS",
    "listing_applicable",
    "named_tools",
    "tool_findings",
]


def listing_applicable(ctx: ScanContext) -> Applicability:
    """Static checks read the raw tools/list result captured at discovery."""
    listing = ctx.listing
    if listing is None:
        return Applicability.no("tools/list was not captured")
    if not listing.tools:
        return Applicability.no(listing.error or "the server lists no tools")
    return Applicability.yes()


def named_tools(ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
    """Each raw tool with a label for reports (its name, or its position if it has none)."""
    tools = ctx.listing.tools if ctx.listing is not None else []
    return [
        (t["name"] if isinstance(t.get("name"), str) and t["name"] else f"(tool #{i})", t)
        for i, t in enumerate(tools)
    ]


def tool_findings(
    check: Check,
    ctx: ScanContext,
    issues: Mapping[str, Sequence[str]],
    *,
    severity: Severity,
    title: str,
    case_prefix: str,
    expect: Mapping[str, Any],
) -> list[Finding]:
    """One finding per tool with ``issues`` (at most MAX_FINDINGS, the rest summarized)."""
    findings: list[Finding] = []
    flagged = list(issues.items())
    for tool, problems in flagged[:MAX_FINDINGS]:
        findings.append(
            make_finding(
                check,
                ctx,
                severity=severity,
                title=f"{title}: {tool}",
                message="; ".join(problems),
                tool=tool if not tool.startswith("(tool #") else None,
                case_id=f"{case_prefix}:{slug(tool)}",
                steps=[request_step("tools/list")],
                expect=expect,
                observations={"problems": list(problems)},
            )
        )
    if len(flagged) > MAX_FINDINGS:
        rest = [name for name, _ in flagged[MAX_FINDINGS:]]
        findings.append(
            make_finding(
                check,
                ctx,
                severity=severity,
                title=f"{title}: {len(rest)} more tools",
                message=f"{len(rest)} further tools have the same kind of problem.",
                case_id=f"{case_prefix}:more",
                steps=[request_step("tools/list")],
                expect=expect,
                observations={"tools": rest[:100]},
            )
        )
    return findings
