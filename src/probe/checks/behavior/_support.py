"""Helpers shared by the behavior checks."""

from collections.abc import Mapping, Sequence
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import Campaign, Outcome
from probe.checks.context import ScanContext
from probe.checks.support import ALL_MODES, make_finding
from probe.engine.outcomes import Finding, Severity
from probe.schema.cases import CaseKind
from probe.wire.mrtr import ElicitationRule, InputPolicy

MAX_FINDINGS = 25
_EXCERPT = 300

__all__ = [
    "ALL_MODES",
    "MAX_FINDINGS",
    "Verdict",
    "clip",
    "conclude",
    "drop_paging",
    "input_policy",
    "tool_findings",
]


_PAGING = frozenset({"cursor", "page_token", "next_cursor", "pageToken", "page", "offset"})


def drop_paging(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Arguments without paging position: a generated cursor is not one the server issued."""
    return {k: v for k, v in arguments.items() if k not in _PAGING}


def clip(text: str, limit: int = _EXCERPT) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Verdict:
    """A case that went wrong, with what to say about it."""

    __slots__ = ("outcome", "reason")

    def __init__(self, outcome: Outcome, reason: str) -> None:
        self.outcome = outcome
        self.reason = reason


def tool_findings(
    check: Check,
    ctx: ScanContext,
    bad: Mapping[str, Sequence[Verdict]],
    *,
    severity: Severity,
    title: str,
    case_prefix: str,
    expect: Mapping[str, Any],
) -> list[Finding]:
    """One finding per tool with bad cases (at most MAX_FINDINGS; the rest are summarized)."""
    findings: list[Finding] = []
    items = list(bad.items())
    for tool, verdicts in items[:MAX_FINDINGS]:
        first = verdicts[0]
        reasons = sorted({v.reason for v in verdicts})
        findings.append(
            make_finding(
                check,
                ctx,
                severity=severity,
                title=f"{title}: {tool}",
                message="; ".join(reasons),
                tool=tool,
                case_id=first.outcome.case.id,
                steps=[first.outcome.step],
                expect=expect,
                observations={
                    "cases": [v.outcome.case.id for v in verdicts[:10]],
                    "count": len(verdicts),
                    "reasons": reasons,
                    "first_reply": clip(first.outcome.text()),
                },
            )
        )
    if len(items) > MAX_FINDINGS:
        rest = [name for name, _ in items[MAX_FINDINGS:]]
        findings.append(
            make_finding(
                check,
                ctx,
                severity=severity,
                title=f"{title}: {len(rest)} more tools",
                message=f"{len(rest)} further tools have the same kind of problem.",
                case_id=f"{case_prefix}:more",
                steps=[],
                expect=expect,
                observations={"tools": rest[:50]},
            )
        )
    return findings


def conclude(
    findings: list[Finding],
    unreproduced: Sequence[Outcome],
    book: Campaign | None = None,
    kind: CaseKind | None = None,
) -> CheckOutcome:
    """Findings if there are any. Otherwise an ERROR when the verdict is not trustworthy: the only
    trouble was a crash that did not repeat, or the target gave out before every case ran."""
    if findings:
        return CheckOutcome(findings)
    if book is not None and kind in book.unstable:
        return CheckOutcome.error("target_unstable: the target kept dying before every case ran")
    if unreproduced:
        cases = ", ".join(o.case.id for o in unreproduced[:3])
        return CheckOutcome.error(f"the target stopped on {cases} but it did not happen again")
    return CheckOutcome()


def input_policy(ctx: ScanContext) -> InputPolicy:
    """How to answer a server's requests for input: the profile's elicitation answers, else
    decline (which never changes anything)."""
    profile = ctx.profile
    answers = profile.elicitation_answers if profile is not None else []
    rules = [
        ElicitationRule(
            a.match.key,
            a.match.message_regex,
            a.response.action,
            a.response.content,
        )
        for a in answers
    ]
    roots: tuple[str, ...] = ()
    if profile is not None and profile.fixtures.fs is not None:
        roots = tuple(f"file://{r}" for r in profile.fixtures.fs.allowed_roots)
    return InputPolicy(rules, roots) if roots else InputPolicy(rules)
