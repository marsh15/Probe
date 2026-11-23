"""What a tool says about repeating a call, and whether it holds to it."""

import re
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import changed_anything, outcomes, run_case
from probe.checks.behavior._support import ALL_MODES, MAX_FINDINGS
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step, slug
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

_KEY_PARAM = re.compile(r"idempotency_?key|request_?id|client_?token", re.IGNORECASE)
_WRITES = frozenset({"write", "destructive"})


def contract(ctx: ScanContext, tool: ToolInfo) -> tuple[bool | None, str]:
    """(is it promised idempotent, where the promise comes from): profile, then annotation, then
    an idempotency-key parameter. (None, "") if nothing is said."""
    override = ctx.profile.override_for(tool.name) if ctx.profile is not None else None
    if override is not None and override.idempotent is not None:
        return override.idempotent, "the profile"
    hint = tool.annotations.get("idempotentHint")
    if isinstance(hint, bool):
        return hint, "the idempotentHint annotation"
    properties = tool.input_schema.get("properties")
    if isinstance(properties, dict) and any(_KEY_PARAM.fullmatch(p) for p in properties):
        return True, "an idempotency key parameter"
    return None, ""


@register
class IdempotencyDeclared(Check):
    meta = CheckMeta(
        id="behavior.idempotency_declared",
        family=Family.BEHAVIOR,
        title="Tools that change data say whether repeating them is safe",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"write_tools"}),
        modes=ALL_MODES,
        phase="static",
        spec_refs=["2026-07-28/server/tools#annotations"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Agents retry failed calls. Without idempotentHint a client cannot tell whether "
            "a retry will create a duplicate or do the same thing twice."
        ),
        remediation="Set annotations.idempotentHint (true or false) on every tool that writes.",
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(t.kind in _WRITES for t in ctx.tools):
            return Applicability.no("no tool is classified as writing or destructive")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        missing = [
            t
            for t in ctx.tools
            if t.kind in _WRITES and not isinstance(t.annotations.get("idempotentHint"), bool)
        ]
        findings: list[Finding] = [
            make_finding(
                self,
                ctx,
                severity=Severity.LOW,
                title=f"No idempotentHint: {t.name}",
                message=f"{t.name} changes data ({t.classification_reason}) but does not say "
                "whether repeating it is safe.",
                tool=t.name,
                case_id=f"idempotency-declared:{slug(t.name)}",
                steps=[request_step("tools/list")],
                expect={"annotations.idempotentHint": "true or false"},
                observations={"kind": t.kind, "annotations": sorted(t.annotations)},
            )
            for t in missing[:MAX_FINDINGS]
        ]
        return CheckOutcome(findings)


@register
class ReplayIdempotent(Check):
    meta = CheckMeta(
        id="behavior.replay_idempotent",
        family=Family.BEHAVIOR,
        title="A tool that promises idempotence changes nothing the second time",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"write_tools", "fixtures", "side_effects"}),
        modes=ALL_MODES,
        phase="active.write",
        spec_refs=["2026-07-28/server/tools#annotations"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients retry calls on timeouts. A tool marked idempotent that writes again on "
            "the second call corrupts data (duplicate orders, doubled counters) on every retry."
        ),
        remediation=(
            "Make repeated identical calls leave the state as the first call did, or remove "
            "the idempotent claim. An idempotency key parameter makes the contract explicit."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("no fixtures to observe")
        valid = await outcomes(ctx, "valid")
        tools = {t.name: t for t in ctx.callable_tools() if t.kind in _WRITES}
        first_ok: dict[str, Any] = {}
        for o in valid:
            if o.ok and o.case.tool in tools:
                first_ok.setdefault(o.case.tool, o.case)
        findings: list[Finding] = []
        judged = 0
        for name, case in first_ok.items():
            await fixtures.reset()
            if not (await run_case(ctx, case)).ok:
                continue
            after_first = await fixtures.snapshot()
            second = await run_case(ctx, case)
            if second.failed_hard:
                continue
            diff = fixtures.diff(after_first, await fixtures.snapshot())
            judged += 1
            if not changed_anything(diff):
                continue
            promised, source = contract(ctx, tools[name])
            if promised is False:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH if promised else Severity.INFO,
                    title=(
                        f"Repeating {name} changed state again"
                        if promised
                        else f"{name} is not idempotent and does not say so"
                    ),
                    message=(
                        f"A second identical call to {name} changed {_what(diff)}"
                        + (f", though {source} promises idempotence." if promised else ".")
                    ),
                    tool=name,
                    case_id=f"replay:{slug(name)}",
                    steps=[second.step, second.step],
                    expect={"second_call_changes": "nothing"},
                    observations={
                        "contract": source or "none",
                        "changed": diff.changed[:10],
                        "added": diff.added[:10],
                        "removed": diff.removed[:10],
                        "backend_writes": len(diff.backend_writes),
                    },
                )
            )
        if not judged:
            return CheckOutcome.na("no write tool had a successful baseline call to replay")
        return CheckOutcome(findings)


def _what(diff: Any) -> str:
    parts = []
    for label, items in (
        ("files changed", diff.changed),
        ("files added", diff.added),
        ("files removed", diff.removed),
        ("database tables changed", diff.sqlite_changed),
        ("backend records changed", diff.collections_changed),
        ("backend writes", diff.backend_writes),
    ):
        if items:
            parts.append(f"{len(items)} {label}")
    return ", ".join(parts) or "state"
