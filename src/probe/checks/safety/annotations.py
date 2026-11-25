"""safety.annotations_truthful, safety.destructive_annotated"""

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import campaign, changed_anything, run_case
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.classify.tools import heuristic_kind
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetUnstable
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)

_MAX_FINDINGS = 10
_CASES_PER_KIND = 2


def _says_read_only(annotations: dict[str, object]) -> bool:
    return annotations.get("readOnlyHint") is True


@register
class AnnotationsTruthful(Check):
    meta = CheckMeta(
        id="safety.annotations_truthful",
        family=Family.SAFETY,
        title="Tools marked read-only change nothing",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"fixtures", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/server/tools#annotations"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "Clients let tools marked read-only run without asking. A tool that claims it only "
            "reads but writes or deletes turns that trust into data loss."
        ),
        remediation=(
            "Remove readOnlyHint from any tool that can change state, and set destructiveHint "
            "for tools that delete or overwrite."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(_says_read_only(t.annotations) for t in ctx.callable_tools()):
            return Applicability.no("no tool is annotated readOnlyHint")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        judged = False
        try:
            book = await campaign(ctx)
            for plan in book.plans:
                if not _says_read_only(plan.tool.annotations):
                    continue
                cases = [
                    case
                    for kind in ("valid", "boundary", "malformed")
                    for case in plan.cases(kind)[:_CASES_PER_KIND]
                ]
                await fixtures.reset()
                for case in cases:
                    outcome = await run_case(ctx, case, watch_state=True)
                    if outcome.failed_hard or outcome.diff is None:
                        continue
                    judged = True
                    if not changed_anything(outcome.diff):
                        continue
                    diff = outcome.diff
                    findings.append(
                        make_finding(
                            self,
                            ctx,
                            severity=Severity.HIGH,
                            title=f"{plan.tool.name} is marked read-only but changed state",
                            message=f"A call to {plan.tool.name} changed data although it is "
                            "annotated readOnlyHint: true.",
                            case_id=f"read-only:{slug(plan.tool.name)}",
                            steps=[outcome.step],
                            expect={"state_changed": False},
                            observations={
                                "case": case.id,
                                "changed": [*diff.changed, *diff.added, *diff.removed][:8],
                                "sqlite_changed": diff.sqlite_changed[:4],
                                "backend_writes": len(diff.backend_writes),
                            },
                            tool=plan.tool.name,
                        )
                    )
                    await fixtures.reset()
                    break  # one demonstration per tool is enough
                if len(findings) >= _MAX_FINDINGS:
                    break
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("annotation campaign interrupted before a verdict")
        if not judged and not findings:
            return CheckOutcome.na("no read-only tool could be called and observed")
        return CheckOutcome(findings)


@register
class DestructiveAnnotated(Check):
    meta = CheckMeta(
        id="safety.destructive_annotated",
        family=Family.SAFETY,
        title="Tools that sound destructive say so in their annotations",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="static",
        spec_refs=["2026-07-28/server/tools#annotations"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients ask the user before running a tool marked destructive. A tool that deletes "
            "or runs commands but says it is read-only or not destructive skips that question."
        ),
        remediation=(
            "Set destructiveHint: true (and readOnlyHint: false) on tools that delete, overwrite "
            "or execute, or leave the hints out so the spec default applies."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        for tool in ctx.tools:
            if tool.classification_source == "profile":
                continue  # the profile's author has said what this tool is
            guess, reason = heuristic_kind(tool.name, tool.description)
            if guess not in ("destructive", "exec"):
                continue
            hints = tool.annotations
            # A tool that says nothing gets the spec default (destructiveHint true), which makes
            # clients ask first; only an explicit claim to the contrary is wrong.
            if hints.get("readOnlyHint") is True:
                said = "marks it read-only"
            elif hints.get("destructiveHint") is False:
                said = "sets destructiveHint to false"
            else:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title=f"{tool.name} sounds {guess} but {said}",
                    message=f"{tool.name} looks {guess} ({reason}) and its annotations {said}.",
                    case_id=f"destructive-annotated:{slug(tool.name)}",
                    steps=[request_step("tools/list")],
                    expect={"annotations.destructiveHint": True},
                    observations={"heuristic": guess, "annotations": tool.annotations},
                    tool=tool.name,
                )
            )
        return CheckOutcome(findings[:_MAX_FINDINGS])
