"""schema.tool_order_deterministic"""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.normalize_volatile import normalize_volatile
from probe.checks.registry import register
from probe.checks.schema._support import ALL_MODES
from probe.checks.support import close_fresh, list_all_tools, make_finding, open_fresh, request_step
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.util.hashing import canonical_hash
from probe.wire.session import Session

SAME_INSTANCE_LISTINGS = 3


def _describe(first: list[dict[str, Any]], other: list[dict[str, Any]], where: str) -> str | None:
    """How ``other`` differs from ``first`` (None if they match after normalization)."""
    a, b = normalize_volatile(first), normalize_volatile(other)
    if canonical_hash(a) == canonical_hash(b):
        return None
    names_a = [t.get("name") for t in a]
    names_b = [t.get("name") for t in b]
    if sorted(map(str, names_a)) == sorted(map(str, names_b)) and names_a != names_b:
        return f"{where}: same tools in a different order"
    return f"{where}: different tools or definitions"


@register
class ToolOrderDeterministic(Check):
    meta = CheckMeta(
        id="schema.tool_order_deterministic",
        family=Family.SCHEMA,
        title="tools/list returns the same tools in the same order every time",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/server/tools#listing-tools"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A shuffled or changing tool list breaks pagination, caching and prompt caching "
            "for models, and makes the server's behavior hard to reproduce."
        ),
        remediation=(
            "Return tools in a stable order (for example sorted by name) with stable content."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if ctx.listing is None or not ctx.listing.tools:
            return Applicability.no("the server lists no tools")
        return Applicability.yes()

    async def _round(self, ctx: ScanContext, other: Session | None) -> list[str]:
        """Three listings on this instance (and one on ``other``), each against the first."""
        problems: list[str] = []
        base: list[dict[str, Any]] | None = None
        for number in range(1, SAME_INSTANCE_LISTINGS + 1):
            tools = await list_all_tools(ctx, ctx.client)
            if tools is None:
                return [f"listing {number} failed"]
            if base is None:
                base = tools
            elif diff := _describe(base, tools, f"listing {number} on the same instance"):
                problems.append(diff)
        if other is not None and base is not None:
            tools = await list_all_tools(ctx, other)
            if tools is not None and (diff := _describe(base, tools, "a second instance")):
                problems.append(diff)
        return problems

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        other = await open_fresh(ctx, ctx.era.value, "order-check")
        try:
            problems = await self._round(ctx, other)
            if problems:
                # Comparison checks rerun once; only a mismatch that persists counts.
                problems = await self._round(ctx, other)
        finally:
            await close_fresh(other)
        if not problems:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title="tools/list is not deterministic",
                    message="; ".join(problems),
                    case_id="tool-order:repeat",
                    steps=[request_step("tools/list")],
                    expect={"tools/list": "identical order and content on every call"},
                    observations={"problems": problems},
                )
            ]
        )
