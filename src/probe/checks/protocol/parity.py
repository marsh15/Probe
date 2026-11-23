"""protocol.era_parity"""

from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import (
    close_fresh,
    list_all_tools,
    make_finding,
    open_fresh,
    request_step,
)
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.util.hashing import canonical_hash
from probe.wire.session import NegotiationFailed, Session


def tool_fingerprints(tools: list[dict[str, Any]]) -> dict[str, str]:
    """Name -> hash of the parts of a tool definition that must not depend on the era."""
    return {
        str(t.get("name")): canonical_hash([t.get("inputSchema"), t.get("outputSchema")])
        for t in tools
    }


@register
class EraParity(Check):
    meta = CheckMeta(
        id="protocol.era_parity",
        family=Family.PROTOCOL,
        title="A dual-era server offers the same tools in both eras",
        severity=Severity.LOW,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset({"second_instance"}),
        modes=frozenset({"deep"}),
        phase="active.safe",
        spec_refs=[
            "2026-07-28/basic/versioning#backward-compatibility-with-initialization-based-versions"
        ],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A server that answers both eras should be one server. If a client's era changes "
            "which tools or schemas it sees, behavior depends on how the client connected."
        ),
        remediation="Serve the same tool names and schemas to modern and legacy clients.",
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        ctx.spend(2)  # the two negotiations
        modern = await open_fresh(ctx, "modern", "parity-modern")
        legacy: Session | None = None
        try:
            try:
                legacy = await open_fresh(ctx, "legacy", "parity-legacy")
            except NegotiationFailed:
                # Not a dual-era server. (Its discover result may not list legacy versions even
                # when it speaks them, so the handshake itself is the test.)
                return CheckOutcome.na("the server does not complete a legacy handshake")
            if modern is None or legacy is None:
                return CheckOutcome.na("cannot start fresh instances")
            modern_tools = await list_all_tools(ctx, modern)
            legacy_tools = await list_all_tools(ctx, legacy)
        finally:
            await close_fresh(modern)
            await close_fresh(legacy)
        if modern_tools is None or legacy_tools is None:
            era = "modern" if modern_tools is None else "legacy"
            return CheckOutcome.na(f"tools/list did not succeed in the {era} era")
        a, b = tool_fingerprints(modern_tools), tool_fingerprints(legacy_tools)
        if a == b:
            return CheckOutcome()
        only_modern = sorted(set(a) - set(b))
        only_legacy = sorted(set(b) - set(a))
        changed = sorted(n for n in set(a) & set(b) if a[n] != b[n])
        parts = []
        if only_modern:
            parts.append(f"only in modern: {only_modern}")
        if only_legacy:
            parts.append(f"only in legacy: {only_legacy}")
        if changed:
            parts.append(f"schemas differ: {changed}")
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title="Tools differ between the modern and legacy era",
                    message="; ".join(parts),
                    case_id="era-parity:tools",
                    steps=[request_step("tools/list")],
                    expect={"tool_set": "identical in both eras"},
                    observations={
                        "only_modern": only_modern,
                        "only_legacy": only_legacy,
                        "schemas_differ": changed,
                    },
                )
            ]
        )
