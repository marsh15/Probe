"""protocol.discover_implemented"""

from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import (
    ALL_MODES,
    close_fresh,
    make_finding,
    open_fresh,
    request_step,
)
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.wire.jsonrpc import ResultResponse

_CACHE_SCOPES = ("public", "private")


def discover_problems(result: dict[str, Any]) -> list[str]:
    """What is wrong with a ``server/discover`` result, per the 2026-07-28 schema."""
    problems: list[str] = []
    versions = result.get("supportedVersions")
    if not (isinstance(versions, list) and versions and all(isinstance(v, str) for v in versions)):
        problems.append("supportedVersions is missing, empty or not a list of strings")
    if not isinstance(result.get("capabilities"), dict):
        problems.append("capabilities is missing or not an object")
    if "resultType" not in result:
        problems.append("resultType is missing")
    ttl = result.get("ttlMs")
    if not (isinstance(ttl, int) and not isinstance(ttl, bool) and ttl >= 0):
        problems.append("ttlMs is missing or not a non-negative integer")
    if result.get("cacheScope") not in _CACHE_SCOPES:
        problems.append("cacheScope is missing or not 'public' or 'private'")
    return problems


@register
class DiscoverImplemented(Check):
    meta = CheckMeta(
        id="protocol.discover_implemented",
        family=Family.PROTOCOL,
        title="server/discover is implemented and well formed",
        severity=Severity.HIGH,
        # Judges modern behavior, but must also run when Probe negotiated legacy because
        # discover failed: that is the failure it exists to catch.
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/server/discover"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients detect a server's era and supported versions with server/discover. A "
            "modern-capable server without it looks like a legacy server and is driven with "
            "the wrong protocol."
        ),
        remediation=(
            "Implement server/discover and return supportedVersions, capabilities, resultType, "
            "ttlMs and cacheScope."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        if ctx.era is Era.MODERN:
            return self._judge_discover(ctx)
        return await self._confirm_era(ctx)

    def _judge_discover(self, ctx: ScanContext) -> CheckOutcome:
        result = ctx.client.discover_result
        if result is None:
            return CheckOutcome(
                [
                    make_finding(
                        self,
                        ctx,
                        severity=Severity.HIGH,
                        title="server/discover returned no result",
                        message="The server is modern but answered server/discover with an error.",
                        case_id="discover:no-result",
                        steps=[request_step("server/discover")],
                        expect={"result": "DiscoverResult"},
                        observations={"negotiation": [s.outcome for s in ctx.client.negotiation]},
                    )
                ]
            )
        problems = discover_problems(result)
        if not problems:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title="server/discover result is incomplete",
                    message="; ".join(problems),
                    case_id="discover:incomplete",
                    steps=[request_step("server/discover")],
                    expect={"fields": ["supportedVersions", "capabilities", "resultType"]},
                    observations={"problems": problems},
                )
            ]
        )

    async def _confirm_era(self, ctx: ScanContext) -> CheckOutcome:
        """Probe negotiated legacy. On a fresh instance, does a modern request work anyway?"""
        fresh = await open_fresh(ctx, "modern", "era-confirmation")
        if fresh is None:
            return CheckOutcome.na("cannot start a fresh instance to confirm the server's era")
        try:
            ctx.spend()
            outcome = await fresh.exchange("tools/list")
            discover_steps = [f"{s.action}: {s.outcome}" for s in fresh.negotiation]
            discover_works = fresh.discover_result is not None
        finally:
            await close_fresh(fresh)
        response = outcome.response
        modern_capable = (
            isinstance(response, ResultResponse)
            and isinstance(response.result, dict)
            and isinstance(response.result.get("tools"), list)
        )
        if not modern_capable:
            return CheckOutcome.na("the server speaks legacy MCP only")
        if discover_works:
            # Probe was told to use the legacy era (or negotiation failed for another reason);
            # server/discover itself is fine.
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title="modern-capable server does not implement server/discover",
                    message=(
                        "A modern tools/list works on a fresh instance, but server/discover "
                        "failed, so clients negotiate the legacy protocol."
                    ),
                    case_id="discover:missing",
                    steps=[request_step("server/discover"), request_step("tools/list")],
                    expect={"server/discover": "DiscoverResult"},
                    observations={"fresh_instance_negotiation": discover_steps},
                )
            ]
        )
