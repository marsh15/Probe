"""behavior.stateless_consistent"""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import WRITE_KINDS, campaign
from probe.checks.context import ScanContext
from probe.checks.normalize_volatile import normalize_volatile
from probe.checks.registry import register
from probe.checks.support import (
    close_fresh,
    list_all_tools,
    make_finding,
    open_fresh,
    request_step,
)
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity
from probe.engine.outcomes import Transport as TransportKind
from probe.wire.jsonrpc import ErrorResponse, ResultResponse
from probe.wire.session import Session

_ATTEMPTS = 2  # a difference must show up twice
_CALLS = 2
_IGNORED_DISCOVER = frozenset({"ttlMs", "cacheScope", "_meta", "resultType"})


def _discover_view(result: dict[str, Any] | None) -> Any:
    if result is None:
        return None
    return normalize_volatile({k: v for k, v in result.items() if k not in _IGNORED_DISCOVER})


async def _answer(ctx: ScanContext, session: Session, name: str, arguments: Any) -> Any:
    ctx.spend()
    exchange = await session.exchange("tools/call", {"name": name, "arguments": arguments})
    response = exchange.response
    if isinstance(response, ResultResponse) and isinstance(response.result, dict):
        keep = {k: response.result.get(k) for k in ("content", "structuredContent", "isError")}
        return normalize_volatile(keep)
    if isinstance(response, ErrorResponse):
        return {"error": response.error.code}
    return None


@register
class StatelessConsistent(Check):
    meta = CheckMeta(
        id="behavior.stateless_consistent",
        family=Family.BEHAVIOR,
        title="Two fresh instances of the server answer alike",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools", "second_instance"}),
        modes=frozenset({"standard", "deep"}),
        phase="active.safe",
        spec_refs=["2026-07-28/basic/index", "2026-07-28/server/discover"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "The 2026-07-28 core is stateless: any instance may answer any request. If a fresh "
            "instance describes itself or answers differently, load balancers and restarts "
            "will change what clients see."
        ),
        remediation=(
            "Derive everything a response contains from the request and shared storage, not "
            "from process-local state such as a pid, start time or in-memory cache."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if ctx.client.discover_result is None:
            return Applicability.no("the server was negotiated without server/discover")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        reads = await self._reads(ctx)
        differences: list[str] = []
        for _ in range(_ATTEMPTS):
            ctx.spend(1)  # the fresh instance's negotiation
            fresh = await open_fresh(ctx, "modern", "stateless")
            if fresh is None:
                return CheckOutcome.na("cannot start a second instance")
            try:
                differences = await self._differences(ctx, fresh, reads)
            finally:
                await close_fresh(fresh)
            if not differences:
                return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title="Fresh instances of the server answer differently",
                    message="; ".join(differences),
                    case_id="stateless:instances",
                    steps=[
                        request_step("server/discover"),
                        request_step("tools/list"),
                        *[
                            request_step("tools/call", {"name": n, "arguments": a})
                            for n, a in reads
                        ],
                    ],
                    expect={"answers": "identical on every instance"},
                    observations={"differences": differences},
                )
            ]
        )

    @staticmethod
    async def _reads(ctx: ScanContext) -> list[tuple[str, Any]]:
        """Read calls with a known good answer, taken from the generated valid inputs."""
        book = await campaign(ctx)
        reads: list[tuple[str, Any]] = []
        for plan in book.plans:
            args = next((c.arguments for c in plan.valid if isinstance(c.arguments, dict)), None)
            if plan.tool.kind in WRITE_KINDS or args is None or len(reads) >= _CALLS:
                continue
            first = await ctx.establish_baseline(plan.tool, args)
            if first is not None:
                reads.append((plan.tool.name, args))
        return reads

    async def _differences(
        self, ctx: ScanContext, fresh: Session, reads: list[tuple[str, Any]]
    ) -> list[str]:
        found: list[str] = []
        if _discover_view(ctx.client.discover_result) != _discover_view(fresh.discover_result):
            found.append("server/discover describes the server differently")
        mine = await list_all_tools(ctx, ctx.client)
        theirs = await list_all_tools(ctx, fresh)
        if mine is None or theirs is None:
            return found
        if normalize_volatile(mine) != normalize_volatile(theirs):
            names = sorted(
                str(a.get("name"))
                for a, b in zip(mine, theirs, strict=False)
                if normalize_volatile(a) != normalize_volatile(b)
            )
            changed = f" ({', '.join(names[:5])})" if names else ""
            found.append(f"tools/list differs{changed}")
        for name, arguments in reads:
            if await _answer(ctx, ctx.client, name, arguments) != await _answer(
                ctx, fresh, name, arguments
            ):
                found.append(f"{name} answers differently")
        return found
