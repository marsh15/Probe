"""schema.cache_scope_correct: a list marked public must be the same for everyone."""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.schema._support import ALL_MODES
from probe.checks.support import close_fresh, make_finding, open_fresh, request_step
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)
from probe.util.hashing import canonical_hash
from probe.wire.jsonrpc import ResultResponse
from probe.wire.session import Session

# method -> the result field holding the items
LISTS = {"tools/list": "tools", "resources/list": "resources"}
_MAX_PAGES = 20


class _View:
    """What one identity was shown for one list method."""

    def __init__(self, scope: object, items: list[Any]) -> None:
        self.scope = scope
        self.items = items
        self.digest = canonical_hash(items)


async def _view(ctx: ScanContext, session: Session, method: str, key: str) -> _View | None:
    """Every item of ``method`` as this identity sees it, or None if it cannot list them."""
    items: list[Any] = []
    scope: object = None
    cursor: str | None = None
    for page in range(_MAX_PAGES):
        ctx.spend()
        outcome = await session.exchange(method, {"cursor": cursor} if cursor else None)
        response = outcome.response
        if not isinstance(response, ResultResponse) or not isinstance(response.result, dict):
            return None
        result = response.result
        if not isinstance(result.get(key), list):
            return None
        items += result[key]
        if page == 0:
            scope = result.get("cacheScope")
        elif result.get("cacheScope") == "public":
            scope = "public"
        cursor = result.get("nextCursor")
        if not isinstance(cursor, str) or not cursor:
            break
    # Order is the server's business (another check judges it); only content may differ here.
    items.sort(key=canonical_hash)
    return _View(scope, items)


@register
class CacheScopeCorrect(Check):
    meta = CheckMeta(
        id="schema.cache_scope_correct",
        family=Family.SCHEMA,
        title="Lists that differ between users are not marked public",
        severity=Severity.HIGH,
        eras=frozenset({Era.MODERN}),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"auth_identities"}),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/schema#cacheableresult"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            'cacheScope "public" lets a shared cache or gateway store a result once and serve '
            "it to everybody. If the list depends on who asks, one user's tools or resources "
            "are shown to another."
        ),
        remediation=(
            "Mark any list that depends on the caller's identity or permissions with cacheScope "
            '"private".'
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if len(ctx.auth_identities) < 2:
            return Applicability.no("needs at least two auth identities in the profile")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        tokens = {i.name: i.token for i in ctx.profile.auth.identities}
        views: dict[str, dict[str, _View | None]] = {}
        for name in ctx.auth_identities:
            session = await open_fresh(
                ctx,
                ctx.client.era,
                f"identity:{name}",
                headers={"Authorization": f"Bearer {tokens[name]}"},
            )
            if session is None:
                return CheckOutcome.na("cannot open a connection as another identity")
            try:
                views[name] = {m: await _view(ctx, session, m, k) for m, k in LISTS.items()}
            finally:
                await close_fresh(session)
        if all(v is None for per in views.values() for v in per.values()):
            return CheckOutcome.error("no identity could list tools or resources")
        findings: list[Finding] = []
        for method in LISTS:
            seen = {n: v for n, per in views.items() if (v := per[method]) is not None}
            if len(seen) < 2 or len({v.digest for v in seen.values()}) == 1:
                continue
            public = sorted(n for n, v in seen.items() if v.scope == "public")
            if not public:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title=f"{method} differs between users but is marked public",
                    message=(
                        f"{method} returned different content to {', '.join(sorted(seen))} "
                        f'while cacheScope was "public" for {", ".join(public)}.'
                    ),
                    case_id=f"cache-scope:{method}",
                    steps=[request_step(method)],
                    expect={"cacheScope": "private when the list depends on the caller"},
                    observations={
                        "identities": {
                            n: {"cacheScope": v.scope, "count": len(v.items), "digest": v.digest}
                            for n, v in sorted(seen.items())
                        }
                    },
                )
            )
        return CheckOutcome(findings)
