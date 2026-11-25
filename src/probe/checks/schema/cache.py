"""Schema checks on the caching fields of modern list results."""

import sys
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import main_messages, response_methods
from probe.checks.registry import register
from probe.checks.schema._support import ALL_MODES
from probe.checks.support import make_finding, request_step
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport

MAX_SANE_TTL_MS = 86_400_000  # 24 hours
CACHEABLE_METHODS = frozenset(
    {
        "server/discover",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
    }
)
_SCOPES = ("public", "private")


def cache_problems(result: dict[str, Any]) -> list[str]:
    problems = []
    ttl = result.get("ttlMs")
    if isinstance(ttl, bool) or not isinstance(ttl, int | float):
        problems.append("ttlMs is missing or not a number")
    elif ttl < 0:
        problems.append("ttlMs is negative")
    if result.get("cacheScope") not in _SCOPES:
        problems.append("cacheScope is missing or not 'public' or 'private'")
    return problems


@register
class CacheFieldsPresent(Check):
    meta = CheckMeta(
        id="schema.cache_fields_present",
        family=Family.SCHEMA,
        title="Cacheable results carry ttlMs and cacheScope",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["2026-07-28/schema#cacheableresult"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients and gateways decide how long to reuse a list and whether to share it "
            "between users from ttlMs and cacheScope. Without them they guess, and may serve "
            "one user's list to another."
        ),
        remediation=(
            "Add ttlMs (a non-negative number) and cacheScope (public or private) to list, "
            "read and discover results."
        ),
    )

    def _cacheable_results(self, ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
        methods = response_methods(ctx)
        found: list[tuple[str, dict[str, Any]]] = []
        for record, body in main_messages(ctx, "s2c"):
            if not isinstance(body.get("result"), dict):
                continue
            method = methods.get(record["seq"])
            if method in CACHEABLE_METHODS:
                found.append((method, body["result"]))
        return found

    def applicable(self, ctx: ScanContext) -> Applicability:
        if ctx.trace is None:
            return Applicability.no("no trace was recorded")
        if not self._cacheable_results(ctx):
            return Applicability.no("no cacheable results were recorded")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        by_method: dict[str, set[str]] = {}
        for method, result in self._cacheable_results(ctx):
            for problem in cache_problems(result):
                by_method.setdefault(method, set()).add(problem)
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title=f"{method} result lacks valid cache fields",
                    message="; ".join(sorted(problems)),
                    case_id=f"cache-fields:{method}",
                    steps=[request_step(method)],
                    expect={"ttlMs": "number >= 0", "cacheScope": list(_SCOPES)},
                    observations={"problems": sorted(problems)},
                )
                for method, problems in sorted(by_method.items())
            ]
        )


def _ttl_text(ttl: int | float) -> str:
    return str(ttl) if ttl > sys.float_info.max else f"{ttl:g}"


def _ttl_hours(ttl: int | float) -> str:
    # Integer division avoids overflowing a float on hostile JSON integers.
    if isinstance(ttl, int) and ttl > sys.float_info.max:
        return str(ttl // 3_600_000)
    return f"{ttl / 3_600_000:.0f}"


@register
class CacheTtlSane(Check):
    meta = CheckMeta(
        id="schema.cache_ttl_sane",
        family=Family.SCHEMA,
        title="Cache lifetimes are not absurdly long",
        severity=Severity.LOW,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="static",
        spec_refs=["2026-07-28/schema#cacheableresult"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A list cached for longer than a day will outlive the tools it describes, so "
            "clients keep calling tools that changed or are gone."
        ),
        remediation="Use a ttlMs of at most 24 hours (86400000) for list results.",
    )

    def _ttls(self, ctx: ScanContext) -> list[tuple[str, int | None, int | float]]:
        """(method, page index of a paged list or None, ttlMs) for each result with a ttlMs."""
        results: list[tuple[str, int | None, dict[str, Any]]] = []
        if ctx.client.discover_result is not None:
            results.append(("server/discover", None, ctx.client.discover_result))
        if ctx.listing is not None:
            results += [("tools/list", i, page) for i, page in enumerate(ctx.listing.pages)]
        return [
            (method, page, r["ttlMs"])
            for method, page, r in results
            if isinstance(r.get("ttlMs"), int | float) and not isinstance(r["ttlMs"], bool)
        ]

    def applicable(self, ctx: ScanContext) -> Applicability:
        return Applicability.yes() if self._ttls(ctx) else Applicability.no("no ttlMs to judge")

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        # One finding per (method, ttl), at the first page that has it. The page is part of the
        # case id so that pages with different TTLs get different finding ids.
        groups: dict[tuple[str, int | float], list[int | None]] = {}
        for method, page, ttl in self._ttls(ctx):
            if ttl > MAX_SANE_TTL_MS:
                groups.setdefault((method, ttl), []).append(page)
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title=f"{method} ttlMs is {_ttl_text(ttl)} ms",
                    message=(
                        f"{method} may be cached for {_ttl_hours(ttl)} hours; the sane limit is 24."
                    ),
                    case_id=f"cache-ttl:{method}"
                    + ("" if pages[0] is None else f":page-{pages[0]}"),
                    steps=[request_step(method)],
                    expect={"ttlMs": f"<= {MAX_SANE_TTL_MS}"},
                    observations={"ttlMs": ttl} | ({} if pages[0] is None else {"pages": pages}),
                )
                for (method, ttl), pages in sorted(
                    groups.items(), key=lambda item: (item[0][0], item[1][0] or 0)
                )
            ]
        )
