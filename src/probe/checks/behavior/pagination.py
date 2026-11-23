"""behavior.pagination_sound"""

from dataclasses import dataclass
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import campaign, run_case
from probe.checks.behavior._support import ALL_MODES, drop_paging
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step
from probe.engine.budget import BudgetExhausted
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
from probe.schema.cases import Case
from probe.util.hashing import canonical_hash
from probe.wire.jsonrpc import ErrorResponse, ResultResponse

_MAX_PAGES = 100
_TOOL_PAGES = 20
_BOGUS = "probe-bogus"
_INVALID_PARAMS = -32602
_LIST_METHODS = {"tools/list": "tools", "resources/list": "resources"}
_CURSOR_IN = ("cursor", "page_token", "next_cursor", "pageToken")
_CURSOR_OUT = ("nextCursor", "next_cursor", "next_page_token", "nextPageToken")


@dataclass
class Problem:
    what: str
    case_id: str
    detail: str
    step: dict[str, Any]


def _item_key(item: Any) -> str:
    return canonical_hash(item)


async def _walk_list(ctx: ScanContext, method: str, key: str) -> list[Problem]:
    """Follow ``nextCursor`` through a protocol list, then try an invalid cursor."""
    problems: list[Problem] = []
    seen_items: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    paged = False
    try:
        for page in range(_MAX_PAGES):
            exchange = await ctx.exchange(method, {"cursor": cursor} if cursor else None)
            response = exchange.response
            if not isinstance(response, ResultResponse) or not isinstance(response.result, dict):
                return problems  # not listable (e.g. resources not supported): nothing to judge
            items = response.result.get(key)
            if not isinstance(items, list):
                return problems
            repeated = [i for i in items if _item_key(i) in seen_items]
            if repeated:
                problems.append(
                    Problem(
                        "duplicate items across pages",
                        f"{method}:duplicate",
                        f"page {page + 1} repeated {len(repeated)} item(s) from earlier pages",
                        request_step(method, {"cursor": cursor} if cursor else None),
                    )
                )
                return problems
            seen_items.update(_item_key(i) for i in items)
            nxt = response.result.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                break
            paged = True
            if nxt in seen_cursors or nxt == cursor:
                problems.append(
                    Problem(
                        "a cursor repeated (the pages loop)",
                        f"{method}:loop",
                        f"nextCursor {nxt[:40]!r} came back on page {page + 1}",
                        request_step(method, {"cursor": cursor} if cursor else None),
                    )
                )
                return problems
            seen_cursors.add(nxt)
            cursor = nxt
        if paged:
            exchange = await ctx.exchange(method, {"cursor": _BOGUS})
            response = exchange.response
            rejected = (
                isinstance(response, ErrorResponse) and response.error.code == _INVALID_PARAMS
            )
            if not rejected:
                problems.append(
                    Problem(
                        "an invalid cursor was not rejected with -32602",
                        f"{method}:bogus-cursor",
                        "answered " + _describe(response),
                        request_step(method, {"cursor": _BOGUS}),
                    )
                )
    except BudgetExhausted:
        pass
    return problems


def _describe(response: Any) -> str:
    if isinstance(response, ErrorResponse):
        return f"error {response.error.code}"
    return "a result" if response is not None else "nothing"


def _cursor_param(tool: ToolInfo) -> str | None:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return None
    return next((p for p in _CURSOR_IN if p in properties), None)


def _next_cursor(result: dict[str, Any]) -> str | None:
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return None
    value = next((structured[k] for k in _CURSOR_OUT if structured.get(k)), None)
    return value if isinstance(value, str) else None


def _items(result: dict[str, Any]) -> list[Any]:
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return []
    return next((v for v in structured.values() if isinstance(v, list)), [])


async def _walk_tool(ctx: ScanContext, tool: ToolInfo, base: dict[str, Any]) -> list[Problem]:
    param = _cursor_param(tool)
    if param is None:
        return []
    problems: list[Problem] = []
    seen_items: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    paged = False
    try:
        for page in range(_TOOL_PAGES):
            arguments = {**base, **({param: cursor} if cursor else {})}
            outcome = await run_case(ctx, Case(tool.name, "valid", "pagination", page, arguments))
            if not outcome.ok or outcome.result is None:
                return problems
            items = _items(outcome.result)
            if any(_item_key(i) in seen_items for i in items):
                problems.append(
                    Problem(
                        "duplicate items across pages",
                        f"{tool.name}:duplicate",
                        f"page {page + 1} repeated items from earlier pages",
                        outcome.step,
                    )
                )
                return problems
            seen_items.update(_item_key(i) for i in items)
            nxt = _next_cursor(outcome.result)
            if nxt is None:
                break
            paged = True
            if nxt in seen_cursors or nxt == cursor:
                problems.append(
                    Problem(
                        "a cursor repeated (the pages loop)",
                        f"{tool.name}:loop",
                        f"the next cursor came back on page {page + 1}",
                        outcome.step,
                    )
                )
                return problems
            seen_cursors.add(nxt)
            cursor = nxt
        if paged:
            bogus = await run_case(
                ctx, Case(tool.name, "malformed", "bogus-cursor", 0, {**base, param: _BOGUS})
            )
            if bogus.ok:
                problems.append(
                    Problem(
                        "an invalid cursor was accepted",
                        f"{tool.name}:bogus-cursor",
                        "the call with a made-up cursor succeeded",
                        bogus.step,
                    )
                )
    except BudgetExhausted:
        pass
    return problems


@register
class PaginationSound(Check):
    meta = CheckMeta(
        id="behavior.pagination_sound",
        family=Family.BEHAVIOR,
        title="Paged results end, do not repeat, and reject bad cursors",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/server/utilities/pagination"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A client that follows cursors until the list ends loops forever, or shows "
            "duplicates, when the server repeats a cursor or a page."
        ),
        remediation=(
            "Make every cursor advance, never repeat items across pages, end the list by "
            "omitting nextCursor, and answer an unknown cursor with -32602."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        found: list[tuple[str | None, Problem]] = []
        for method, key in _LIST_METHODS.items():
            found += [(None, p) for p in await _walk_list(ctx, method, key)]
        book = await campaign(ctx)
        for plan in book.plans:
            first = next((c.arguments for c in plan.valid if isinstance(c.arguments, dict)), None)
            if first is None or plan.tool.kind != "read":
                continue
            base = drop_paging(first)
            found += [(plan.tool.name, p) for p in await _walk_tool(ctx, plan.tool, base)]
        findings: list[Finding] = [
            make_finding(
                self,
                ctx,
                severity=Severity.MEDIUM,
                title=f"Pagination problem: {problem.what}",
                message=problem.detail,
                tool=tool,
                case_id=f"pagination:{problem.case_id}",
                steps=[problem.step],
                expect={"pagination": "cursors advance, items are unique, bad cursors are refused"},
                observations={"problem": problem.what},
            )
            for tool, problem in found
        ]
        return CheckOutcome(findings)
