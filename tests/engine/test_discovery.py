"""Tool discovery: paging, and bounds against a hostile server."""

from typing import Any

from probe.engine.discovery import list_tools, tool_infos
from probe.wire.jsonrpc import ResultResponse
from probe.wire.session import Exchange


class PagedSession:
    """Just enough of a Session: serves canned tools/list pages (the last has no cursor)."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls = 0

    async def exchange(self, method: str, params: Any = None, **_: Any) -> Exchange:
        page = self.pages[min(self.calls, len(self.pages) - 1)]
        self.calls += 1
        return Exchange(ResultResponse(self.calls, page))


def page(n_tools: int, cursor: str | None = None, pad: int = 0) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tools": [{"name": f"t{i}", "description": "x" * pad} for i in range(n_tools)]
    }
    if cursor:
        result["nextCursor"] = cursor
    return result


async def test_pages_are_followed_until_there_is_no_cursor() -> None:
    session = PagedSession([page(2, "a"), page(2, "b"), page(1)])
    listing = await list_tools(session)  # type: ignore[arg-type]
    assert (len(listing.pages), len(listing.tools), listing.complete) == (3, 5, True)
    assert session.calls == 3


async def test_an_endless_cursor_stops_at_the_page_limit() -> None:
    listing = await list_tools(PagedSession([page(1, "more")]), max_pages=5)  # type: ignore[arg-type]
    assert not listing.complete and len(listing.pages) == 5
    assert "more than 5 pages" in (listing.error or "")


async def test_the_total_size_is_bounded_not_just_each_page() -> None:
    # Each page is modest, but together they pass the cap: the rest must never be kept.
    session = PagedSession([page(1, "next", pad=300_000)])
    listing = await list_tools(session, max_bytes=1_000_000)  # type: ignore[arg-type]
    assert not listing.complete
    assert "larger than Probe will read" in (listing.error or "")
    assert len(listing.pages) == 3  # 3 x ~300 KB fit; the 4th would pass 1 MB
    assert session.calls == 4


async def test_the_number_of_tools_is_bounded() -> None:
    listing = await list_tools(PagedSession([page(60, "next")]), max_tools=100)  # type: ignore[arg-type]
    assert len(listing.tools) == 60 and not listing.complete
    assert "100 tools" in (listing.error or "")


def test_tool_infos_skip_unnamed_tools_and_classify_the_rest() -> None:
    infos = tool_infos(
        [
            {"name": "delete_everything", "inputSchema": {"type": "object"}},
            {"inputSchema": {}},
            {"name": 5},
            {"name": "get_note", "description": "Read a note.", "inputSchema": {"type": "object"}},
        ]
    )
    assert [i.name for i in infos] == ["delete_everything", "get_note"]
    assert infos[0].kind == "destructive"
