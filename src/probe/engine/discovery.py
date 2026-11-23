"""Find out what the target offers: every page of ``tools/list``, bounded.

Checks read the raw pages (to validate them against the spec) and the flattened tool list.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from probe.classify.tools import classify_tool
from probe.engine.outcomes import ToolInfo
from probe.wire.jsonrpc import ResultResponse, encode
from probe.wire.session import Session

MAX_PAGES = 100
# A hostile server must not make discovery hold gigabytes: bound what is kept in total, on top of
# the per-message limit of the wire layer.
MAX_LISTING_BYTES = 32 * 1024 * 1024
MAX_LISTED_TOOLS = 5_000


@dataclass(frozen=True, slots=True)
class ToolListing:
    pages: list[dict[str, Any]] = field(default_factory=list)  # the raw ``result`` of each page
    tools: list[dict[str, Any]] = field(default_factory=list)  # raw tool objects, in order
    complete: bool = True  # False if listing stopped early (error, timeout, page limit)
    error: str | None = None


async def list_tools(
    session: Session,
    *,
    max_pages: int = MAX_PAGES,
    max_bytes: int = MAX_LISTING_BYTES,
    max_tools: int = MAX_LISTED_TOOLS,
    timeout: float | None = None,  # noqa: ASYNC109 - the per-request deadline
) -> ToolListing:
    """Read ``tools/list`` page by page until there is no cursor, an error, or a limit is hit."""
    pages: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    kept_bytes = 0
    for _ in range(max_pages):
        outcome = await session.exchange(
            "tools/list", {"cursor": cursor} if cursor else None, timeout=timeout
        )
        response = outcome.response
        if not isinstance(response, ResultResponse) or not isinstance(response.result, dict):
            reason = "timed out" if outcome.timed_out else "no result"
            return ToolListing(pages, tools, complete=False, error=f"tools/list: {reason}")
        page_tools = response.result.get("tools")
        added = (
            [t for t in page_tools if isinstance(t, dict)] if isinstance(page_tools, list) else []
        )
        kept_bytes += len(encode(response.result))
        if kept_bytes > max_bytes or len(tools) + len(added) > max_tools:
            # Stop before keeping this page: the listing is incomplete, and says so.
            limit = f"{max_tools} tools or {max_bytes // (1024 * 1024)} MiB"
            error = f"tools/list is larger than Probe will read ({limit})"
            return ToolListing(pages, tools, complete=False, error=error)
        pages.append(response.result)
        tools += added
        cursor = response.result.get("nextCursor")
        if not isinstance(cursor, str) or not cursor:
            return ToolListing(pages, tools)
    return ToolListing(pages, tools, complete=False, error=f"more than {max_pages} pages")


def tool_infos(
    raw_tools: list[dict[str, Any]], profile: Mapping[str, Any] | None = None
) -> list[ToolInfo]:
    """Classify each raw tool (kind, flags, parameter roles). Tools without a usable name are
    skipped here; the schema checks still see them through the raw listing."""
    infos: list[ToolInfo] = []
    for raw in raw_tools:
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            continue
        schema, output = raw.get("inputSchema"), raw.get("outputSchema")
        annotations = raw.get("annotations")
        infos.append(
            classify_tool(
                name,
                dict(schema) if isinstance(schema, Mapping) else {},
                title=raw["title"] if isinstance(raw.get("title"), str) else None,
                description=raw["description"] if isinstance(raw.get("description"), str) else None,
                output_schema=dict(output) if isinstance(output, Mapping) else None,
                annotations=annotations if isinstance(annotations, Mapping) else None,
                profile=profile,
            )
        )
    return infos
