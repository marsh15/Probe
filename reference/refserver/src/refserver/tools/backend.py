"""call_backend: read an item from the fakehttp backend with a server-held API token."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Annotated

import httpx
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver import bugs
from refserver.tools import hints

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

TIMEOUT = 10.0
MAX_BODY = 256 * 1024
TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


def trace_headers(meta: dict[str, object] | None) -> dict[str, str]:
    """W3C trace context from request `_meta`, forwarded only when well-formed."""
    meta = meta or {}
    traceparent = meta.get("traceparent")
    if not isinstance(traceparent, str) or not TRACEPARENT_RE.match(traceparent):
        return {}
    headers = {"traceparent": traceparent}
    tracestate = meta.get("tracestate")
    if isinstance(tracestate, str) and len(tracestate) <= 512 and "\n" not in tracestate:
        headers["tracestate"] = tracestate
    return headers


async def fetch_item(
    cfg: Config,
    item_id: int,
    meta: dict[str, object] | None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, object]:
    token = cfg.backend_token
    if not token:
        raise ToolError("call_backend is not configured: the server has no backend token")
    # b44: the trace context is not forwarded.
    forwarded = {} if bugs.is_on("b44") else trace_headers(meta)
    headers = {"Authorization": f"Bearer {token}", **forwarded}
    url = f"{cfg.backend_url}/c/items/{item_id}"
    try:
        async with httpx.AsyncClient(
            transport=transport, timeout=TIMEOUT, follow_redirects=False
        ) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        # Messages are built from fixed text only: exception strings can carry request details.
        raise ToolError(f"backend unreachable ({type(exc).__name__}); try again later") from None
    status = response.status_code
    if bugs.is_on("b36") and status >= 400:
        # the bug: the failed request, credentials and all, goes into the error text
        raise ToolError(f"backend error (HTTP {status}) for GET {url} with headers {headers}")
    if status == 429:
        retry_after = response.headers.get("retry-after", "").strip()
        wait = f"{retry_after} seconds" if retry_after.isdigit() else "a few seconds"
        raise ToolError(f"backend rate limit hit (HTTP 429); retry after {wait}")
    if status == 404:
        raise ToolError(f"item {item_id} not found in the backend")
    if status in (401, 403):
        raise ToolError(
            f"backend refused the server's credentials (HTTP {status}); contact the operator"
        )
    if status >= 400:
        raise ToolError(f"backend error (HTTP {status}); try again later")
    text = response.text[:MAX_BODY].replace(token, "[redacted]")
    try:
        body: object = json.loads(text)
    except ValueError:
        body = text
    return {"item_id": item_id, "status": status, "item": body}


def register(mcp: MCPServer, cfg: Config) -> None:
    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=True, destructive=False, idempotent=True, open_world=True),
    )
    async def call_backend(
        ctx: Context,
        item_id: Annotated[int, Field(ge=1, le=2**31 - 1, description="Backend item id.")],
    ) -> str:
        """Fetch an item from the backend items API (authenticated by the server)."""
        return json.dumps(await fetch_item(cfg, item_id, dict(ctx.request_context.meta or {})))
