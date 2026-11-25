"""Bearer-token identities for HTTP mode (REFSERVER_TOKENS="alice:<tok>,bob:<tok>").

Identities see different tool sets: bob lacks purge_notes. Because tools/list
then depends on who asks, it is served with cacheScope "private".
"""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.types import CallToolResult, ListToolsResult, TextContent
from starlette.requests import Request
from starlette.responses import JSONResponse

from refserver import bugs

SCOPES = ["notes:read", "notes:write"]
HIDDEN_TOOLS: dict[str, frozenset[str]] = {"bob": frozenset({"purge_notes"})}
PRM_PATH = "/.well-known/oauth-protected-resource"


class StaticTokenVerifier:
    """Maps configured bearer tokens to identities (compared in constant time)."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = dict(tokens)

    async def verify_token(self, token: str) -> AccessToken | None:
        for known, identity in self._tokens.items():
            if hmac.compare_digest(known.encode(), token.encode()):
                return AccessToken(
                    token=token, client_id=identity, subject=identity, scopes=list(SCOPES)
                )
        return None


def current_identity() -> str | None:
    token = get_access_token()
    return token.subject if token else None


def hidden_for(identity: str | None) -> frozenset[str]:
    return HIDDEN_TOOLS.get(identity or "", frozenset())


async def identity_tool_filter(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    """Server middleware: hide per-identity tools from tools/list and refuse calls to them."""
    hidden = hidden_for(current_identity())
    if not hidden or ctx.method not in ("tools/list", "tools/call"):
        return await call_next(ctx)
    if ctx.method == "tools/call":
        name = (ctx.params or {}).get("name")
        # A name that is not a string cannot be hidden; the SDK rejects it with -32602.
        if isinstance(name, str) and name in hidden:
            # Same answer the SDK gives for a tool that does not exist.
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")], is_error=True
            )
        return await call_next(ctx)
    result = await call_next(ctx)
    if isinstance(result, ListToolsResult):
        return result.model_copy(
            update={"tools": [t for t in result.tools if t.name not in hidden]}
        )
    if isinstance(result, dict):
        return {
            **result,
            "tools": [t for t in result.get("tools", []) if t.get("name") not in hidden],
        }
    return result


def prm_document(resource: str, issuer: str) -> dict[str, Any]:
    return {
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": ["*", "admin"] if bugs.is_on("b43") else list(SCOPES),
        "bearer_methods_supported": ["header"],
    }


def prm_endpoint(
    issuer: str, mcp_path: str = "/mcp"
) -> Callable[[Request], Awaitable[JSONResponse]]:
    async def endpoint(request: Request) -> JSONResponse:
        resource = str(request.base_url).rstrip("/") + mcp_path
        return JSONResponse(prm_document(resource, issuer))

    return endpoint
