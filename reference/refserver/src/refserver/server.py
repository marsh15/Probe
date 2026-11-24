"""Builds the reference MCPServer and its HTTP app.

Era handling is entirely the SDK's: one server answers both `server/discover`
(2026-07-28) and the legacy `initialize` handshake, on stdio and HTTP.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from typing import TYPE_CHECKING

from mcp.server.auth.settings import AuthSettings
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import InvalidRequestState, MCPServer, RequestStateSecurity
from mcp.server.transport_security import TransportSecuritySettings

from refserver import auth, behavior_bugs, bugs, wire_bugs
from refserver.tools import register_all

if TYPE_CHECKING:
    from starlette.types import ASGIApp

    from refserver.config import Config

NAME = "refserver"
VERSION = "0.1.0"
INSTRUCTIONS = "Reference notes server used to validate Probe. Tools operate on a seeded sandbox."
# Short enough that a changed tool set is picked up quickly, long enough to be cacheable.
LIST_TTL_MS = 60_000
_TOKEN_PREFIX = "rs1."


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


class HMACRequestStateCodec:
    """Sign-only requestState codec (HMAC-SHA256); the SDK boundary adds expiry and request binding.

    Token: "rs1." + b64(payload) + "." + b64(tag), with the prefix under the tag.
    """

    def __init__(self, secret: bytes) -> None:
        self._key = hmac.new(secret, b"refserver/request-state/v1", hashlib.sha256).digest()

    def _tag(self, payload: bytes) -> bytes:
        return hmac.new(self._key, _TOKEN_PREFIX.encode() + payload, hashlib.sha256).digest()

    def seal(self, payload: bytes) -> str:
        return f"{_TOKEN_PREFIX}{_b64(payload)}.{_b64(self._tag(payload))}"

    def unseal(self, token: str) -> bytes:
        if not token.startswith(_TOKEN_PREFIX):
            raise InvalidRequestState("format")
        try:
            payload_part, tag_part = token[len(_TOKEN_PREFIX) :].split(".")
            payload, tag = _unb64(payload_part), _unb64(tag_part)
        except (ValueError, binascii.Error):
            raise InvalidRequestState("format") from None
        # b41: the signature is read but never checked
        if not bugs.is_on("b41") and not hmac.compare_digest(tag, self._tag(payload)):
            raise InvalidRequestState("signature")
        return payload


def build_server(cfg: Config) -> MCPServer:
    bugs.active()  # fail fast on a bad PROBE_REF_BUGS
    authed = bool(cfg.tokens)
    mcp = MCPServer(
        NAME,
        version=VERSION,
        instructions=INSTRUCTIONS,
        token_verifier=auth.StaticTokenVerifier(cfg.tokens) if authed else None,
        # resource_server_url=None: the PRM document is served by our own route (see http_app).
        auth=AuthSettings(issuer_url=cfg.issuer_url, resource_server_url=None) if authed else None,
        request_state_security=RequestStateSecurity(codec=HMACRequestStateCodec(cfg.secret)),
        cache_hints={
            # b14: a list that differs per identity is marked public.
            "tools/list": CacheHint(
                ttl_ms=LIST_TTL_MS,
                scope="private" if authed and not bugs.is_on("b14") else "public",
            ),
            "server/discover": CacheHint(ttl_ms=LIST_TTL_MS, scope="public"),
        },
        middleware=[behavior_bugs.make(cfg), *([auth.identity_tool_filter] if authed else [])],
    )
    register_all(mcp, cfg)
    if authed:
        endpoint = auth.prm_endpoint(cfg.issuer_url)
        for path in (auth.PRM_PATH, auth.PRM_PATH + "/mcp"):
            mcp.custom_route(path, methods=["GET"])(endpoint)
    return mcp


def _allowed_hosts() -> list[str]:
    extra = [
        h.strip() for h in os.environ.get("REFSERVER_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]
    return ["127.0.0.1:*", "localhost:*", "[::1]:*", *extra]


def http_app(mcp: MCPServer) -> ASGIApp:
    hosts = _allowed_hosts()
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=[f"http://{h}" for h in hosts] + [f"https://{h}" for h in hosts],
    )
    app = mcp.streamable_http_app(streamable_http_path="/mcp", transport_security=security)
    return wire_bugs.WireBugMiddleware(app)
