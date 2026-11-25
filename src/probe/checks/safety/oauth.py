"""safety.oauth_scopes_minimal

Static: it reads the server's own protected-resource metadata and its 401 challenge. The
authorization server is only asked on the target's origin, or on loopback for a local target.
Probe never contacts a third party on a target's behalf.
"""

import asyncio
import ipaddress
import json
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import ALL_MODES, make_finding, raw_http_step
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)
from probe.wire.errors import RequestTimeout
from probe.wire.transport_http import HttpTransport, RawHttpResult

_BROAD = frozenset({"*", "admin", "all", "full_access"})
_MANY = 20
_PRM_PATH = "/.well-known/oauth-protected-resource"
_AS_PATH = "/.well-known/oauth-authorization-server"
_CHALLENGE_SCOPE = re.compile(r'scope="([^"]*)"')


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


async def _issuer_allowed(issuer: str, target: str) -> bool:
    try:
        parts = urlsplit(issuer)
        target_parts = urlsplit(target)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or "?" in issuer
            or "#" in issuer
        ):
            return False

        def origin(url: str) -> tuple[str, str | None, int]:
            parsed = urlsplit(url)
            return (
                parsed.scheme,
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )

        async def addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
            try:
                return [ipaddress.ip_address(host)]
            except ValueError:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    host, None, type=socket.SOCK_STREAM
                )
                return [ipaddress.ip_address(info[4][0]) for info in infos]

        issuer_ips = await addresses(parts.hostname)
        if not issuer_ips or any(ip.is_link_local for ip in issuer_ips):
            return False
        if origin(issuer) == origin(target):
            return True
        target_ips = await addresses(target_parts.hostname or "")
        return bool(target_ips) and all(ip.is_loopback for ip in [*issuer_ips, *target_ips])
    except (ValueError, OSError):
        return False


def _json(result: RawHttpResult | None) -> dict[str, Any] | None:
    if result is None or result.status != 200:
        return None
    try:
        document = json.loads(result.body)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


@register
class OauthScopesMinimal(Check):
    meta = CheckMeta(
        id="safety.oauth_scopes_minimal",
        family=Family.SAFETY,
        title="OAuth metadata asks for narrow scopes",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"http"}),
        modes=ALL_MODES,
        phase="static",
        spec_refs=["2026-07-28/basic/authorization#scope-selection-strategy", "RFC9728", "RFC9207"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A server that advertises scopes like '*' or 'admin' (or asks for all of them at "
            "once) gets tokens that can do far more than any one tool needs."
        ),
        remediation=(
            "Publish one scope per capability, ask for the smallest set a request needs in the "
            "401 challenge, and avoid wildcard or admin scopes."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not isinstance(ctx.client.transport, HttpTransport):
            return Applicability.no("needs an HTTP target")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        transport = ctx.client.transport
        if not isinstance(transport, HttpTransport):
            return CheckOutcome.na("needs an HTTP target")
        origin = _origin(transport.url)
        try:
            prm = await self._get(ctx, origin + _PRM_PATH)
            if _json(prm) is None:  # the path-suffixed form for an endpoint under a path
                prm = await self._get(ctx, origin + _PRM_PATH + urlsplit(transport.url).path)
            challenge = await ctx.raw_http(
                {"Content-Type": "application/json", "Accept": "application/json"},
                b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            )
        except RequestTimeout:
            return CheckOutcome.error("the server did not answer the metadata requests")
        document = _json(prm)
        challenged = challenge.status == 401 and "www-authenticate" in challenge.headers
        if document is None and not challenged:
            return CheckOutcome.na("the server advertises no OAuth protection")
        findings: list[Finding] = []
        scopes = [str(s) for s in (document or {}).get("scopes_supported") or []]
        broad = sorted(s for s in scopes if s.lower() in _BROAD)
        if broad or len(scopes) > _MANY:
            what = f"broad scopes {broad}" if broad else f"{len(scopes)} scopes"
            findings.append(
                self._finding(ctx, f"The server advertises {what}", "prm", prm, Severity.MEDIUM)
            )
        asked = _CHALLENGE_SCOPE.search(challenge.headers.get("www-authenticate", ""))
        if asked and len(scopes) > 1 and set(asked.group(1).split()) >= set(scopes):
            findings.append(
                self._finding(
                    ctx,
                    "The 401 challenge asks for every supported scope",
                    "challenge",
                    challenge,
                    Severity.MEDIUM,
                )
            )
        findings += await self._authorization_server(ctx, document or {})
        return CheckOutcome(findings)

    async def _get(self, ctx: ScanContext, url: str) -> RawHttpResult:
        return await ctx.raw_http({"Accept": "application/json"}, b"", method="GET", url=url)

    async def _authorization_server(
        self, ctx: ScanContext, document: dict[str, Any]
    ) -> list[Finding]:
        servers = document.get("authorization_servers") or []
        issuer = servers[0] if servers and isinstance(servers[0], str) else None
        if issuer is None:
            return []
        transport = ctx.client.transport
        if not isinstance(transport, HttpTransport) or not await _issuer_allowed(
            issuer, transport.url
        ):
            return [
                self._finding(
                    ctx,
                    "The authorization server is outside the permitted origin, "
                    "so its metadata was not fetched",
                    "as-skipped",
                    None,
                    Severity.INFO,
                )
            ]
        try:
            result = await self._get(ctx, urljoin(issuer, _AS_PATH))
        except RequestTimeout:
            return []
        metadata = _json(result)
        if metadata is None:
            return []
        if metadata.get("authorization_response_iss_parameter_supported") is not True:
            return [
                self._finding(
                    ctx,
                    "The authorization server does not declare RFC 9207 issuer identification",
                    "as-iss",
                    result,
                    Severity.LOW,
                )
            ]
        return []

    def _finding(
        self,
        ctx: ScanContext,
        title: str,
        case: str,
        result: RawHttpResult | None,
        severity: Severity,
    ) -> Finding:
        observed = (
            {"status": result.status, "body": result.body[:600].decode("utf-8", "replace")}
            if result is not None
            else {}
        )
        return make_finding(
            self,
            ctx,
            severity=severity,
            title=title,
            message=title,
            case_id=f"oauth:{case}",
            steps=[raw_http_step({"Accept": "application/json"}, b"", method="GET")],
            expect={"scopes": "narrow"},
            observations=observed,
        )
