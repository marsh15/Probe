"""SSRF-safe URL fetching.

Every hop (the first URL and each redirect) is parsed, its host resolved, and
every resolved address required to be `ipaddress.is_global`. The connection
then goes to the vetted address itself, with the original Host header and
TLS SNI, so a second DNS answer cannot swap in a private address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urljoin, urlsplit

import httpx
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver.tools import hints

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

MAX_REDIRECTS = 3
MAX_BODY = 1024 * 1024
TIMEOUT = 10.0
BLOCKED_HOSTNAMES = frozenset(
    {"localhost", "metadata", "metadata.google.internal", "instance-data", "metadata.azure.com"}
)
_REDIRECTS = {301, 302, 303, 307, 308}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


def _literal_ip(host: str) -> IPAddress | None:
    """Parse IP literals, including legacy numeric forms (2130706433, 0x7f.1, 127.1)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        return None


def _require_global(ip: IPAddress, shown: str) -> IPAddress:
    effective = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
    if not effective.is_global:
        raise ToolError(
            f"blocked: {shown} resolves to non-public address {ip}; "
            "only public http(s) URLs are allowed"
        )
    return effective


class Fetcher:
    def __init__(
        self, resolve: Resolver = system_resolve, transport: httpx.AsyncBaseTransport | None = None
    ):
        self._resolve = resolve
        self._transport = transport

    async def _vet(self, url: str) -> tuple[httpx.URL, dict[str, str], dict[str, str]]:
        """Return (url to connect to, headers, extensions) for one hop, or raise ToolError."""
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ToolError(
                f"unsupported URL scheme {scheme or '(none)'!r}; only http and https are allowed"
            )
        if parts.username or parts.password:
            raise ToolError("URLs with embedded credentials are not allowed")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise ToolError("URL has no host")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            raise ToolError("URL has an invalid port") from None
        if host in BLOCKED_HOSTNAMES or host.endswith((".internal", ".localhost")):
            raise ToolError(f"blocked: host {host!r} is a local or cloud-metadata name")

        literal = _literal_ip(host)
        if literal is not None:
            ip = _require_global(literal, host)
        else:
            try:
                addresses = await self._resolve(host, port)
            except OSError:
                raise ToolError(f"could not resolve host {host!r}") from None
            if not addresses:
                raise ToolError(f"could not resolve host {host!r}")
            vetted = [_require_global(ipaddress.ip_address(a), host) for a in addresses]
            ip = vetted[0]

        target = httpx.URL(url).copy_with(host=str(ip))
        default_port = port == (443 if scheme == "https" else 80)
        headers = {"Host": host if default_port else f"{host}:{port}"}
        extensions = {"sni_hostname": host} if scheme == "https" else {}
        return target, headers, extensions

    async def fetch(self, url: str) -> dict[str, object]:
        async with httpx.AsyncClient(
            transport=self._transport, timeout=TIMEOUT, follow_redirects=False
        ) as client:
            current = url
            for hop in range(MAX_REDIRECTS + 1):
                target, headers, extensions = await self._vet(current)
                request = client.build_request(
                    "GET", target, headers=headers, extensions=extensions
                )
                try:
                    response = await client.send(request, stream=True)
                except httpx.HTTPError as exc:
                    raise ToolError(f"request to {current} failed: {type(exc).__name__}") from None
                try:
                    location = response.headers.get("location")
                    if response.status_code in _REDIRECTS and location:
                        if hop == MAX_REDIRECTS:
                            raise ToolError(f"too many redirects (limit {MAX_REDIRECTS})")
                        current = urljoin(current, location)
                        continue
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BODY:
                            break
                    return {
                        "url": current,
                        "status": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "body": bytes(body[:MAX_BODY]).decode("utf-8", errors="replace"),
                        "truncated": len(body) > MAX_BODY,
                    }
                finally:
                    await response.aclose()
        raise AssertionError("unreachable")


def register(mcp: MCPServer, cfg: Config) -> None:
    fetcher = Fetcher()

    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=True, destructive=False, idempotent=True, open_world=True),
    )
    async def fetch_url(
        url: Annotated[
            str, Field(min_length=1, max_length=2048, description="Public http(s) URL to GET.")
        ],
    ) -> str:
        """Fetch a public http(s) URL (at most 3 redirects, body capped at 1 MiB)."""
        return json.dumps(await fetcher.fetch(url))
