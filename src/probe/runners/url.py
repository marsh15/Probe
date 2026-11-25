"""Test a server that is already running at a URL. Probe never spawns, restarts or stops it.

Because Probe sends adversarial traffic, it refuses any host that is not local or private unless
the operator states they have permission to test it. The check resolves the name once, at
start; it is a guard against pointing Probe at the wrong target, not a defense against a name
that later resolves elsewhere.
"""

import asyncio
import ipaddress
import socket
import time
from collections.abc import Mapping
from urllib.parse import urlsplit

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import RunnerState, TargetUnavailable
from probe.wire.recorder import Recorder
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpTransport

CONNECT_TIMEOUT_S = 2.0
DEFAULT_RESTART_WAIT_S = 10.0


class PermissionRequired(Exception):
    """The URL is not a local or private address and no permission was asserted."""


def _non_global(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    private = (
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") if ip.version == 4 else ("fc00::/7",)
    )
    return (
        ip.is_loopback
        or ip.is_link_local
        or any(ip in ipaddress.ip_network(network) for network in private)
    )


async def is_local_or_private(host: str) -> bool:
    """True if ``host`` is, or resolves only to, loopback, private or link-local addresses."""
    host = host.strip("[]").rstrip(".").lower()
    if host == "localhost":
        return True
    try:
        return _non_global(host)
    except ValueError:
        pass  # a name, not an address literal
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False  # cannot prove it is local
    addresses = {str(info[4][0]) for info in infos}
    return bool(addresses) and all(_non_global(a) for a in addresses)


class UrlRunner:
    transport_kind = TransportKind.HTTP
    sandboxed = False

    def __init__(
        self,
        url: str,
        *,
        i_have_permission: bool = False,
        headers: Mapping[str, str] | None = None,
        recorder: Recorder | None = None,
        restart_wait_s: float = DEFAULT_RESTART_WAIT_S,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("a target URL must be http:// or https:// with a host")
        self.url = url
        self._host = parts.hostname
        self._port = parts.port or (443 if parts.scheme == "https" else 80)
        self._permission = i_have_permission
        self._headers = dict(headers or {})
        self._recorder = recorder
        self._restart_wait_s = restart_wait_s
        self._transport: HttpTransport | None = None
        # Shown to the operator when they used the flag on a non-local target.
        self.permission_reminder: str | None = None

    async def start(self) -> Transport:
        if not await is_local_or_private(self._host):
            if not self._permission:
                raise PermissionRequired(
                    f"{self._host} is not a local or private address. Probe sends adversarial "
                    "requests; only test servers you own or have written permission to test. "
                    "Pass --i-have-permission to proceed."
                )
            self.permission_reminder = (
                f"You asserted permission to test {self._host}. Probe will send malformed, "
                "oversized and hostile requests to it."
            )
        self._transport = self._new_transport()
        return self._transport

    async def restart(self) -> Transport:
        """Probe cannot restart a remote server; reconnect if it is (back) up, else give up."""
        await self._close()
        deadline = time.monotonic() + self._restart_wait_s
        while not await self._reachable():
            if time.monotonic() >= deadline:
                raise TargetUnavailable(f"{self.url} is not reachable and Probe cannot restart it")
            await asyncio.sleep(min(0.25, self._restart_wait_s))
        self._transport = self._new_transport()
        return self._transport

    async def second_instance(self) -> Transport | None:
        return None

    async def logs(self) -> str:
        return ""

    async def state(self) -> RunnerState:
        return RunnerState(running=await self._reachable())

    async def stop(self) -> None:
        await self._close()

    def _new_transport(self) -> HttpTransport:
        return HttpTransport(self.url, headers=self._headers, recorder=self._recorder)

    async def _close(self) -> None:
        if self._transport is not None:
            await self._transport.close()
            self._transport = None

    async def _reachable(self) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), CONNECT_TIMEOUT_S
            )
        except (OSError, TimeoutError):
            return False
        writer.close()
        return True
