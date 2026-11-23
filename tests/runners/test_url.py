"""UrlRunner: the permission gate for non-local hosts, and never spawning or restarting."""

import asyncio
import socket
from collections.abc import AsyncIterator

import pytest

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import TargetUnavailable
from probe.runners.url import PermissionRequired, UrlRunner, is_local_or_private
from probe.wire.jsonrpc import Request
from probe.wire.transport_http import HttpTransport
from tests.wire.fake_http import ServerState, serve


@pytest.fixture
async def server() -> AsyncIterator[tuple[str, ServerState]]:
    async with serve() as running:
        yield running


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "sub.localhost",
        "LOCALHOST.",
        "127.0.0.1",
        "127.9.9.9",
        "::1",
        "[::1]",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "fe80::1",
        "fd00::1",
        "100.64.0.1",  # carrier-grade NAT: not global
    ],
)
async def test_local_and_private_addresses_are_recognized(host: str) -> None:
    assert await is_local_or_private(host) is True


@pytest.mark.parametrize("host", ["8.8.8.8", "93.184.216.34", "2606:4700::1111", "1.1.1.1"])
async def test_public_addresses_are_not_local(host: str) -> None:
    assert await is_local_or_private(host) is False


async def test_an_unresolvable_name_is_not_provably_local() -> None:
    assert await is_local_or_private("does-not-exist.invalid") is False


async def test_a_name_resolving_only_to_private_addresses_is_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, 0, 0, "", ("10.0.0.5", 0))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    assert await is_local_or_private("internal.example") is True


async def test_a_name_with_any_public_address_is_not_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, 0, 0, "", ("10.0.0.5", 0)),
            (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    assert await is_local_or_private("mixed.example") is False


@pytest.mark.parametrize("url", ["ftp://localhost/mcp", "localhost:3000/mcp", "http:///mcp", ""])
def test_malformed_urls_are_refused(url: str) -> None:
    with pytest.raises(ValueError, match="http"):
        UrlRunner(url)


def test_declares_what_it_is() -> None:
    runner = UrlRunner("http://127.0.0.1:1/mcp")
    assert runner.transport_kind is TransportKind.HTTP
    assert runner.sandboxed is False


async def test_a_local_target_starts_without_any_permission(
    server: tuple[str, ServerState],
) -> None:
    runner = UrlRunner(server[0] + "/json")
    transport = await runner.start()
    assert isinstance(transport, HttpTransport)
    assert (await transport.request(Request(1, "x").to_obj(), timeout=5)).unwrap() == {"echo": "x"}
    assert runner.permission_reminder is None
    await runner.stop()


async def test_a_remote_target_is_refused_without_permission() -> None:
    runner = UrlRunner("https://8.8.8.8/mcp")
    with pytest.raises(PermissionRequired, match="--i-have-permission"):
        await runner.start()


async def test_permission_allows_a_remote_target_and_leaves_a_reminder() -> None:
    runner = UrlRunner("https://8.8.8.8/mcp", i_have_permission=True)
    transport = await runner.start()
    assert isinstance(transport, HttpTransport)
    assert runner.permission_reminder is not None
    assert "8.8.8.8" in runner.permission_reminder
    await runner.stop()


async def test_second_instance_and_logs_are_unavailable(server: tuple[str, ServerState]) -> None:
    runner = UrlRunner(server[0] + "/json")
    await runner.start()
    assert await runner.second_instance() is None
    assert await runner.logs() == ""
    await runner.stop()


async def test_state_follows_whether_the_server_answers(server: tuple[str, ServerState]) -> None:
    runner = UrlRunner(server[0] + "/json")
    await runner.start()
    assert (await runner.state()).running is True
    await runner.stop()
    dead = UrlRunner("http://127.0.0.1:1/mcp")
    assert (await dead.state()).running is False


async def test_restart_reconnects_to_a_server_that_is_up(server: tuple[str, ServerState]) -> None:
    runner = UrlRunner(server[0] + "/json", restart_wait_s=2)
    first = await runner.start()
    second = await runner.restart()
    assert second is not first
    assert not first.alive()
    assert (await second.request(Request(1, "x").to_obj(), timeout=5)).unwrap() == {"echo": "x"}
    await runner.stop()


async def test_restart_gives_up_when_nothing_answers() -> None:
    runner = UrlRunner("http://127.0.0.1:1/mcp", restart_wait_s=0.3)
    with pytest.raises(TargetUnavailable, match="cannot restart"):
        await runner.restart()


async def test_default_headers_are_sent(server: tuple[str, ServerState]) -> None:
    runner = UrlRunner(server[0] + "/json", headers={"Authorization": "Bearer t0ken"})
    transport = await runner.start()
    await transport.request(Request(1, "x").to_obj(), timeout=5)
    assert server[1].seen[0]["headers"]["authorization"] == "Bearer t0ken"
    await runner.stop()
