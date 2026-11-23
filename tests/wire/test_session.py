"""Era negotiation and request building, against scripted servers over stdio-like and HTTP."""

import asyncio
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from probe import __version__
from probe.wire.errors import ProtocolViolation, TransportClosed
from probe.wire.jsonrpc import ErrorResponse, Request
from probe.wire.session import (
    NegotiationFailed,
    NoCommonVersion,
    Session,
)
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpRequestFailed, HttpTransport
from tests.wire.fake_eras import PV, EraServer, Reply, ScriptedTransport, error
from tests.wire.fake_http import serve

Connect = Callable[[EraServer], Awaitable[Transport]]
FAST = {"probe_timeout": 0.3, "request_timeout": 5}
TRACEPARENT = re.compile(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01")


@pytest.fixture(params=["stdio", "http"])
async def connect(request: pytest.FixtureRequest) -> AsyncIterator[Connect]:
    opened: list[Transport] = []
    async with serve() as (base, state):

        async def _connect(server: EraServer) -> Transport:
            transport: Transport
            if request.param == "stdio":
                transport = ScriptedTransport(server)
            else:
                state.script = server
                transport = HttpTransport(base + "/mcp")
            opened.append(transport)
            return transport

        yield _connect
        for transport in opened:
            await transport.close()


@pytest.fixture
async def connect_http() -> AsyncIterator[Connect]:
    opened: list[Transport] = []
    async with serve() as (base, state):

        async def _connect(server: EraServer) -> Transport:
            state.script = server
            transport = HttpTransport(base + "/mcp")
            opened.append(transport)
            return transport

        yield _connect
        for transport in opened:
            await transport.close()


def rules(transport: Transport) -> list[str]:
    return [e.rule for e in transport.events() if isinstance(e, ProtocolViolation)]


# --- era detection, both carriers -------------------------------------------------------


async def test_modern_only_server(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "modern"
    assert session.protocol_version == "2026-07-28"
    assert session.supported_versions == ("2026-07-28",)
    assert session.server_capabilities == {"tools": {}}
    assert session.instructions == "scripted"
    assert session.server_info == {"name": "modern-fake"}  # stamped into discover's _meta
    assert server.methods() == ["server/discover"]  # no initialize, ever


async def test_dual_era_server_stays_modern(connect: Connect) -> None:
    server = EraServer(legacy=True, advertise_legacy=True)
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "modern"
    assert "initialize" not in server.methods()


async def test_legacy_only_server_falls_back_to_initialize(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True)
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "legacy"
    assert session.protocol_version == "2025-11-25"
    assert session.server_info == {"name": "legacy-fake", "version": "1"}
    assert session.instructions == "legacy hello"
    assert server.methods() == ["server/discover", "initialize", "notifications/initialized"]
    init_params = server.received[1][0]["params"]
    assert init_params["protocolVersion"] == "2025-11-25"
    assert init_params["clientInfo"] == {"name": "probe", "version": __version__}


@pytest.mark.parametrize("code", [-32602, -32000, -32603, -1])
async def test_fallback_is_not_keyed_to_one_error_code(connect: Connect, code: int) -> None:
    server = EraServer(modern=False, legacy=True, probe_error_code=code)
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "legacy"


async def test_silent_legacy_server_times_out_into_legacy(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True, legacy_probe="silent")
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "legacy"
    assert ("discover", "timeout") in [(s.action, s.outcome) for s in session.negotiation]


async def test_unsupported_version_retries_with_a_listed_modern_version(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect(server), modern_version="2026-09-01", **FAST)
    assert session.era == "modern"
    assert session.protocol_version == "2026-07-28"
    versions = [msg["params"]["_meta"][PV] for msg, _ in server.received]
    assert versions == ["2026-09-01", "2026-07-28"]
    ids = [msg["id"] for msg, _ in server.received]
    assert len(set(ids)) == 2  # the retry is a new request


async def test_server_listing_only_legacy_versions_gets_a_legacy_handshake(
    connect: Connect,
) -> None:
    server = EraServer(modern_versions=("2027-01-01",), legacy=True, advertise_legacy=True)
    session = await Session.open(await connect(server), **FAST)
    assert session.era == "legacy"
    assert server.methods() == ["server/discover", "initialize", "notifications/initialized"]


async def test_forced_modern_does_not_fall_back_when_only_legacy_is_listed(
    connect: Connect,
) -> None:
    server = EraServer(modern_versions=("2027-01-01",), legacy=True, advertise_legacy=True)
    with pytest.raises(NoCommonVersion) as info:
        await Session.open(await connect(server), era="modern", **FAST)
    assert info.value.supported == ("2027-01-01", "2025-11-25")
    assert "initialize" not in server.methods()


async def test_no_common_version_at_all(connect: Connect) -> None:
    server = EraServer(modern_versions=("2027-01-01",))
    with pytest.raises(NoCommonVersion):
        await Session.open(await connect(server), **FAST)


async def test_unsupported_version_error_without_a_list_fails(connect: Connect) -> None:
    class NoList(EraServer):
        def _modern(self, id_: Any, *args: Any) -> Reply:
            return error(id_, -32022, "Unsupported protocol version", data="oops", status=400)

    with pytest.raises(NegotiationFailed, match="supported-versions"):
        await Session.open(await connect(NoList()), **FAST)


async def test_other_modern_errors_on_discover_keep_the_session_modern(connect: Connect) -> None:
    class Strict(EraServer):
        def _modern(self, id_: Any, *args: Any) -> Reply:
            return error(id_, -32020, "Header mismatch", status=400)

    transport = await connect(Strict())
    session = await Session.open(transport, **FAST)
    assert session.era == "modern"
    assert "discover_rejected" in rules(transport)


async def test_forced_legacy_skips_discover(connect: Connect) -> None:
    server = EraServer(legacy=True, advertise_legacy=True)
    session = await Session.open(await connect(server), era="legacy", **FAST)
    assert session.era == "legacy"
    assert server.methods() == ["initialize", "notifications/initialized"]


async def test_forced_modern_stays_modern_against_a_legacy_server(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True)
    session = await Session.open(await connect(server), era="modern", **FAST)
    assert session.era == "modern"
    assert server.methods() == ["server/discover"]
    assert session.discover_result is None


async def test_legacy_server_answering_with_an_older_version(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True, legacy_version="2025-03-26")
    session = await Session.open(await connect(server), era="legacy", **FAST)
    assert session.protocol_version == "2025-03-26"
    assert (await session.request("tools/list")).unwrap() == {
        "method": "tools/list",
        "legacy": True,
    }


async def test_initialize_answering_with_an_unknown_version_fails(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True, initialize_version="2099-01-01")
    with pytest.raises(NegotiationFailed, match="2099-01-01"):
        await Session.open(await connect(server), era="legacy", **FAST)


async def test_initialize_rejected_by_a_modern_only_server(connect: Connect) -> None:
    server = EraServer()
    with pytest.raises(NegotiationFailed, match="rejected") as info:
        await Session.open(await connect(server), era="legacy", **FAST)
    assert info.value.steps[-1].action == "initialize"


async def test_unknown_era_is_a_programming_error(connect: Connect) -> None:
    with pytest.raises(ValueError, match="era"):
        await Session.open(await connect(EraServer()), era="both", **FAST)  # type: ignore[arg-type]


# --- building requests ------------------------------------------------------------------


async def test_modern_request_meta(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(
        await connect(server), client_capabilities={"elicitation": {}}, **FAST
    )
    await session.request("tools/list", {"cursor": "c"})
    sent = server.received[-1][0]["params"]
    meta = sent["_meta"]
    assert sent["cursor"] == "c"
    assert meta[PV] == "2026-07-28"
    assert meta["io.modelcontextprotocol/clientInfo"] == {"name": "probe", "version": __version__}
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {"elicitation": {}}
    assert TRACEPARENT.fullmatch(meta["traceparent"])
    assert "tracestate" not in meta
    assert "baggage" not in meta


async def test_caller_meta_is_merged_and_can_override(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect(server), **FAST)
    await session.request(
        "tools/list",
        {"_meta": {"progressToken": "p1", "custom": 1}},
        meta={"baggage": "k=v", "custom": 2},
    )
    meta = server.received[-1][0]["params"]["_meta"]
    assert meta["progressToken"] == "p1"
    assert meta["baggage"] == "k=v"
    assert meta["custom"] == 2  # the explicit argument wins
    assert meta[PV] == "2026-07-28"


async def test_traceparent_is_deterministic_per_seed_and_unique_per_request(
    connect: Connect,
) -> None:
    def parents(server: EraServer) -> list[str]:
        return [m["params"]["_meta"]["traceparent"] for m, _ in server.received]

    first, second, other = EraServer(), EraServer(), EraServer()
    for server, seed in ((first, 7), (second, 7), (other, 8)):
        session = await Session.open(await connect(server), seed=seed, **FAST)
        await session.request("tools/list")
        await session.request("tools/list")
    assert parents(first) == parents(second)
    assert len(set(parents(first))) == 3  # discover + two requests, all different
    assert parents(first) != parents(other)


async def test_every_request_gets_a_new_id(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect(server), **FAST)
    for _ in range(3):
        await session.request("tools/list")
    ids = [msg["id"] for msg, _ in server.received]
    assert len(set(ids)) == len(ids) == 4


async def test_legacy_requests_carry_no_meta(connect: Connect) -> None:
    server = EraServer(modern=False, legacy=True)
    session = await Session.open(await connect(server), era="legacy", **FAST)
    await session.request("tools/list", {"cursor": "c"})
    assert server.received[-1][0]["params"] == {"cursor": "c"}


async def test_notify_sends_a_notification(connect: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect(server), **FAST)
    await session.notify("notifications/cancelled", {"requestId": 1})
    message = server.received[-1][0]
    assert message == {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 1},
    }


async def test_tool_header_annotations_are_recorded_and_unusable_tools_excluded(
    connect: Connect,
) -> None:
    transport = await connect(EraServer())
    session = await Session.open(transport, **FAST)
    good = {"name": "good", "inputSchema": {"properties": {"r": {"type": "string"}}}}
    bad = {
        "name": "bad",
        "inputSchema": {"properties": {"n": {"type": "number", "x-mcp-header": "N"}}},
    }
    usable = session.register_tools([good, bad])
    assert set(session.x_mcp_header_errors) == {"bad"}
    # Over HTTP an invalid definition must be dropped; stdio may ignore the annotations.
    assert [t["name"] for t in usable] == (
        ["good"] if isinstance(transport, HttpTransport) else ["good", "bad"]
    )


# --- modern-era server behavior ---------------------------------------------------------


async def test_a_server_request_in_the_modern_era_is_a_violation_and_gets_method_not_found() -> (
    None
):
    server = EraServer()
    transport = ScriptedTransport(server)
    await Session.open(transport, **FAST)
    transport.push(Request("srv-1", "roots/list").to_obj())
    await asyncio.sleep(0.05)
    assert "server_request_in_modern_era" in rules(transport)
    reply, _ = server.received[-1]
    assert reply["id"] == "srv-1"
    assert reply["error"]["code"] == -32601


# --- HTTP specifics ---------------------------------------------------------------------


async def test_modern_http_headers_follow_the_body(connect_http: Connect) -> None:
    server = EraServer()
    transport = await connect_http(server)
    session = await Session.open(transport, **FAST)
    discover_headers = server.received[0][1]
    assert discover_headers is not None
    assert discover_headers["mcp-protocol-version"] == "2026-07-28"
    assert discover_headers["mcp-method"] == "server/discover"
    assert "mcp-name" not in discover_headers

    server.mirrors = {"Mcp-Param-Region": "us-west1", "Mcp-Param-Note": " padded é"}
    schema = {
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "note": {"type": "string", "x-mcp-header": "Note"},
        }
    }
    session.register_tools([{"name": "héllo", "inputSchema": schema}])
    arguments = {"region": "us-west1", "note": " padded é"}
    response = await session.request("tools/call", {"name": "héllo", "arguments": arguments})
    assert response.unwrap() == {"resultType": "complete", "method": "tools/call"}
    headers = server.received[-1][1]
    assert headers is not None
    assert headers["mcp-name"].startswith("=?base64?")  # non-ASCII tool name


async def test_unmirrored_parameters_are_rejected_by_a_strict_server(connect_http: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect_http(server), **FAST)
    server.mirrors = {"Mcp-Param-Region": "us-west1"}
    response = await session.request(
        "tools/call", {"name": "t", "arguments": {"region": "us-west1"}}
    )
    assert isinstance(response, ErrorResponse)
    assert response.error.code == -32020  # the tool was never registered, so no mirror


@pytest.mark.parametrize("probe", ["http400", "http404", "http400-json", "http500"])
async def test_http_status_without_a_modern_error_means_legacy(
    connect_http: Connect, probe: str
) -> None:
    server = EraServer(modern=False, legacy=True, legacy_probe=probe)  # type: ignore[arg-type]
    session = await Session.open(await connect_http(server), **FAST)
    assert session.era == "legacy"
    outcome = session.negotiation[0]
    assert outcome.action == "discover"
    assert outcome.outcome.startswith(("http", "error"))


async def test_unreachable_server_is_not_mistaken_for_a_legacy_one() -> None:
    transport = HttpTransport("http://127.0.0.1:1/mcp")
    try:
        with pytest.raises(HttpRequestFailed):
            await Session.open(transport, **FAST)
    finally:
        await transport.close()


async def test_legacy_http_session_id_and_version_header(connect_http: Connect) -> None:
    server = EraServer(modern=False, legacy=True, legacy_probe="http400")
    transport = await connect_http(server)
    session = await Session.open(transport, **FAST)
    assert isinstance(transport, HttpTransport)
    assert transport.session_id == "s-1"
    assert (await session.request("tools/list")).unwrap()["legacy"] is True
    headers = server.received[-1][1]
    assert headers is not None
    assert headers["mcp-session-id"] == "s-1"
    assert headers["mcp-protocol-version"] == "2025-11-25"
    # The handshake itself carries no version header; the initialized notification does.
    assert "mcp-protocol-version" not in (server.received[1][1] or {})
    assert (server.received[2][1] or {})["mcp-protocol-version"] == "2025-11-25"


async def test_expired_legacy_session_is_reinitialized_once(connect_http: Connect) -> None:
    server = EraServer(modern=False, legacy=True, legacy_probe="http400")
    transport = await connect_http(server)
    session = await Session.open(transport, **FAST)
    server.forget_session()
    assert (await session.request("tools/list")).unwrap()["legacy"] is True
    assert server.methods()[-4:] == [
        "tools/list",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert isinstance(transport, HttpTransport)
    assert transport.session_id == "s-2"
    assert ("reinitialize", "404 for a session the server no longer knows") in [
        (s.action, s.outcome) for s in session.negotiation
    ]


async def test_a_second_404_is_surfaced_not_retried_forever(connect_http: Connect) -> None:
    class Gone(EraServer):
        def _legacy(self, id_: Any, method: str, headers: Any) -> Reply:
            return Reply(status=404)

    server = Gone(modern=False, legacy=True, legacy_probe="http400")
    session = await Session.open(await connect_http(server), **FAST)
    with pytest.raises(HttpRequestFailed) as info:
        await session.request("tools/list")
    assert info.value.status == 404
    assert server.methods().count("initialize") == 2  # the original and exactly one retry


async def test_notifications_carry_mcp_method_over_http(connect_http: Connect) -> None:
    server = EraServer()
    session = await Session.open(await connect_http(server), **FAST)
    await session.notify("notifications/cancelled", {"requestId": 3})
    headers = server.received[-1][1]
    assert headers is not None
    assert headers["mcp-method"] == "notifications/cancelled"
    assert headers["mcp-protocol-version"] == "2026-07-28"


async def test_closed_transport_stops_the_session(connect: Connect) -> None:
    session = await Session.open(await connect(EraServer()), **FAST)
    await session.close()
    with pytest.raises(TransportClosed):
        await session.request("tools/list")
