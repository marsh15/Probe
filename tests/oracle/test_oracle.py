"""Probe's own wire client against the official SDK client, on the same refserver.

If Probe and the SDK disagree about what the server said, Probe's client is wrong (or the SDK
found something worth knowing). Both eras run over stdio and HTTP. Results are compared after
one normalization: ``None`` values are dropped, because the SDK's models drop absent fields.
"""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from probe.wire.session import Session
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpTransport
from probe.wire.transport_stdio import StdioTransport

# (Probe era, SDK mode)
ERAS = [("modern", "2026-07-28"), ("legacy", "legacy")]
KINDS = ["stdio", "http"]
TIMEOUT = 60  # first call can include interpreter and seed startup


def norm(value: Any) -> Any:
    """JSON-compatible value without ``None`` entries, so SDK and raw dicts compare equal."""
    if isinstance(value, dict):
        return {k: norm(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [norm(v) for v in value]
    return value


def result_for(era: str, raw: dict[str, Any]) -> Any:
    """A raw ``tools/call`` result, normalized for comparison with the SDK's model.

    Legacy servers do not send ``resultType`` and the SDK's model fills in its default
    ("complete", which is what an absent value means), so legacy comparisons drop it from both
    sides after asserting the raw result has none. Modern results must carry it and match.
    """
    value = norm(raw)
    if era == "legacy":
        assert "resultType" not in value
    else:
        assert value["resultType"] == "complete"
    return value


def sdk_result(era: str, model: Any) -> Any:
    value = sdk_dump(model)
    if era == "legacy":
        value.pop("resultType", None)
    return value


def sdk_dump(model: Any) -> Any:
    return norm(model.model_dump(by_alias=True, exclude_none=True, mode="json"))


@asynccontextmanager
async def probe_session(
    kind: str, era: str, stdio_command: tuple[list[str], dict[str, str]], http_url: str
) -> AsyncIterator[Session]:
    transport: Transport
    if kind == "stdio":
        argv, env = stdio_command
        transport = await StdioTransport.spawn(argv, env=env)
    else:
        transport = HttpTransport(http_url)
    try:
        yield await Session.open(
            transport,
            era=era,  # type: ignore[arg-type]
            probe_timeout=TIMEOUT,
            request_timeout=TIMEOUT,
        )
    finally:
        await transport.close()


@asynccontextmanager
async def sdk_client(
    kind: str, mode: str, stdio_command: tuple[list[str], dict[str, str]], http_url: str
) -> AsyncIterator[Client]:
    target: StdioServerParameters | str
    if kind == "stdio":
        argv, env = stdio_command
        target = StdioServerParameters(command=argv[0], args=argv[1:], env=env)
    else:
        target = http_url
    async with Client(target, mode=mode, read_timeout_seconds=TIMEOUT) as client:  # type: ignore[arg-type]
        yield client


async def probe_tools(session: Session) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(20):
        params = {"cursor": cursor} if cursor else None
        page = (await session.request("tools/list", params)).unwrap()
        tools += page["tools"]
        cursor = page.get("nextCursor")
        if not cursor:
            return tools
    raise AssertionError("tools/list did not terminate")


async def sdk_tools(client: Client) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(20):
        page = await client.list_tools(cursor=cursor)
        tools += [sdk_dump(tool) for tool in page.tools]
        cursor = page.next_cursor
        if not cursor:
            return tools
    raise AssertionError("tools/list did not terminate")


@pytest.mark.parametrize(("era", "mode"), ERAS)
@pytest.mark.parametrize("kind", KINDS)
async def test_both_clients_negotiate_the_same_version(
    kind: str, era: str, mode: str, stdio_command: Any, http_url: str
) -> None:
    async with (
        probe_session(kind, era, stdio_command, http_url) as ours,
        sdk_client(kind, mode, stdio_command, http_url) as sdk,
    ):
        assert ours.era == era
        assert ours.protocol_version == sdk.protocol_version


@pytest.mark.parametrize("kind", KINDS)
async def test_auto_detection_picks_modern_like_the_sdk(
    kind: str, stdio_command: Any, http_url: str
) -> None:
    async with (
        probe_session(kind, "auto", stdio_command, http_url) as ours,
        sdk_client(kind, "auto", stdio_command, http_url) as sdk,
    ):
        assert ours.era == "modern"
        assert ours.protocol_version == sdk.protocol_version == "2026-07-28"


@pytest.mark.parametrize(("era", "mode"), ERAS)
@pytest.mark.parametrize("kind", KINDS)
async def test_tools_list_is_identical(
    kind: str, era: str, mode: str, stdio_command: Any, http_url: str
) -> None:
    async with (
        probe_session(kind, era, stdio_command, http_url) as ours,
        sdk_client(kind, mode, stdio_command, http_url) as sdk,
    ):
        ours_tools = norm(await probe_tools(ours))
        sdk_list = await sdk_tools(sdk)
    assert len(ours_tools) == len(sdk_list) >= 15
    assert [t["name"] for t in ours_tools] == [t["name"] for t in sdk_list]  # order matters too
    for mine, theirs in zip(ours_tools, sdk_list, strict=True):
        assert json.dumps(mine, sort_keys=True) == json.dumps(theirs, sort_keys=True), mine["name"]


@pytest.mark.parametrize(("era", "mode"), ERAS)
@pytest.mark.parametrize("kind", KINDS)
async def test_notes_get_results_are_identical(
    kind: str, era: str, mode: str, stdio_command: Any, http_url: str
) -> None:
    async with (
        probe_session(kind, era, stdio_command, http_url) as ours,
        sdk_client(kind, mode, stdio_command, http_url) as sdk,
    ):
        raw = (
            await ours.request("tools/call", {"name": "notes_get", "arguments": {"id": 1}})
        ).unwrap()
        mine = result_for(era, raw)
        theirs = sdk_result(era, await sdk.call_tool("notes_get", {"id": 1}))
    assert mine["structuredContent"]["id"] == 1
    assert json.dumps(mine, sort_keys=True) == json.dumps(theirs, sort_keys=True)


@pytest.mark.parametrize(("era", "mode"), ERAS)
@pytest.mark.parametrize("kind", KINDS)
async def test_a_tool_error_looks_the_same_to_both_clients(
    kind: str, era: str, mode: str, stdio_command: Any, http_url: str
) -> None:
    arguments = {"id": 2_000_000_000}  # valid shape, no such note
    async with (
        probe_session(kind, era, stdio_command, http_url) as ours,
        sdk_client(kind, mode, stdio_command, http_url) as sdk,
    ):
        raw = (
            await ours.request("tools/call", {"name": "notes_get", "arguments": arguments})
        ).unwrap()
        mine = result_for(era, raw)
        theirs = sdk_result(era, await sdk.call_tool("notes_get", arguments))
    assert mine["isError"] is True
    assert json.dumps(mine, sort_keys=True) == json.dumps(theirs, sort_keys=True)


@pytest.mark.parametrize(("era", "mode"), ERAS)
@pytest.mark.parametrize("kind", KINDS)
async def test_server_identity_capabilities_and_instructions_match(
    kind: str, era: str, mode: str, stdio_command: Any, http_url: str
) -> None:
    async with (
        probe_session(kind, era, stdio_command, http_url) as ours,
        # An explicit version skips discover in the SDK, so it would have no identity to compare.
        sdk_client(kind, "auto" if era == "modern" else mode, stdio_command, http_url) as sdk,
    ):
        assert sdk.server_info is not None
        assert norm(ours.server_info) == sdk_dump(sdk.server_info)
        assert norm(ours.server_capabilities) == sdk_dump(sdk.server_capabilities)
        assert ours.instructions == sdk.instructions
        assert ours.server_info["name"] == "refserver"
