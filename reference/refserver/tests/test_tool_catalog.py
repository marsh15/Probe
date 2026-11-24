from __future__ import annotations

import pytest
from mcp import Client

pytestmark = pytest.mark.anyio

# (readOnly, destructive, idempotent, openWorld) per plan section 12.1.
EXPECTED = {
    "notes_create": (False, False, False, False),
    "notes_update": (False, False, True, False),
    "notes_delete": (False, True, True, False),
    "notes_get": (True, False, True, False),
    "notes_list": (True, False, True, False),
    "search_notes": (True, False, True, False),
    "fetch_url": (True, False, True, True),
    "read_file": (True, False, True, False),
    "write_file": (False, True, True, False),
    "query_db": (True, False, True, False),
    "git_log": (True, False, True, False),
    "slow_report": (True, False, True, False),
    "purge_notes": (False, True, True, False),
    "call_backend": (True, False, True, True),
    "long_export": (False, False, False, False),
}


async def test_all_tools_listed_in_stable_order(client: Client) -> None:
    first = [t.name for t in (await client.list_tools()).tools]
    second = [t.name for t in (await client.list_tools()).tools]
    assert first == second == list(EXPECTED)


async def test_annotations_are_complete_and_explicit(client: Client) -> None:
    for tool in (await client.list_tools()).tools:
        ann = tool.annotations
        assert ann is not None, tool.name
        wire = ann.model_dump(by_alias=True, exclude_none=True)
        for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
            assert key in wire, f"{tool.name} lacks explicit {key}"
        got = (ann.read_only_hint, ann.destructive_hint, ann.idempotent_hint, ann.open_world_hint)
        assert got == EXPECTED[tool.name], tool.name


async def test_descriptions_and_schemas(client: Client) -> None:
    for tool in (await client.list_tools()).tools:
        assert tool.description and tool.description.strip(), tool.name
        assert tool.input_schema["type"] == "object", tool.name
        for name, prop in tool.input_schema.get("properties", {}).items():
            assert "description" in prop or "$ref" in prop or "anyOf" in prop, f"{tool.name}.{name}"
        has_output = tool.output_schema is not None
        assert has_output == (tool.name in ("notes_get", "notes_list")), tool.name


async def test_tools_list_cache_hints_public_without_auth(client: Client) -> None:
    listing = await client.list_tools()
    assert listing.cache_scope == "public"
    assert 0 < listing.ttl_ms <= 3_600_000


async def test_long_export_runs_synchronously_without_the_tasks_extension(client: Client) -> None:
    result = await client.call_tool("long_export", {"items": [1, 2]})
    assert not result.is_error
    assert '"exported": 2' in result.content[0].text
