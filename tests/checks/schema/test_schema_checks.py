"""Each schema check on scripted servers: a clean case and the failures it exists to catch."""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.schema.cache import CacheFieldsPresent, CacheTtlSane
from probe.checks.schema.definitions import (
    DescriptionsPresent,
    InputSchemaStrict,
    InputSchemaValid,
    RefsResolvable,
    ToolNamesValid,
    ToolsListValid,
    XMcpHeaderValid,
)
from probe.checks.schema.order import ToolOrderDeterministic
from probe.engine.outcomes import Severity, Status
from tests.checks.protocol.harness import ToolsServer, scripted_scan, with_listing

GOOD = {
    "name": "search_notes",
    "description": "Search notes.",
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "Text to find."}},
        "required": ["query"],
        "additionalProperties": False,
    },
}


def tool(**overrides: Any) -> dict[str, Any]:
    return {**GOOD, **overrides}


def schema_of(**properties: Any) -> dict[str, Any]:
    return {"type": "object", "properties": properties}


async def run(check: Any, tmp_path: Path, **server: Any) -> Any:
    async with scripted_scan(lambda: ToolsServer(**server), tmp_path) as scan:
        await with_listing(scan)
        return await scan.run(check)


async def run_legacy(check: Any, tmp_path: Path, **server: Any) -> Any:
    async with scripted_scan(
        lambda: ToolsServer(legacy=True, modern=False, **server), tmp_path, era="legacy"
    ) as scan:
        await with_listing(scan)
        return await scan.run(check)


# --- schema.tools_list_valid -------------------------------------------------------------


async def test_a_conforming_listing_passes_in_both_eras(tmp_path: Path) -> None:
    assert (await run(ToolsListValid, tmp_path, tools=[GOOD])).status is Status.PASS
    assert (await run_legacy(ToolsListValid, tmp_path / "b", tools=[GOOD])).status is Status.PASS


async def test_a_tool_without_input_schema_fails_the_listing(tmp_path: Path) -> None:
    result = await run(ToolsListValid, tmp_path, tools=[{"name": "broken"}])
    assert result.status is Status.FAIL
    assert "inputSchema" in result.findings[0].message
    assert result.findings[0].severity is Severity.HIGH


async def test_a_modern_listing_without_cache_fields_fails_the_schema(tmp_path: Path) -> None:
    result = await run(
        ToolsListValid, tmp_path, tools=[GOOD], list_extra={"ttlMs": None, "cacheScope": None}
    )
    assert result.status is Status.FAIL
    assert "ttlMs" in result.findings[0].message


async def test_tools_list_valid_is_na_when_there_is_no_listing(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        result = await scan.run(ToolsListValid)  # discovery never ran
    assert (result.status, result.reason) == (Status.NA, "tools/list returned no pages")


# --- schema.input_schema_valid -----------------------------------------------------------


async def test_input_schemas_pass_when_valid(tmp_path: Path) -> None:
    assert (await run(InputSchemaValid, tmp_path, tools=[GOOD])).status is Status.PASS


@pytest.mark.parametrize(
    ("schema", "fragment"),
    [
        ({"type": "object", "properties": {"a": {"type": "nope"}}}, "properties/a/type"),
        ({"type": "object", "required": "a"}, "required"),
        ({"type": "string"}, "not 'object'"),
        ({"properties": {}}, "not 'object'"),
    ],
)
async def test_invalid_input_schemas_fail(tmp_path: Path, schema: Any, fragment: str) -> None:
    result = await run(InputSchemaValid, tmp_path, tools=[tool(inputSchema=schema)])
    assert result.status is Status.FAIL
    assert fragment in result.findings[0].message


async def test_a_missing_input_schema_is_left_to_the_listing_check(tmp_path: Path) -> None:
    assert (await run(InputSchemaValid, tmp_path, tools=[{"name": "x"}])).status is Status.PASS


async def test_one_finding_per_bad_tool_with_a_cap(tmp_path: Path) -> None:
    bad = [tool(name=f"t{i}", inputSchema={"type": "string"}) for i in range(40)]
    result = await run(InputSchemaValid, tmp_path, tools=bad)
    assert result.status is Status.FAIL
    assert len(result.findings) == 26  # 25 individual findings plus one summary
    assert result.findings[-1].title.endswith("15 more tools")


# --- schema.refs_resolvable --------------------------------------------------------------


async def test_refs_pass_and_fail(tmp_path: Path) -> None:
    good = schema_of(a={"$ref": "#/$defs/s"}) | {"$defs": {"s": {"type": "string"}}}
    assert (
        await run(RefsResolvable, tmp_path, tools=[tool(inputSchema=good)])
    ).status is Status.PASS
    dangling = schema_of(a={"$ref": "#/$defs/missing"})
    remote = schema_of(a={"$ref": "https://evil.probe.test/x.json"})
    result = await run(
        RefsResolvable,
        tmp_path / "b",
        tools=[tool(name="d", inputSchema=dangling), tool(name="r", outputSchema=remote)],
    )
    assert result.status is Status.FAIL
    messages = {f.tool: f.message for f in result.findings}
    assert "unresolvable" in messages["d"]
    assert "outputSchema" in messages["r"] and "remote" in messages["r"]


# --- schema.tool_names_valid -------------------------------------------------------------


async def test_names_pass_when_well_formed(tmp_path: Path) -> None:
    tools = [tool(name="a.b-c_d"), tool(name="x" * 128)]
    assert (await run(ToolNamesValid, tmp_path, tools=tools)).status is Status.PASS


@pytest.mark.parametrize(
    "name",
    ["has space", "slash/name", "", "x" * 129, "naïve"],
    ids=["space", "slash", "empty", "long", "unicode"],
)
async def test_bad_names_fail(tmp_path: Path, name: str) -> None:
    result = await run(ToolNamesValid, tmp_path, tools=[tool(name=name)])
    assert result.status is Status.FAIL


async def test_duplicate_names_fail(tmp_path: Path) -> None:
    result = await run(ToolNamesValid, tmp_path, tools=[tool(), tool()])
    assert result.status is Status.FAIL
    assert "used by 2 tools" in result.findings[0].message


async def test_a_non_string_name_is_reported_by_position(tmp_path: Path) -> None:
    result = await run(ToolNamesValid, tmp_path, tools=[tool(name=7)])
    assert result.status is Status.FAIL
    assert result.findings[0].tool is None
    assert "(tool #0)" in result.findings[0].title


# --- schema.descriptions_present ---------------------------------------------------------


async def test_descriptions_pass_and_fail(tmp_path: Path) -> None:
    assert (await run(DescriptionsPresent, tmp_path, tools=[GOOD])).status is Status.PASS
    no_desc = tool(description="   ")
    bare_param = tool(
        name="p",
        inputSchema={
            "type": "object",
            "properties": {"q": {"type": "string"}, "opt": {"type": "string"}},
            "required": ["q"],
        },
    )
    result = await run(DescriptionsPresent, tmp_path / "b", tools=[no_desc, bare_param])
    assert result.status is Status.FAIL
    text = " ".join(f.message for f in result.findings)
    assert "tool has no description" in text
    assert "required parameter 'q'" in text
    assert "opt" not in text  # optional parameters are not required to be described


# --- schema.x_mcp_header_valid -----------------------------------------------------------


async def test_x_mcp_header_pass_fail_and_era(tmp_path: Path) -> None:
    ok = schema_of(r={"type": "string", "x-mcp-header": "Region"})
    bad = schema_of(n={"type": "number", "x-mcp-header": "N"})
    assert (
        await run(XMcpHeaderValid, tmp_path, tools=[tool(inputSchema=ok)])
    ).status is Status.PASS
    result = await run(XMcpHeaderValid, tmp_path / "b", tools=[tool(inputSchema=bad)])
    assert result.status is Status.FAIL
    assert "primitive" in result.findings[0].message
    legacy = await run_legacy(XMcpHeaderValid, tmp_path / "c", tools=[tool(inputSchema=bad)])
    assert legacy.status is Status.NA


# --- schema.input_schema_strict ----------------------------------------------------------


async def test_strictness_is_information_only(tmp_path: Path) -> None:
    clean = await run(InputSchemaStrict, tmp_path, tools=[GOOD])
    assert (clean.status, clean.findings) == (Status.PASS, [])
    loose = tool(name="loose", inputSchema=schema_of(a={"type": "string"}))
    noted = await run(InputSchemaStrict, tmp_path / "b", tools=[GOOD, loose])
    assert noted.status is Status.PASS
    assert [f.severity for f in noted.findings] == [Severity.INFO]
    assert noted.findings[0].evidence.observations["tools"] == ["loose"]


# --- schema.cache_fields_present / cache_ttl_sane ----------------------------------------


async def test_cache_fields_pass_when_present(tmp_path: Path) -> None:
    assert (await run(CacheFieldsPresent, tmp_path, tools=[GOOD])).status is Status.PASS


@pytest.mark.parametrize(
    ("extra", "fragment"),
    [
        ({"ttlMs": None}, "ttlMs is missing"),
        ({"ttlMs": -5}, "negative"),
        ({"ttlMs": "soon"}, "not a number"),
        ({"cacheScope": None}, "cacheScope is missing"),
        ({"cacheScope": "everyone"}, "not 'public' or 'private'"),
    ],
)
async def test_bad_cache_fields_fail(tmp_path: Path, extra: dict[str, Any], fragment: str) -> None:
    result = await run(CacheFieldsPresent, tmp_path, tools=[GOOD], list_extra=extra)
    assert result.status is Status.FAIL
    assert fragment in result.findings[0].message
    assert result.findings[0].repro.case_id == "cache-fields:tools/list"


async def test_cache_fields_are_na_for_legacy(tmp_path: Path) -> None:
    assert (await run_legacy(CacheFieldsPresent, tmp_path, tools=[GOOD])).status is Status.NA


async def test_cache_ttl_sane(tmp_path: Path) -> None:
    assert (await run(CacheTtlSane, tmp_path, tools=[GOOD])).status is Status.PASS
    result = await run(CacheTtlSane, tmp_path / "b", tools=[GOOD], list_extra={"ttlMs": 90_000_000})
    assert result.status is Status.FAIL
    assert "25 hours" in result.findings[0].message
    assert (
        await run(CacheTtlSane, tmp_path / "c", tools=[GOOD], list_extra={"ttlMs": 86_400_000})
    ).status is Status.PASS  # exactly 24 hours is still fine


# --- schema.tool_order_deterministic -----------------------------------------------------


class Rotating(ToolsServer):
    """Lists its tools in a different order on every call."""

    calls = 0

    def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
        if method == "tools/list":
            type(self).calls += 1
            tools = self.tools
            self.tools = (
                tools[type(self).calls % len(tools) :] + tools[: type(self).calls % len(tools)]
            )
        return super()._modern(id_, method, *rest)


async def test_a_stable_order_passes(tmp_path: Path) -> None:
    tools = [tool(name="a"), tool(name="b"), tool(name="c")]
    assert (await run(ToolOrderDeterministic, tmp_path, tools=tools)).status is Status.PASS


async def test_a_shuffled_order_fails(tmp_path: Path) -> None:
    Rotating.calls = 0
    tools = [tool(name="a"), tool(name="b"), tool(name="c")]
    async with scripted_scan(lambda: Rotating(tools=tools), tmp_path) as scan:
        await with_listing(scan)
        result = await scan.run(ToolOrderDeterministic)
    assert result.status is Status.FAIL
    assert "different order" in result.findings[0].message


async def test_a_second_instance_with_the_tools_in_another_order_fails(tmp_path: Path) -> None:
    made = iter(
        [
            ToolsServer(tools=[tool(name="a"), tool(name="b")]),  # the main instance
            ToolsServer(tools=[tool(name="b"), tool(name="a")]),  # the instance opened by the check
        ]
    )
    async with scripted_scan(lambda: next(made), tmp_path) as scan:
        await with_listing(scan)
        result = await scan.run(ToolOrderDeterministic)
    assert result.status is Status.FAIL
    assert "a second instance" in result.findings[0].message


async def test_a_one_off_difference_is_forgiven_by_the_rerun(tmp_path: Path) -> None:
    class Hiccup(ToolsServer):
        lists = 0

        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            reply = super()._modern(id_, method, *rest)
            if method == "tools/list":
                type(self).lists += 1
                if type(self).lists == 3:  # one odd answer, then stable again
                    reply.body["result"]["tools"] = list(reversed(self.tools))
            return reply

    Hiccup.lists = 0
    tools = [tool(name="a"), tool(name="b")]
    async with scripted_scan(lambda: Hiccup(tools=tools), tmp_path) as scan:
        await with_listing(scan)  # list call 1; the check's own listings are calls 2..5 and 6..9
        assert (await scan.run(ToolOrderDeterministic)).status is Status.PASS


# --- regressions from the M1 review ------------------------------------------------------


async def test_a_failing_listing_is_not_reported_as_nondeterministic(tmp_path: Path) -> None:
    from tests.wire.fake_eras import error

    class Flaky(ToolsServer):
        lists = 0

        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            if method == "tools/list":
                type(self).lists += 1
                if type(self).lists > 1:  # the first listing (discovery) works, later ones fail
                    return error(id_, -32603, "temporarily broken")
            return super()._modern(id_, method, *rest)

    Flaky.lists = 0
    async with scripted_scan(lambda: Flaky(tools=[GOOD, tool(name="b")]), tmp_path) as scan:
        await with_listing(scan)
        result = await scan.run(ToolOrderDeterministic)
    assert result.status is Status.NA
    assert "did not succeed" in (result.reason or "")


async def test_a_large_listing_without_cache_fields_is_still_caught(tmp_path: Path) -> None:
    async with scripted_scan(
        lambda: ToolsServer(tools=[GOOD], list_extra={"ttlMs": None}), tmp_path, body_max_bytes=40
    ) as scan:
        await with_listing(scan)
        result = await scan.run(CacheFieldsPresent)
    assert result.status is Status.FAIL
    assert "ttlMs is missing" in result.findings[0].message


async def test_several_pages_with_different_ttls_give_distinct_finding_ids(tmp_path: Path) -> None:
    async with scripted_scan(lambda: ToolsServer(tools=[GOOD]), tmp_path) as scan:
        await with_listing(scan)
        assert scan.ctx.listing is not None
        scan.ctx.listing.pages[:] = [
            {"tools": [], "ttlMs": 90_000_000, "cacheScope": "public"},
            {"tools": [], "ttlMs": 100_000_000, "cacheScope": "public"},
            {"tools": [], "ttlMs": 90_000_000, "cacheScope": "public"},
            {"tools": [], "ttlMs": 1_000, "cacheScope": "public"},
        ]
        result = await scan.run(CacheTtlSane)
    assert result.status is Status.FAIL
    assert [f.repro.case_id for f in result.findings] == [
        "cache-ttl:tools/list:page-0",
        "cache-ttl:tools/list:page-1",
    ]
    assert len({f.finding_id for f in result.findings}) == 2
    assert result.findings[0].evidence.observations["pages"] == [0, 2]
