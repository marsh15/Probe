"""Meta-validation, $ref resolution and spec validation of tool schemas."""

from typing import Any

import pytest

from probe.schema.jsonschema_tools import find_refs, meta_problems, ref_problems
from probe.schema.spec import list_tools_problems, vendored_schema


def test_valid_schemas_have_no_problems() -> None:
    assert meta_problems({"type": "object", "properties": {"a": {"type": "string"}}}) == []
    assert meta_problems({}) == []
    assert meta_problems(True) == []


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "nope"},
        {"type": "object", "properties": {"a": {"minimum": "x"}}},
        {"type": "object", "required": "a"},
        {"$schema": "http://json-schema.org/draft-07/schema#", "type": 5},
    ],
)
def test_invalid_schemas_are_reported(schema: Any) -> None:
    assert meta_problems(schema)


def test_a_non_schema_is_reported() -> None:
    assert meta_problems("string")[0].startswith("not a JSON Schema")
    assert meta_problems(None)[0].startswith("not a JSON Schema")


def test_pathologically_deep_schemas_do_not_crash() -> None:
    deep: dict[str, Any] = {"type": "object"}
    for _ in range(5000):
        deep = {"type": "object", "properties": {"x": deep}}
    problems = meta_problems(deep)
    assert problems and "deep" in problems[0]


def test_find_refs_ignores_data_keywords() -> None:
    schema = {
        "properties": {
            "a": {"$ref": "#/$defs/x"},
            "b": {"enum": [{"$ref": "not a ref"}], "default": {"$ref": "also data"}},
        },
        "$defs": {"x": {"type": "string"}, "y": {"items": {"$ref": "#/$defs/x"}}},
    }
    assert sorted(find_refs(schema)) == ["#/$defs/x", "#/$defs/x"]


def test_local_refs_that_exist_are_fine() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"$ref": "#/$defs/s"}, "b": {"$ref": "#"}},
        "$defs": {"s": {"type": "string"}},
    }
    assert ref_problems(schema) == []


def test_a_ref_to_a_missing_definition_is_unresolvable() -> None:
    assert ref_problems({"properties": {"a": {"$ref": "#/$defs/missing"}}}) == [
        ("#/$defs/missing", "unresolvable")
    ]


@pytest.mark.parametrize(
    "ref",
    ["https://evil.probe.test/schema.json", "http://internal.example/x#/y", "file:///etc/passwd"],
)
def test_remote_refs_are_flagged_not_fetched(ref: str) -> None:
    assert ref_problems({"properties": {"a": {"$ref": ref}}}) == [(ref, "remote")]


def test_refs_to_embedded_ids_and_standard_metaschemas_resolve_offline() -> None:
    schema = {
        "$id": "https://example.test/root.json",
        "properties": {
            "a": {"$ref": "https://example.test/other.json"},
            "b": {"$ref": "https://json-schema.org/draft/2020-12/schema"},
        },
        "$defs": {"o": {"$id": "https://example.test/other.json", "type": "string"}},
    }
    assert ref_problems(schema) == []


def test_a_relative_ref_without_a_base_is_unresolvable() -> None:
    assert ref_problems({"properties": {"a": {"$ref": "other.json"}}}) == [
        ("other.json", "unresolvable")
    ]


def test_vendored_schemas_load_for_both_eras() -> None:
    for version in ("2026-07-28", "2025-11-25"):
        document = vendored_schema(version)
        assert "ListToolsResult" in (document.get("$defs") or document["definitions"])
    with pytest.raises(KeyError):
        vendored_schema("1999-01-01")


MODERN_PAGE: dict[str, Any] = {
    "resultType": "complete",
    "ttlMs": 0,
    "cacheScope": "public",
    "tools": [{"name": "a", "inputSchema": {"type": "object"}}],
}


def test_a_conforming_page_has_no_problems() -> None:
    assert list_tools_problems(MODERN_PAGE, "2026-07-28") == []
    legacy = {"tools": [{"name": "a", "inputSchema": {"type": "object"}}]}
    assert list_tools_problems(legacy, "2025-11-25") == []
    assert list_tools_problems(legacy, "2025-03-26") == []  # older legacy: judged by 2025-11-25


def test_violations_are_reported_with_their_location() -> None:
    page = {**MODERN_PAGE, "tools": [{"name": "a"}, {"inputSchema": {}}]}
    problems = list_tools_problems(page, "2026-07-28")
    assert any("tools/0" in p and "inputSchema" in p for p in problems)
    assert any("tools/1" in p and "name" in p for p in problems)


def test_modern_pages_need_the_cache_fields() -> None:
    page = {"tools": [{"name": "a", "inputSchema": {"type": "object"}}]}
    problems = " ".join(list_tools_problems(page, "2026-07-28"))
    assert "ttlMs" in problems and "cacheScope" in problems and "resultType" in problems
    assert list_tools_problems(page, "2025-11-25") == []


def test_problem_lists_are_capped() -> None:
    page = {**MODERN_PAGE, "tools": [{} for _ in range(100)]}
    assert len(list_tools_problems(page, "2026-07-28")) <= 20
