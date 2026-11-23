"""Draft-7 conversion preserves supported constraints and reports losses."""

from copy import deepcopy

import pytest
from jsonschema import Draft7Validator

from probe.schema.normalize import normalize


@pytest.mark.parametrize("tail", [False, True, {"type": "boolean"}])
def test_prefix_items_and_tail_are_converted(tail):
    result = normalize({"type": "array", "prefixItems": [{"type": "string"}], "items": tail})
    assert result.schema["items"] == [{"type": "string"}]
    assert result.schema["additionalItems"] == tail
    assert "prefixItems" not in result.schema
    Draft7Validator.check_schema(result.schema)


def test_prefix_items_without_a_tail_allows_additional_items():
    result = normalize({"prefixItems": [{"type": "integer"}]})
    assert result.schema["items"] == [{"type": "integer"}]
    assert result.schema.get("additionalItems", True) is True


@pytest.mark.parametrize("tail", [False, {"type": "integer"}])
def test_empty_prefix_items_is_a_uniform_array(tail):
    result = normalize({"prefixItems": [], "items": tail})
    assert result.schema["items"] == tail
    assert "additionalItems" not in result.schema
    Draft7Validator.check_schema(result.schema)


def test_defs_become_definitions_and_refs_are_inlined():
    result = normalize(
        {"$defs": {"x": {"type": "integer"}}, "properties": {"x": {"$ref": "#/$defs/x"}}}
    )
    assert result.schema["definitions"] == {"x": {"type": "integer"}}
    assert result.schema["properties"]["x"] == {"type": "integer"}
    assert "$defs" not in result.schema


def test_dependent_required_and_schemas_are_conjoined_on_collision():
    schema = {
        "dependentRequired": {"a": ["b"]},
        "dependentSchemas": {"a": {"properties": {"b": {"type": "string"}}}},
    }
    result = normalize(schema)
    validator = Draft7Validator(result.schema)
    assert validator.is_valid({})
    assert validator.is_valid({"a": 1, "b": "ok"})
    assert not validator.is_valid({"a": 1})
    assert not validator.is_valid({"a": 1, "b": 2})
    assert "dependentRequired" not in result.schema
    assert "dependentSchemas" not in result.schema


def test_separate_dependencies_and_existing_dependencies_are_preserved():
    result = normalize(
        {
            "dependencies": {"a": ["b"]},
            "dependentRequired": {"a": ["c"], "d": ["e"]},
            "dependentSchemas": {"f": {"required": ["g"]}},
        }
    )
    validator = Draft7Validator(result.schema)
    assert validator.is_valid({"a": 0, "b": 0, "c": 0})
    assert not validator.is_valid({"a": 0, "b": 0})
    assert result.schema["dependencies"]["d"] == ["e"]
    assert result.schema["dependencies"]["f"] == ["g"]
    assert not validator.is_valid({"f": 0})
    assert validator.is_valid({"f": 0, "g": 0})


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("unevaluatedProperties", False),
        ("unevaluatedItems", False),
        ("$dynamicAnchor", "node"),
        ("$vocabulary", {"https://example.test/vocab": True}),
        ("contentSchema", {"type": "object"}),
    ],
)
def test_dropped_keywords_have_path_specific_approximation_notes(keyword, value):
    result = normalize({"properties": {"a/b~c": {keyword: value}}})
    assert keyword not in result.schema["properties"]["a/b~c"]
    assert [(note.kind, note.path) for note in result.approximations] == [
        (keyword, f"/properties/a~1b~0c/{keyword}")
    ]


def test_new_contains_bounds_are_reported_as_approximations():
    result = normalize({"contains": {"type": "integer"}, "minContains": 0, "maxContains": 2})
    assert "minContains" not in result.schema
    assert "maxContains" not in result.schema
    assert {note.kind for note in result.approximations} == {"minContains", "maxContains"}


def test_draft_7_keywords_survive_in_all_schema_positions():
    schema = {
        "if": {"required": ["x"]},
        "then": {"properties": {"x": {"const": 1}}},
        "else": {"propertyNames": {"minLength": 1}},
        "contains": {"enum": [1, 2]},
        "not": {"type": "null"},
        "anyOf": [{"type": "array"}, {"type": "object"}],
        "allOf": [True],
        "oneOf": [{"minProperties": 1}, {"maxProperties": 0}],
    }
    result = normalize(schema)
    assert {k: v for k, v in result.schema.items() if k != "$schema"} == schema


def test_data_keywords_and_extension_annotations_are_not_rewritten():
    data = {
        "$defs": {"x": {}},
        "prefixItems": [],
        "dependentRequired": {"x": ["y"]},
        "unevaluatedProperties": False,
        "$ref": "https://example.test/data",
    }
    schema = {
        "const": data,
        "enum": [data],
        "default": data,
        "examples": [data],
        "x-annotation": data,
    }
    result = normalize(schema)
    assert {k: v for k, v in result.schema.items() if k != "$schema"} == schema
    assert result.approximations == ()


@pytest.mark.parametrize("schema", [True, False, {}, {"$schema": "https://unknown.test/draft"}])
def test_booleans_and_unknown_dialects_normalize(schema):
    result = normalize(schema)
    if isinstance(schema, bool):
        assert result.schema is schema
    else:
        assert result.schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    if isinstance(schema, dict) and "$schema" in schema:
        assert result.dialect.notes


def test_normalization_is_idempotent_and_does_not_mutate_input():
    schema = {
        "$defs": {"x": {"prefixItems": [{"const": {"$defs": {"y": 1}}}], "items": False}},
        "properties": {"x": {"$ref": "#/$defs/x"}},
        "dependentRequired": {"x": ["y"]},
        "unevaluatedProperties": False,
    }
    original = deepcopy(schema)
    result = normalize(schema)
    assert schema == original
    assert normalize(result.schema).schema == result.schema
    result.schema["definitions"]["x"]["items"][0]["const"]["$defs"]["y"] = 2
    assert schema == original


def test_min_contains_zero_does_not_require_a_matching_item():
    result = normalize({"type": "array", "contains": False, "minContains": 0})
    assert "contains" not in result.schema
    assert Draft7Validator(result.schema).is_valid([])
    assert Draft7Validator(result.schema).is_valid([1])
    assert [note.kind for note in result.approximations] == ["minContains"]


def test_colliding_dependency_lists_keep_all_required_names_without_duplicates():
    result = normalize({"dependencies": {"a": ["b"]}, "dependentRequired": {"a": ["b", "c"]}})
    assert result.schema["dependencies"]["a"] == ["b", "c"]
    Draft7Validator.check_schema(result.schema)


def test_all_schema_containers_are_normalized():
    child = {"unevaluatedProperties": False, "dependentRequired": {"x": ["y"]}}
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "patternProperties": {".*": child},
        "additionalProperties": child,
        "items": [child],
        "additionalItems": child,
        "contains": child,
        "dependencies": {"a": child},
        "propertyNames": child,
        "not": child,
        "if": child,
        "then": child,
        "else": child,
        "allOf": [child],
        "anyOf": [child],
        "oneOf": [child],
    }
    result = normalize(schema)
    assert len(result.approximations) == 14
    for note in result.approximations:
        assert note.kind == "unevaluatedProperties"
    assert result.schema["patternProperties"][".*"] == {"dependencies": {"x": ["y"]}}


def test_reference_diagnostics_are_available_after_normalization():
    result = normalize({"$ref": "https://missing.probe.test/schema"})
    assert result.ref_problems == (("https://missing.probe.test/schema", "remote"),)
    assert [note.kind for note in result.approximations] == ["ref_remote"]
