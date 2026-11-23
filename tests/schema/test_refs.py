"""Reference inlining stays offline and bounds reference expansion."""

from copy import deepcopy
from unittest.mock import patch

import pytest
from jsonschema import Draft7Validator

from probe.schema.refs import inline_refs


@pytest.mark.parametrize("definitions", ["$defs", "definitions"])
def test_local_pointer_refs_are_inlined(definitions):
    schema = {
        definitions: {"a/b~c": {"type": "string"}},
        "properties": {"x": {"$ref": f"#/{definitions}/a~1b~0c"}},
    }
    result = inline_refs(schema)
    assert result.schema["properties"]["x"] == {"type": "string"}
    assert result.problems == ()


def test_local_anchor_and_embedded_id_refs_resolve():
    schema = {
        "$id": "https://example.test/root",
        "$defs": {
            "s": {"$anchor": "text", "type": "string"},
            "n": {"$id": "number", "type": "integer"},
        },
        "properties": {"s": {"$ref": "#text"}, "n": {"$ref": "number"}},
    }
    result = inline_refs(schema)
    assert result.schema["properties"]["s"]["type"] == "string"
    assert result.schema["properties"]["n"]["type"] == "integer"
    assert result.problems == ()


def test_refs_respect_nested_resource_scope():
    schema = {
        "$id": "https://example.test/root",
        "$defs": {
            "inner": {
                "$id": "inner/",
                "$defs": {"s": {"$id": "text", "type": "string"}},
                "properties": {"x": {"$ref": "text"}},
            }
        },
        "$ref": "inner/",
    }
    result = inline_refs(schema)
    assert result.problems == ()
    assert result.schema["allOf"][0]["properties"]["x"]["type"] == "string"


def test_exactly_three_ref_hops_are_inlined():
    schema = {
        "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/c"}, "c": {"type": "integer"}},
        "$ref": "#/$defs/a",
    }
    assert inline_refs(schema).schema["allOf"][0] == {"type": "integer"}
    schema["$defs"]["c"] = {"$ref": "#/$defs/d"}
    schema["$defs"]["d"] = {"type": "integer"}
    result = inline_refs(schema)
    assert result.schema["allOf"][0] == {}
    assert any(note.kind == "ref_depth" for note in result.approximations)


def test_recursive_ref_is_cut_after_three_expansions():
    schema = {"type": "object", "properties": {"next": {"$ref": "#"}}}
    result = inline_refs(schema)
    node = result.schema
    for _ in range(3):
        node = node["properties"]["next"]
        assert node["type"] == "object"
    assert node["properties"]["next"] == {}
    assert result.problems == ()
    assert result.approximations[0].kind == "ref_depth"


@pytest.mark.parametrize(
    ("ref", "reason"),
    [
        ("https://evil.probe.test/schema", "remote"),
        ("file:///etc/passwd", "remote"),
        ("http://example.test/a", "remote"),
        ("ftp://example.test/a", "remote"),
        ("#/$defs/missing", "unresolvable"),
        ("#missing-anchor", "unresolvable"),
        ("missing.json", "unresolvable"),
    ],
)
def test_bad_refs_are_reported_and_replaced_without_network(ref, reason):
    with patch("socket.socket", side_effect=AssertionError("network access")):
        result = inline_refs({"properties": {"x": {"$ref": ref}, "y": {"$ref": ref}}})
    assert result.schema["properties"] == {"x": {}, "y": {}}
    assert result.problems == ((ref, reason),)
    assert len(result.approximations) == 2
    assert {note.kind for note in result.approximations} == {f"ref_{reason}"}


def test_static_dynamic_ref_resolution_is_noted():
    schema = {"$defs": {"x": {"$dynamicAnchor": "node", "type": "integer"}}, "$dynamicRef": "#node"}
    result = inline_refs(schema)
    assert result.schema["allOf"][0]["type"] == "integer"
    assert any(note.kind == "dynamic_ref" for note in result.approximations)
    missing = inline_refs({"$dynamicRef": "#missing"})
    assert missing.schema == {}
    assert missing.problems == (("#missing", "unresolvable"),)


def test_modern_ref_siblings_are_conjoined():
    schema = {"$defs": {"x": {"type": "integer"}}, "$ref": "#/$defs/x", "minimum": 3}
    result = inline_refs(schema)
    assert Draft7Validator(result.schema).is_valid(3)
    assert not Draft7Validator(result.schema).is_valid(2)


def test_draft_7_ref_siblings_are_ignored():
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "definitions": {"x": {"type": "integer"}},
        "$ref": "#/definitions/x",
        "minimum": 3,
    }
    result = inline_refs(schema)
    assert result.schema == {"type": "integer"}
    assert any(note.kind == "ref_siblings" for note in result.approximations)


def test_boolean_ref_targets_and_ref_like_data_are_preserved():
    schema = {
        "$defs": {"no": False},
        "properties": {"x": {"$ref": "#/$defs/no"}},
        "const": {"$ref": "https://example.test/data"},
        "properties-not-a-keyword": {"$ref": "data"},
    }
    original = deepcopy(schema)
    result = inline_refs(schema)
    assert result.schema["properties"]["x"] is False
    assert result.schema["const"] == schema["const"]
    assert result.schema["properties-not-a-keyword"] == schema["properties-not-a-keyword"]
    assert result.problems == ()
    assert schema == original
    result.schema["const"]["$ref"] = "changed"
    assert schema == original


def test_property_names_that_look_like_keywords_are_not_schemas():
    schema = {
        "properties": {"$ref": {"type": "string"}, "const": {"$ref": "#/$defs/x"}},
        "$defs": {"x": {"type": "integer"}},
    }
    result = inline_refs(schema)
    assert result.schema["properties"]["const"] == {"type": "integer"}
    assert result.problems == ()


def test_missing_local_anchor_with_an_absolute_id_is_unresolvable():
    result = inline_refs({"$id": "https://example.test/local", "$ref": "#missing"})
    assert result.problems == (("#missing", "unresolvable"),)


def test_remote_metaschemas_are_not_inlined_even_when_installed_offline():
    result = inline_refs({"$ref": "https://json-schema.org/draft/2020-12/schema"})
    assert result.schema == {}
    assert result.problems == (("https://json-schema.org/draft/2020-12/schema", "remote"),)


def test_zero_depth_and_invalid_depth():
    schema = {"$defs": {"x": {"type": "string"}}, "properties": {"x": {"$ref": "#/$defs/x"}}}
    result = inline_refs(schema, max_depth=0)
    assert result.schema["properties"]["x"] == {}
    assert result.approximations[0].kind == "ref_depth"
    with pytest.raises(ValueError, match="nonnegative"):
        inline_refs(schema, max_depth=-1)


def test_ref_to_non_schema_is_unresolvable():
    result = inline_refs({"title": "data", "$ref": "#/title"})
    assert result.schema["allOf"][0] == {}
    assert result.problems == (("#/title", "unresolvable"),)
