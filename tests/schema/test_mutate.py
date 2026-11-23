"""Mutation rules, original-schema rejection, sampling, and bounded hostile inputs."""

import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, Draft202012Validator

from probe.engine.outcomes import ToolInfo
from probe.schema.mutate import (
    ARRAY_STRESS_ITEMS,
    NESTING_DEPTH,
    PROPERTY_NAME_BYTES,
    STRING_STRESS_BYTES,
    boundary_cases,
    malformed_cases,
)
from tests.schema.synthetic import SCHEMAS

FIXTURES = sorted(Path("fixtures/schemas").glob("*.json"))


def tool(schema, name="test"):
    return ToolInfo(
        name=name,
        title=None,
        description=None,
        input_schema=schema,
        output_schema=None,
        annotations={},
        kind="read",
        flags=set(),
        classification_source="heuristic",
        classification_reason="test",
        param_roles={},
    )


def boundary(schema, base=None, seed=0):
    return boundary_cases(
        tool({"type": "object", "properties": {"x": schema}}), base, seed=seed, mode="deep"
    )


def values(result, rule, prop="x"):
    return [case.arguments[prop] for case in result.cases if case.rule == rule]


@pytest.mark.parametrize(
    ("rule", "schema", "expected"),
    [
        ("string-empty", {"type": "string"}, ""),
        ("string-min-length", {"type": "string", "minLength": 2}, "aa"),
        ("string-min-length-minus-one", {"type": "string", "minLength": 2}, "a"),
        ("string-max-length", {"type": "string", "maxLength": 3}, "aaa"),
        ("string-max-length-plus-one", {"type": "string", "maxLength": 3}, "aaaa"),
        ("string-large", {"type": "string"}, "a" * 65536),
        ("string-unicode-emoji", {"type": "string"}, "😀"),
        ("string-unicode-rtl", {"type": "string"}, "\u202e"),
        ("string-unicode-combining", {"type": "string"}, "e\u0301"),
        ("string-unicode-nul", {"type": "string"}, "\x00"),
        ("number-minimum", {"type": "number", "minimum": 2}, 2),
        ("number-minimum-minus-one", {"type": "number", "minimum": 2}, 1),
        ("number-maximum", {"type": "number", "maximum": 5}, 5),
        ("number-maximum-plus-one", {"type": "number", "maximum": 5}, 6),
        ("number-exclusive-minimum", {"type": "number", "exclusiveMinimum": 2}, 2),
        ("number-exclusive-minimum-inside", {"type": "integer", "exclusiveMinimum": 2}, 3),
        ("number-exclusive-maximum", {"type": "number", "exclusiveMaximum": 5}, 5),
        ("number-exclusive-maximum-inside", {"type": "integer", "exclusiveMaximum": 5}, 4),
        ("number-zero", {"type": "integer"}, 0),
        ("number-negative-one", {"type": "number"}, -1),
        ("number-unsafe-integer", {"type": "number"}, 2**53 + 1),
        ("number-min-int64", {"type": "number"}, -(2**63)),
        ("number-large", {"type": "number"}, 1e308),
        ("array-empty", {"type": "array"}, []),
        ("array-min-items", {"type": "array", "items": {"const": 7}, "minItems": 2}, [7, 7]),
        (
            "array-max-items-plus-one",
            {"type": "array", "items": {"const": 7}, "maxItems": 2},
            [7, 7, 7],
        ),
        ("array-large", {"type": "array", "items": {"const": 7}}, [7] * 1000),
        ("boolean-false", {"type": "boolean"}, False),
        ("boolean-true", {"type": "boolean"}, True),
    ],
)
def test_boundary_rule_values(rule, schema, expected):
    assert values(boundary(schema), rule) == [expected]


@pytest.mark.parametrize(
    ("kind", "rules"),
    [
        (
            "string",
            {
                "string-min-length",
                "string-min-length-minus-one",
                "string-max-length",
                "string-max-length-plus-one",
            },
        ),
        (
            "number",
            {
                "number-minimum",
                "number-minimum-minus-one",
                "number-maximum",
                "number-maximum-plus-one",
                "number-exclusive-minimum",
                "number-exclusive-minimum-inside",
                "number-exclusive-maximum",
                "number-exclusive-maximum-inside",
            },
        ),
        ("array", {"array-min-items", "array-max-items-plus-one"}),
        ("boolean", {"enum-member", "enum-non-member"}),
    ],
)
def test_constraint_rules_are_absent_without_constraints(kind, rules):
    assert not rules.intersection(case.rule for case in boundary({"type": kind}).cases)


def test_zero_minimum_length_never_produces_a_negative_length():
    result = boundary({"type": "string", "minLength": 0})
    assert not values(result, "string-min-length-minus-one")
    assert values(result, "string-min-length") == [""]


def test_enum_members_and_non_member_use_json_schema_equality():
    members = [0, False, "probe", None, {"a": [1]}]
    result = boundary({"enum": members})
    assert sorted(map(json.dumps, values(result, "enum-member"))) == sorted(
        map(json.dumps, members)
    )
    non_members = values(result, "enum-non-member")
    assert len(non_members) == 1
    assert not Draft202012Validator({"enum": members}).is_valid(non_members[0])


def test_refs_and_composition_constraints_are_discovered():
    schema = {
        "$defs": {"text": {"type": "string", "minLength": 2}},
        "allOf": [
            {"properties": {"x": {"$ref": "#/$defs/text"}}},
            {"properties": {"x": {"maxLength": 4}}},
        ],
    }
    result = boundary_cases(tool(schema), {"x": "ok"}, seed=0, mode="deep")
    assert values(result, "string-min-length") == ["aa"]
    assert values(result, "string-max-length") == ["aaaa"]


def test_constraints_in_branches_and_conditionals_are_discovered():
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"x": {"type": "integer", "minimum": 3}}},
            {"properties": {"y": {"type": "array", "maxItems": 2}}},
        ],
        "if": {"required": ["flag"]},
        "then": {"properties": {"z": {"type": "string", "maxLength": 2}}},
    }
    result = boundary_cases(tool(schema), {}, seed=0, mode="deep")
    assert any(c.rule == "number-minimum" and c.arguments["x"] == 3 for c in result.cases)
    assert any(c.rule == "array-max-items-plus-one" for c in result.cases)
    assert any(c.rule == "string-max-length" for c in result.cases)


@pytest.mark.parametrize(
    ("schema", "base", "rule", "expected"),
    [
        ({"type": "object"}, {}, "root-not-object", [[], "x", None]),
        (
            {"type": "object", "required": ["x"], "properties": {"x": {"type": "string"}}},
            {"x": "ok"},
            "missing-required",
            [{}],
        ),
        ({"properties": {"x": {"type": "string"}}}, {"x": "ok"}, "type-swap", [{"x": 0}]),
        ({"properties": {"x": {"type": "number"}}}, {"x": 1}, "type-swap", [{"x": "x"}]),
        ({"properties": {"x": {"type": "object"}}}, {"x": {}}, "type-swap", [{"x": []}]),
        ({"properties": {"x": {"type": "array"}}}, {"x": []}, "type-swap", [{"x": {}}]),
        ({"properties": {"x": {"type": "boolean"}}}, {"x": True}, "type-swap", [{"x": "x"}]),
        ({"properties": {"x": {"type": "null"}}}, {"x": None}, "type-swap", [{"x": "x"}]),
        ({"properties": {"x": {"type": "string"}}}, {"x": "ok"}, "type-null", [{"x": None}]),
    ],
)
def test_malformed_rule_values(schema, base, rule, expected):
    result = malformed_cases(tool(schema), base, seed=0, mode="deep")
    actual = [c.arguments for c in result.cases if c.rule == rule]
    assert sorted(map(json.dumps, actual)) == sorted(map(json.dumps, expected))


def test_extra_property_huge_name_and_nesting_rules():
    schema = {"type": "object", "additionalProperties": False}
    result = malformed_cases(tool(schema), {}, seed=0, mode="deep")
    by_rule = {c.rule: c.arguments for c in result.cases}
    assert len(by_rule["extra-property"]) == 1
    assert len(next(iter(by_rule["huge-property-name"]))) == PROPERTY_NAME_BYTES == 10240
    value = by_rule["nesting-64"]
    depth = 0
    while isinstance(value, dict):
        depth += 1
        value = next(iter(value.values()))
    assert depth == NESTING_DEPTH == 64
    assert STRING_STRESS_BYTES == 65536
    assert ARRAY_STRESS_ITEMS == 1000


def test_non_required_and_open_object_rules_are_not_mislabeled():
    result = malformed_cases(
        tool({"type": "object", "properties": {"x": {}}}), {}, seed=0, mode="deep"
    )
    assert not {"missing-required", "extra-property"}.intersection(c.rule for c in result.cases)
    assert any("stayed valid" in note and "huge-property-name" in note for note in result.notes)
    assert any("stayed valid" in note and "nesting-64" in note for note in result.notes)


def test_type_swaps_that_remain_valid_are_dropped_and_not_budget_skipped():
    schema = {"type": "object", "properties": {"x": {"type": ["string", "number", "null"]}}}
    result = malformed_cases(tool(schema), {"x": "ok"}, seed=0, mode="deep")
    assert {c.rule for c in result.cases} == {"root-not-object"}
    assert not result.skipped
    assert any("type-swap" in note and "stayed valid" in note for note in result.notes)
    assert any("type-null" in note and "stayed valid" in note for note in result.notes)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_every_malformed_fixture_case_is_invalid_under_original_schema(path):
    schema = json.loads(path.read_text())
    result = malformed_cases(tool(schema, path.stem), None, seed=42, mode="deep")
    assert result.cases  # Corpus validation must not silently become vacuous.
    cls = Draft7Validator if "draft-07" in schema.get("$schema", "") else Draft202012Validator
    for case in result.cases:
        assert not cls(schema).is_valid(case.arguments), case.id


@pytest.mark.parametrize("schema", list(SCHEMAS.values()), ids=list(SCHEMAS))
def test_every_malformed_synthetic_case_is_invalid(schema):
    result = malformed_cases(tool(schema), None, seed=42, mode="deep")
    for case in result.cases:
        assert not Draft202012Validator(schema).is_valid(case.arguments), case.id


@pytest.mark.parametrize(
    "schema,base,missing",
    [
        ({"allOf": [{"required": ["x"]}, {"properties": {"x": {"const": 1}}}]}, {"x": 1}, "x"),
        (
            {"dependentRequired": {"x": ["y"]}, "properties": {"x": {}, "y": {}}},
            {"x": 1, "y": 2},
            "y",
        ),
        (
            {
                "if": {"required": ["x"]},
                "then": {"required": ["y"]},
                "properties": {"x": {}, "y": {}},
            },
            {"x": 1, "y": 2},
            "y",
        ),
    ],
)
def test_composed_required_properties_are_removed_one_at_a_time(schema, base, missing):
    result = malformed_cases(tool(schema), base, seed=0, mode="deep")
    assert any(c.rule == "missing-required" and missing not in c.arguments for c in result.cases)
    assert all(not Draft202012Validator(schema).is_valid(c.arguments) for c in result.cases)


def test_one_of_optional_branch_requirements_are_filtered():
    schema = {
        "type": "object",
        "oneOf": [{"required": ["x"]}, {"required": ["y"]}],
        "properties": {"x": {}, "y": {}},
    }
    result = malformed_cases(tool(schema), {"x": 1}, seed=0, mode="deep")
    assert not any(c.rule == "missing-required" and "x" in c.arguments for c in result.cases)
    assert all(not Draft202012Validator(schema).is_valid(c.arguments) for c in result.cases)


@pytest.mark.parametrize(
    "mutator,caps", [(boundary_cases, [2, 8, 20]), (malformed_cases, [2, 6, 15])]
)
def test_caps_partition_candidates_and_are_reproducible(mutator, caps):
    schema = {
        "type": "object",
        "properties": {f"p{i}": {"type": "string"} for i in range(8)},
        "required": [f"p{i}" for i in range(8)],
        "additionalProperties": False,
    }
    base = {f"p{i}": "ok" for i in range(8)}
    results = [
        mutator(tool(schema), base, seed=12, mode=mode) for mode in ("quick", "standard", "deep")
    ]
    totals = []
    for result, cap in zip(results, caps, strict=True):
        assert len(result.cases) == cap
        ids = [c.id for c in result.cases] + result.skipped
        assert len(set(ids)) == len(ids)
        assert all(re.fullmatch(r"test:(boundary|malformed):[a-z0-9-]+:\d+", i) for i in ids)
        totals.append(set(ids))
    assert totals[0] == totals[1] == totals[2]
    assert results[0] == mutator(tool(schema), base, seed=12, mode="quick")
    assert results[0].cases != mutator(tool(schema), base, seed=99, mode="quick").cases


def test_round_robin_covers_rules_and_properties_before_repeating():
    schema = {
        "type": "object",
        "properties": {p: {"type": "string", "minLength": 1, "maxLength": 8} for p in "abcd"},
    }
    base = dict.fromkeys("abcd", "ok")
    for seed in range(10):
        result = boundary_cases(tool(schema), base, seed=seed, mode="standard")
        assert len({c.rule for c in result.cases}) == 8
        changed = [next(p for p in base if c.arguments[p] != base[p]) for c in result.cases]
        assert len(set(changed[:4])) == 4


def test_smallest_base_uses_required_const_enum_default_and_types():
    schema = {
        "type": "object",
        "properties": {
            "a": {"const": {"key": 2}},
            "b": {"enum": [7, 8]},
            "c": {"type": "string", "default": "yes"},
            "d": {"type": "boolean"},
            "e": {"type": "array", "minItems": 2, "items": {"const": 1}},
            "optional": {"type": "string"},
        },
        "required": ["a", "b", "c", "d", "e"],
    }
    result = boundary_cases(tool(schema), None, seed=0, mode="deep")
    case = next(c for c in result.cases if c.rule == "boolean-true")
    assert case.arguments == {"a": {"key": 2}, "b": 7, "c": "yes", "d": True, "e": [1, 1]}


@pytest.mark.parametrize("mutator", [boundary_cases, malformed_cases])
def test_inputs_and_other_cases_are_not_aliased(mutator):
    schema = {
        "type": "object",
        "properties": {"x": {"type": "string"}, "keep": {"type": "array"}},
        "required": ["x"],
    }
    base = {"x": "ok", "keep": [{"value": 1}]}
    before = deepcopy((schema, base))
    result = mutator(tool(schema), base, seed=0, mode="deep")
    case = next(
        c
        for c in result.cases
        if isinstance(c.arguments, dict) and c.arguments.get("keep") == base["keep"]
    )
    others = deepcopy([c for c in result.cases if c is not case])
    case.arguments["keep"].append("changed")
    assert (schema, base) == before
    assert [c for c in result.cases if c is not case] == others


def test_separate_process_determinism():
    script = """
import json
from dataclasses import asdict
from tests.schema.test_mutate import tool
from probe.schema.mutate import boundary_cases, malformed_cases
schema = {"type": "object", "properties": {p: {"type": "string"} for p in "abcd"}}
print(json.dumps([asdict(f(tool(schema), None, seed=8, mode="standard"))
                  for f in (boundary_cases, malformed_cases)], sort_keys=True))
"""
    outputs = [
        subprocess.run(  # noqa: S603 - fixed interpreter and test script
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": str(seed)},
        ).stdout
        for seed in (1, 999)
    ]
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("mutator", [boundary_cases, malformed_cases])
@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(10000)}},
        {"properties": {"x": {"enum": list(range(100000))}}},
        {"properties": {"x": {"type": "string", "minLength": 10**100}}},
        {"properties": {"x": {"type": "array", "maxItems": 10**100}}},
    ],
)
def test_pathological_sizes_are_bounded_and_noted(mutator, schema):
    result = mutator(tool(schema), None, seed=0, mode="deep")
    assert result.notes
    assert len(result.cases) <= 20
    assert len(result.skipped) < 1000


@pytest.mark.parametrize("mutator", [boundary_cases, malformed_cases])
def test_deep_schema_and_base_are_bounded_without_recursion_errors(mutator):
    schema = {"type": "string"}
    for _ in range(1500):
        schema = {"type": "object", "properties": {"x": schema}}
    assert mutator(tool(schema), None, seed=0, mode="deep").notes
    base = {}
    for _ in range(1500):
        base = {"x": base}
    assert mutator(tool({}), base, seed=0, mode="deep").notes


def test_unresolved_refs_are_offline_and_validation_failures_are_not_malformed():
    result = malformed_cases(
        tool({"$ref": "https://offline.invalid/schema"}), {}, seed=0, mode="deep"
    )
    assert not result.cases
    assert any("ref" in n.lower() for n in result.notes)


def test_draft7_validation_ignores_ref_siblings():
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$ref": "#/definitions/any",
        "definitions": {"any": {}},
        "type": "object",
        "required": ["x"],
        "properties": {"x": {"type": "string"}},
    }
    result = malformed_cases(tool(schema), {"x": "ok"}, seed=0, mode="deep")
    assert not result.cases
    assert any("stayed valid" in n for n in result.notes)


@pytest.mark.parametrize("mutator", [boundary_cases, malformed_cases])
def test_candidate_inventory_has_exact_independent_counts(mutator):
    schema = {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
        "additionalProperties": False,
    }
    result = mutator(tool(schema), {"x": "ok"}, seed=1, mode="quick")
    # Six string rules; or three root values, one deletion, two swaps, and three stress rules.
    expected = 6 if mutator is boundary_cases else 9
    assert len(result.cases) + len(result.skipped) == expected


def test_float_exclusive_bounds_use_adjacent_representable_values():
    from math import nextafter

    result = boundary({"type": "number", "exclusiveMinimum": 1.5, "exclusiveMaximum": 3.5})
    assert values(result, "number-exclusive-minimum-inside") == [nextafter(1.5, float("inf"))]
    assert values(result, "number-exclusive-maximum-inside") == [nextafter(3.5, -float("inf"))]


def test_prefix_items_supply_per_position_boundary_values():
    result = boundary(
        {
            "type": "array",
            "prefixItems": [{"const": "tag"}, {"const": 7}],
            "items": {"const": False},
            "minItems": 3,
        }
    )
    assert values(result, "array-min-items") == [["tag", 7, False]]


def test_removing_conditional_trigger_is_dropped_when_it_stays_valid():
    schema = {
        "type": "object",
        "properties": {"x": {}, "y": {}},
        "if": {"required": ["x"]},
        "then": {"required": ["y"]},
    }
    result = malformed_cases(tool(schema), {"x": 1, "y": 2}, seed=0, mode="deep")
    # Only y is required in the active branch; optional x does not become a deletion rule.
    missing = [c.arguments for c in result.cases if c.rule == "missing-required"]
    assert missing == [{"x": 1}]


@pytest.mark.parametrize(
    "schema,expected",
    [
        (
            {
                "allOf": [
                    {"properties": {"x": {"type": "integer", "minimum": 2}}},
                    {"required": ["x"]},
                ]
            },
            {"x": 2},
        ),
        (
            {
                "properties": {"a": {"const": 1}, "b": {"const": 2}},
                "required": ["a"],
                "dependentRequired": {"a": ["b"]},
            },
            {"a": 1, "b": 2},
        ),
        (
            {
                "properties": {"a": {"const": 1}, "b": {"const": 2}},
                "dependentRequired": {"a": ["b"]},
            },
            {},
        ),
        (
            {
                "properties": {"kind": {"const": "a"}, "value": {"type": "integer"}},
                "required": ["kind"],
                "if": {"properties": {"kind": {"const": "a"}}},
                "then": {"required": ["value"], "properties": {"value": {"minimum": 4}}},
            },
            {"kind": "a", "value": 4},
        ),
        (
            {
                "oneOf": [
                    {"properties": {"x": {"const": 1}}, "required": ["x"]},
                    {"properties": {"y": {"const": 2}}, "required": ["y"]},
                ]
            },
            {"x": 1},
        ),
    ],
)
def test_fallback_base_handles_simple_composition(schema, expected):
    schema = {
        **schema,
        "type": "object",
        "properties": {**schema.get("properties", {}), "flag": {"type": "boolean"}},
    }
    result = boundary_cases(tool(schema), None, seed=1, mode="deep")
    case = next(c for c in result.cases if c.rule == "boolean-true")
    assert case.arguments == {**expected, "flag": True}
    assert not any("could not be verified valid" in n for n in result.notes)


@pytest.mark.parametrize("mutator", [boundary_cases, malformed_cases])
def test_nested_array_expansion_is_bounded(mutator):
    schema = {"type": "integer"}
    for _ in range(6):
        schema = {"type": "array", "items": schema, "minItems": 1000}
    result = mutator(
        tool({"type": "object", "properties": {"x": schema}, "required": ["x"]}),
        None,
        seed=0,
        mode="deep",
    )
    assert any("work limit" in n for n in result.notes)


def test_regex_validation_is_time_bounded_and_cannot_label_unknown_as_invalid():
    schema = {"type": "object", "properties": {"x": {"pattern": "^(a+)+$"}}}
    result = malformed_cases(tool(schema), {"x": "a" * 40 + "!"}, seed=0, mode="deep")
    assert not result.cases
    assert any("validation work limit" in n for n in result.notes)


def test_mapping_base_does_not_have_to_be_a_dict():
    from types import MappingProxyType

    base = MappingProxyType({"x": "ok"})
    assert boundary({"type": "string"}, base).cases
    assert dict(base) == {"x": "ok"}


def test_unrepresentable_exclusive_neighbors_are_skipped_with_a_note():
    result = boundary({"type": "number", "exclusiveMinimum": sys.float_info.max}, {"x": 1})
    assert values(result, "number-exclusive-minimum") == [sys.float_info.max]
    assert not values(result, "number-exclusive-minimum-inside")
    assert any("no finite adjacent value" in n for n in result.notes)


def test_huge_numeric_exclusive_bound_does_not_overflow_with_a_supplied_base():
    result = boundary({"type": "number", "exclusiveMinimum": 10**1000}, {"x": 1})
    assert result.cases
    assert any("no finite adjacent value" in n for n in result.notes)
