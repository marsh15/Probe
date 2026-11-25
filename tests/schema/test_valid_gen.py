"""Deterministic valid inputs, original-schema validation, and hard tool budgets."""

import json
import multiprocessing
import os
import subprocess
import sys
import threading
import time
import warnings
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, Draft202012Validator

from probe.classify.tools import classify_tool
from probe.config.profile import Profile
from probe.schema import valid_gen
from probe.schema.dialect import detect_dialect
from probe.schema.valid_gen import generate_valid
from probe.util.canonical_json import canonical_json

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "schemas"
PATHOLOGICAL = {
    "type": "object",
    "properties": {"s": {"type": "string", "pattern": "^(a+)+$"}},
    "required": ["s"],
}


@pytest.fixture(scope="module", autouse=True)
def preload_draw_helpers():
    # Injected draws must already be imported when measuring a 100 ms draw budget.
    previous = valid_gen._WORKER_MODULES
    valid_gen._WORKER_MODULES = [valid_gen.__name__, __name__]
    try:
        warm = generate_valid(classify_tool("warm", {"type": "object"}), seed=1, mode="quick")
        assert warm.cases
        yield
    finally:
        valid_gen._WORKER_MODULES = previous


def validator(schema):
    cls = Draft7Validator if detect_dialect(schema).name == "draft-07" else Draft202012Validator
    return cls(schema)


def check_cases(tool, result, cap):
    assert 0 < len(result.cases) <= cap
    assert all(case.tool == tool.name and case.kind == "valid" for case in result.cases)
    assert all(validator(tool.input_schema).is_valid(case.arguments) for case in result.cases)
    assert len({canonical_json(case.arguments) for case in result.cases}) == len(result.cases)
    assert len({case.id for case in result.cases}) == len(result.cases)


def test_sixty_fixtures_are_byte_identical_across_processes_and_vary_with_seed():
    script = Path(__file__).with_name("valid_gen_process.py")
    outputs = [
        subprocess.run(  # noqa: S603 - fixed local test helper, no shell
            [sys.executable, str(script), str(seed)],
            check=True,
            capture_output=True,
            timeout=40,
        ).stdout
        for seed in (23, 23, 24)
    ]
    assert outputs[0] == outputs[1]
    first, other = json.loads(outputs[0]), json.loads(outputs[2])
    paths = sorted(FIXTURES.glob("*.json"))
    assert len(paths) == len(first) == len(other) == 60
    changed = 0
    for path in paths:
        schema = json.loads(path.read_text())
        cases = first[path.stem]
        assert 0 < len(cases) <= 4, path.stem
        assert all(validator(schema).is_valid(args) for _, args in cases), path.stem
        assert len({canonical_json(args) for _, args in cases}) == len(cases)
        assert len({identity for identity, _ in cases}) == len(cases)
        changed += cases != other[path.stem]
    assert changed >= 40


@pytest.mark.parametrize(("mode", "cap"), [("quick", 4), ("standard", 10), ("deep", 25)])
def test_caps_validation_deduplication_and_no_input_mutation(mode, cap):
    tool = classify_tool(
        "demo",
        {
            "type": "object",
            "properties": {"n": {"type": "integer"}},
            "required": ["n"],
            "additionalProperties": False,
            "examples": [{"n": 1}, {"n": "bad"}, {"n": 1}],
            "default": {"n": 2},
        },
    )
    original = deepcopy(tool)
    result = generate_valid(tool, seed=13, mode=mode)
    check_cases(tool, result, cap)
    assert len(result.cases) == cap
    assert tool == original
    assert [(case.rule, case.arguments) for case in result.cases[:3]] == [
        ("example", {"n": 1}),
        ("default", {"n": 2}),
        ("minimal", {"n": 0}),
    ]


def test_profile_seeds_come_first_are_validated_and_supply_ids():
    schema = {
        "type": "object",
        "properties": {"user_id": {"type": "integer"}},
        "required": ["user_id"],
        "additionalProperties": False,
        "examples": [{"user_id": 8}],
    }
    tool = classify_tool("users", schema)
    profile = Profile(inputs={"users": [{"user_id": "bad"}, {"user_id": 7}, {"user_id": 7}]})
    result = generate_valid(tool, seed=1, mode="quick", profile=profile)
    check_cases(tool, result, 4)
    assert result.cases[0].rule == "profile"
    assert result.cases[0].arguments == {"user_id": 7}
    assert result.cases[1].rule == "example"
    assert any("profile" in note and "invalid" in note for note in result.notes)
    assert not any(case.rule == "minimal" for case in result.cases)  # same known id deduped


def test_fixture_formats_reach_minimal_values():
    properties = {name: {"type": "string"} for name in ("url", "path", "user_id", "email", "at")}
    properties["email"]["format"] = "email"
    properties["at"]["format"] = "date-time"
    tool = classify_tool(
        "fetch_user",
        {
            "type": "object",
            "properties": properties,
            "required": list(properties),
        },
    )
    result = generate_valid(
        tool, seed=1, mode="quick", allowed_roots=["/data"], id_values={"user_id": ["u1"]}
    )
    assert result.cases[0].arguments == {
        "url": "http://public.probe.test/hello.txt",
        "path": "/data/hello.txt",
        "user_id": "u1",
        "email": "probe@example.test",
        "at": "2026-01-01T00:00:00Z",
    }
    check_cases(tool, result, 4)


def test_path_roots_can_come_from_profile():
    tool = classify_tool(
        "read",
        {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    profile = Profile.model_validate(
        {"fixtures": {"fs": {"seed_dir": ".", "allowed_roots": ["/data"]}}}
    )
    result = generate_valid(tool, seed=1, mode="quick", profile=profile)
    assert result.cases[0].arguments == {"path": "/data/hello.txt"}


def test_pathological_regex_default_budget_finishes_with_minimal_and_note():
    tool = classify_tool("regex", PATHOLOGICAL)
    started = time.monotonic()
    result = generate_valid(tool, seed=1, mode="standard")
    assert time.monotonic() - started < 6
    check_cases(tool, result, 10)
    assert any(case.rule == "minimal" for case in result.cases)
    assert result.notes


def test_deep_composition_is_bounded_and_keeps_minimal():
    schema = {"type": "object"}
    for index in range(18):
        schema = {"oneOf" if index % 2 else "anyOf": [schema, {"type": "null"}]}
    tool = classify_tool("composition", schema)
    started = time.monotonic()
    result = generate_valid(tool, seed=1, mode="quick", time_budget_s=0.3)
    assert time.monotonic() - started < 1.3
    check_cases(tool, result, 4)
    assert any(case.rule == "minimal" for case in result.cases)
    assert result.notes


def stuck_draw(*args, **kwargs):
    time.sleep(30)


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="fork injection")
# 0.5 s, not less: the worker computes the minimal fallback itself (a hostile regex can hold
# the GIL), and forkserver start-up alone can exceed 0.1 s on a loaded CI runner.
@pytest.mark.parametrize("budget", [0.5, 5.0])
def test_stuck_draw_is_killed_and_partial_draws_are_discarded(monkeypatch, budget):
    monkeypatch.setattr(valid_gen, "_draw_candidates", stuck_draw)
    tool = classify_tool("stuck", {"type": "object"})
    before = {process.pid for process in multiprocessing.active_children()}
    started = time.monotonic()
    result = generate_valid(tool, seed=1, mode="quick", time_budget_s=budget)
    assert time.monotonic() - started < budget + 1
    assert [(case.rule, case.arguments) for case in result.cases] == [("minimal", {})]
    assert any("timed out" in note for note in result.notes)
    assert {process.pid for process in multiprocessing.active_children()} == before


def fail_draw(*args, **kwargs):
    raise RuntimeError("deliberate failure")


def test_hypothesis_failure_keeps_valid_fallbacks(monkeypatch):
    monkeypatch.setattr(valid_gen, "_draw_candidates", fail_draw)
    result = generate_valid(classify_tool("fail", {"type": "object"}), seed=1, mode="quick")
    assert result.cases[0].arguments == {}
    assert any("failed" in note for note in result.notes)


@pytest.mark.parametrize("keyword", ["oneOf", "anyOf"])
def test_composition_draws_cover_up_to_four_branches_evenly(keyword):
    branches = [{"type": "integer", "minimum": i * 100, "maximum": i * 100 + 99} for i in range(6)]
    tool = classify_tool("branches", {keyword: branches})
    result = generate_valid(tool, seed=42, mode="deep")
    check_cases(tool, result, 25)
    counts = [sum(case.rule == f"hypothesis-{i}" for case in result.cases) for i in range(4)]
    assert min(counts) >= 5
    assert max(counts) - min(counts) <= 1
    assert any("4 branches" in note for note in result.notes)


def test_not_original_dialect_and_unresolved_refs_are_validated_offline():
    for schema in (
        {"type": "integer", "not": {"const": 0}},
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "const": {"x": 1},
            "$ref": "#/definitions/value",
            "definitions": {"value": {"const": {"x": 2}}},
        },
        {"type": "array", "prefixItems": [{"const": 1}], "items": False, "minItems": 1},
    ):
        tool = classify_tool("original", schema)
        check_cases(tool, generate_valid(tool, seed=1, mode="quick"), 4)
    unresolved = classify_tool("offline", {"$ref": "https://unavailable.probe.test/schema"})
    result = generate_valid(unresolved, seed=1, mode="quick")
    assert not result.cases
    assert any("ref_remote" in note for note in result.notes)
    assert any("validation" in note for note in result.notes)


def test_unsatisfiable_schema_has_no_cases_and_explains_failure():
    result = generate_valid(classify_tool("empty", {"not": {}}), seed=1, mode="quick")
    assert not result.cases
    assert result.notes


def test_nested_formats_and_array_formats_use_fixed_values_for_draws():
    schema = {
        "type": "object",
        "properties": {
            "rows": {
                "type": "array",
                "minItems": 1,
                "maxItems": 3,
                "items": {"type": "string", "format": "email"},
            },
        },
        "required": ["rows"],
        "additionalProperties": False,
    }
    result = generate_valid(classify_tool("mail", schema), seed=9, mode="quick")
    assert result.cases
    assert any(case.rule == "hypothesis" for case in result.cases)
    assert all(
        value == "probe@example.test" for case in result.cases for value in case.arguments["rows"]
    )


def test_nested_composition_draws_cover_each_selected_branch():
    schema = {
        "type": "object",
        "required": ["choice"],
        "additionalProperties": False,
        "properties": {
            "choice": {
                "oneOf": [
                    {"type": "integer", "minimum": 100 * i, "maximum": 100 * i + 99}
                    for i in range(4)
                ]
            }
        },
    }
    result = generate_valid(classify_tool("nested", schema), seed=42, mode="deep")
    check_cases(classify_tool("nested", schema), result, 25)
    assert all(sum(case.rule == f"hypothesis-{i}" for case in result.cases) >= 5 for i in range(4))


class FailSecondDraw:
    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return [1, 2]
        raise RuntimeError("second branch fails")


def test_failure_in_later_branch_discards_all_draws(monkeypatch):
    monkeypatch.setattr(valid_gen, "_draw_candidates", FailSecondDraw())
    tool = classify_tool("atomic", {"oneOf": [{"type": "integer"}, {"type": "string"}]})
    result = generate_valid(tool, seed=1, mode="quick")
    assert [(case.rule, case.arguments) for case in result.cases] == [("minimal", 0)]
    assert any("failed" in note for note in result.notes)


def test_minimal_skips_unsatisfiable_union_branches():
    tool = classify_tool("union", {"anyOf": [False, {"const": {"ok": True}}]})
    result = generate_valid(tool, seed=1, mode="quick")
    assert result.cases[0].rule == "minimal"
    assert result.cases[0].arguments == {"ok": True}


def crashing_draw(*args, **kwargs):
    os._exit(3)


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="fork injection")
def test_a_worker_crash_is_not_reported_as_a_draw_timeout(monkeypatch):
    monkeypatch.setattr(valid_gen, "_draw_candidates", crashing_draw)
    tool = classify_tool("crash", {"type": "object"})
    result = generate_valid(tool, seed=1, mode="quick", time_budget_s=5.0)
    assert [(case.rule, case.arguments) for case in result.cases] == [("minimal", {})]
    assert any("worker exited" in note for note in result.notes)
    assert not any("timed out" in note for note in result.notes)


@pytest.mark.skipif("forkserver" not in multiprocessing.get_all_start_methods(), reason="POSIX")
def test_threaded_caller_uses_forkserver_and_keeps_deadline(monkeypatch):
    stop = threading.Event()
    background = threading.Thread(target=stop.wait)
    background.start()
    try:
        warm = generate_valid(classify_tool("warm", {"type": "object"}), seed=1, mode="quick")
        assert warm.cases
        monkeypatch.setattr(valid_gen, "_draw_candidates", stuck_draw)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            started = time.monotonic()
            result = generate_valid(
                classify_tool("threaded", {"type": "object"}),
                seed=1,
                mode="quick",
                time_budget_s=0.1,
            )
    finally:
        stop.set()
        background.join()
    assert not any("multi-threaded" in str(warning.message) for warning in captured)
    assert time.monotonic() - started < 1.1
    assert result.cases[0].arguments == {}
    assert any("timed out" in note for note in result.notes)


def test_equivalent_schema_key_orders_give_identical_cases():
    branch = {"oneOf": [{"type": "integer"}, {"type": "string"}]}
    schema = {
        "type": "object",
        "properties": {"a": branch, "b": branch},
        "required": ["a", "b"],
        "additionalProperties": False,
    }
    reordered = dict(reversed(list(schema.items())))
    reordered["properties"] = {"b": branch, "a": branch}
    outputs = []
    for candidate in (schema, reordered):
        result = generate_valid(classify_tool("ordered", candidate), seed=17, mode="standard")
        outputs.append(canonical_json([[case.id, case.arguments] for case in result.cases]))
    assert outputs[0] == outputs[1]
