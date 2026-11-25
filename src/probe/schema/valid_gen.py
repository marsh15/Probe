"""Generate reproducible valid cases with an offline, killable per-tool budget."""

import hashlib
import json
import math
import multiprocessing
import re
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import Any, cast

from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import seed as hypothesis_seed
from hypothesis_jsonschema import from_schema
from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema_specifications import REGISTRY as STANDARD_RESOURCES
from referencing import Registry
from referencing.jsonschema import DRAFT7, DRAFT202012

from probe.config.profile import Profile
from probe.engine.outcomes import Mode, ToolInfo
from probe.schema.cases import Case
from probe.schema.dialect import Schema
from probe.schema.formats import format_values
from probe.schema.normalize import normalize
from probe.schema.refs import map_subschemas
from probe.util.canonical_json import canonical_bytes, canonical_json

_CAPS: dict[Mode, int] = {"quick": 4, "standard": 10, "deep": 25}
_WORKER_MODULES = [__name__]


@dataclass
class GeneratedValid:
    """Validated cases and diagnostics for approximations or fallback generation."""

    cases: list[Case] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class _Fixtures:
    roles: dict[str, str]
    roots: tuple[str, ...]
    ids: dict[str, Sequence[Any]]

    def values(self, name: str, schema: Mapping[str, Any]) -> list[Any]:
        return format_values(
            name, schema, role=self.roles.get(name), allowed_roots=self.roots, id_values=self.ids
        )


def _minimal(schema: Schema, fixtures: _Fixtures, name: str = "", depth: int = 0) -> Any:
    if isinstance(schema, bool) or depth > 32:
        return None
    for keyword in ("const", "enum", "default"):
        if keyword in schema:
            value = schema[keyword]
            if keyword == "enum":
                if not value:
                    return None
                value = value[0]
            return deepcopy(value)
    values = fixtures.values(name, schema)
    if values:
        return deepcopy(values[0])
    for keyword in ("oneOf", "anyOf"):
        if schema.get(keyword):
            base = _minimal(
                {k: v for k, v in schema.items() if k != keyword}, fixtures, name, depth + 1
            )
            candidates: list[Any] = []
            for branch_schema in schema[keyword][:4]:
                branch = _minimal(branch_schema, fixtures, name, depth + 1)
                value = (
                    {**base, **branch}
                    if isinstance(base, dict) and isinstance(branch, dict)
                    else branch
                )
                if Draft7Validator(schema).is_valid(value):
                    return value
                candidates.append(value)
            return candidates[0]
    if schema.get("allOf"):
        parts = [_minimal(part, fixtures, name, depth + 1) for part in schema["allOf"]]
        base = _minimal(
            {k: v for k, v in schema.items() if k != "allOf"}, fixtures, name, depth + 1
        )
        for part in parts:
            base = {**base, **part} if isinstance(base, dict) and isinstance(part, dict) else part
        return base
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = kind[0] if kind else None
    if kind == "object" or (kind is None and "properties" in schema):
        properties = schema.get("properties", {})
        required = list(dict.fromkeys(schema.get("required", [])))
        for key in properties:
            if len(required) >= min(schema.get("minProperties", 0), 100):
                break
            if key not in required:
                required.append(key)
        return {
            key: _minimal(properties.get(key, {}), fixtures, key, depth + 1)
            for key in required[:100]
        }
    if kind == "array":
        count = min(schema.get("minItems", 0), 100)
        items = schema.get("items", {})
        if isinstance(items, list):
            return [
                _minimal(
                    items[i] if i < len(items) else schema.get("additionalItems", {}),
                    fixtures,
                    depth=depth + 1,
                )
                for i in range(count)
            ]
        return [_minimal(items, fixtures, depth=depth + 1) for _ in range(count)]
    if kind == "string":
        length = min(schema.get("minLength", 0), 1024)
        options = ["" if not length else "a" * length, "a", "0", "x", "probe"]
        pattern = schema.get("pattern")
        return next(
            (value for value in options if not pattern or re.search(pattern, value)), options[0]
        )
    if kind in {"integer", "number"}:
        value = max(0, schema.get("minimum", 0))
        if "maximum" in schema:
            value = min(value, schema["maximum"])
        if "exclusiveMinimum" in schema:
            value = max(value, schema["exclusiveMinimum"] + 1)
        if "exclusiveMaximum" in schema:
            value = min(value, schema["exclusiveMaximum"] - 1)
        if schema.get("multipleOf", 0) > 0:
            value = math.ceil(value / schema["multipleOf"]) * schema["multipleOf"]
        return math.ceil(value) if kind == "integer" else value
    return False if kind == "boolean" else None


def _guards(schema: Schema) -> list[str]:
    notes: list[str] = []

    def visit(node: Schema, path: str) -> Schema:
        if isinstance(node, dict):
            pattern = node.get("pattern", "")
            if re.search(r"\([^)]*[*+][^)]*\)[*+{]", pattern):
                notes.append("nested regex quantifiers; used minimal values")
            if path.count("/oneOf/") + path.count("/anyOf/") > 8:
                notes.append("deep composition; used minimal values")
                return node
            return map_subschemas(node, path, visit)
        return node

    visit(schema, "")
    return list(dict.fromkeys(notes))


def _fixture_schema(schema: Schema, fixtures: _Fixtures) -> Schema:
    def constrain(node: Schema, values: list[Any]) -> Schema:
        valid = [value for value in values if Draft7Validator(node).is_valid(value)]
        return {"allOf": [node, {"enum": valid}]} if valid else node

    def visit(node: Schema, path: str) -> Schema:
        if isinstance(node, bool):
            return node
        result = map_subschemas(node, path, visit)
        for name, definition in result.get("properties", {}).items():
            if isinstance(definition, dict):
                result["properties"][name] = constrain(
                    definition, fixtures.values(name, definition)
                )
        return constrain(result, fixtures.values("", node))

    return visit(schema, "")


def _draw_candidates(schema: Schema, seed: int, count: int) -> list[Any]:
    values: list[Any] = []

    @hypothesis_seed(seed)
    @settings(
        database=None,
        derandomize=True,
        max_examples=count,
        phases=[Phase.generate],
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    @given(from_schema(schema))
    def draw(value: Any) -> None:
        values.append(value)

    draw()
    return values


def _branches(schema: Schema, notes: list[str]) -> list[tuple[str, Schema]]:
    location: str | None = None
    choices: list[Schema] = []

    def find(node: Schema, path: str) -> Schema:
        nonlocal location, choices
        if isinstance(node, bool) or location is not None:
            return node
        # Definitions and negated/conditional predicates are not input locations to force.
        if any(part in {"definitions", "$defs", "not", "if"} for part in path.split("/")):
            return node
        for keyword in ("oneOf", "anyOf"):
            if node.get(keyword):
                location, choices = path, node[keyword]
                if len(choices) > 4:
                    notes.append(f"{keyword}: sampled only the first 4 branches")
                return node
        return map_subschemas(node, path, find)

    find(schema, "")
    if location is None:
        return [("hypothesis", schema)]
    forced: list[tuple[str, Schema]] = []
    for index, branch in enumerate(choices[:4]):

        def force(node: Schema, path: str, branch: Schema = branch) -> Schema:
            if path == location:
                return {"allOf": [node, branch]}
            return map_subschemas(node, path, force) if isinstance(node, dict) else node

        forced.append((f"hypothesis-{index}", force(schema, "")))
    return forced


def _worker(
    connection: Connection,
    tool: ToolInfo,
    seed: int,
    mode: Mode,
    seeds: list[dict[str, Any]],
    fixtures: _Fixtures,
    draw: Callable[[Schema, int, int], list[Any]],
) -> None:
    result = GeneratedValid()
    seen: set[str] = set()
    indexes: Counter[str] = Counter()
    fallback: GeneratedValid | None = None
    try:
        tool = tool.model_copy(
            update={"input_schema": json.loads(canonical_json(tool.input_schema))}
        )
        prepared = normalize(tool.input_schema)
        result.notes.extend(prepared.dialect.notes)
        result.notes.extend(
            f"{note.kind} at {note.path}: {note.detail}" for note in prepared.approximations
        )
        specification = DRAFT7 if prepared.dialect.name == "draft-07" else DRAFT202012
        root = tool.input_schema.get("$id", "urn:probe:tool-schema")
        registry: Registry[Any] = (
            STANDARD_RESOURCES.combine(Registry())
            .with_resource(root, specification.create_resource(tool.input_schema))
            .crawl()
        )
        cls = Draft7Validator if prepared.dialect.name == "draft-07" else Draft202012Validator
        validator = cls(tool.input_schema, registry=registry)

        def add(rule: str, value: Any) -> None:
            if len(result.cases) >= _CAPS[mode]:
                return
            try:
                encoded = canonical_json(value)
                if encoded in seen:
                    return
                if not validator.is_valid(value):
                    result.notes.append(f"{rule}: invalid candidate dropped")
                    return
            except Exception as exc:
                result.notes.append(f"{rule}: validation failed ({type(exc).__name__})")
                return
            seen.add(encoded)
            result.cases.append(Case(tool.name, "valid", rule, indexes[rule], deepcopy(value)))
            indexes[rule] += 1

        for value in seeds:
            add("profile", value)
        profile_ids: dict[str, Sequence[Any]] = {}
        for case in result.cases:
            for name, value in case.arguments.items():
                if name.endswith("_id"):
                    profile_ids[name] = [*profile_ids.get(name, []), value]
        fixtures.ids = {**profile_ids, **fixtures.ids}
        for value in tool.input_schema.get("examples", []):
            add("example", value)
        if "default" in tool.input_schema:
            add("default", tool.input_schema["default"])
        minimal_schema = prepared.schema
        if isinstance(minimal_schema, dict):
            minimal_schema = {k: v for k, v in minimal_schema.items() if k != "default"}
        add("minimal", _minimal(minimal_schema, fixtures))
        fallback = deepcopy(result)
        connection.send((False, result))
        if len(result.cases) < _CAPS[mode]:
            guarded = _guards(prepared.schema)
            result.notes.extend(guarded)
            if not guarded:
                schema = _fixture_schema(prepared.schema, fixtures)
                branches = _branches(schema, result.notes)
                remaining = _CAPS[mode] - len(result.cases)
                for index, (rule, branch) in enumerate(branches):
                    count = remaining // len(branches) + (index < remaining % len(branches))
                    if count:
                        before = len(result.cases)
                        for value in draw(branch, seed + index, count + 1):
                            add(rule, value)
                            if len(result.cases) - before >= count:
                                break
    except Exception as exc:
        if fallback is not None:
            result = fallback
        result.notes.append(
            f"hypothesis generation failed ({type(exc).__name__}); used minimal values"
        )
    finally:
        result.notes = list(dict.fromkeys(result.notes))
        connection.send((True, result))
        connection.close()


def generate_valid(
    tool: ToolInfo,
    *,
    seed: int,
    mode: Mode,
    profile: Profile | None = None,
    allowed_roots: Sequence[str] = (),
    id_values: Mapping[str, Sequence[Any]] | None = None,
    time_budget_s: float = 5.0,
) -> GeneratedValid:
    """Generate in priority order; timed-out draws never contribute partial results.

    Validation also runs in the worker: a hostile regex can hold the GIL, so a thread cannot
    enforce this deadline. POSIX callers use a forkserver to avoid unsafe forks from hosts
    with Python or native threads; other platforms spawn. No global random state or
    Hypothesis database is used.
    """
    if not math.isfinite(time_budget_s) or time_budget_s <= 0:
        raise ValueError("time_budget_s must be positive and finite")
    seeds = deepcopy(profile.inputs.get(tool.name, [])) if profile is not None else []
    roots = tuple(allowed_roots)
    if not roots and profile is not None and profile.fixtures.fs is not None:
        roots = tuple(profile.fixtures.fs.allowed_roots)
    ids = dict(id_values or {})
    fixtures = _Fixtures(tool.param_roles, roots, ids)
    digest = hashlib.sha256(canonical_bytes([seed, tool.name, tool.input_schema, mode])).digest()
    fixed_seed = int.from_bytes(digest, "big")
    methods = multiprocessing.get_all_start_methods()
    context = (
        multiprocessing.get_context("forkserver")
        if "forkserver" in methods
        else multiprocessing.get_context("spawn")
    )
    if context.get_start_method() == "forkserver":
        context.set_forkserver_preload(_WORKER_MODULES)
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker, args=(writer, tool, fixed_seed, mode, seeds, fixtures, _draw_candidates)
    )
    result = GeneratedValid()
    started = time.monotonic()
    process.start()
    writer.close()
    finished = False
    crashed = False
    try:
        while (remaining := time_budget_s - (time.monotonic() - started)) > 0:
            if not reader.poll(remaining):
                break
            try:
                finished, received = reader.recv()
                result = cast(GeneratedValid, received)
            except EOFError:
                crashed = True
                break
            if finished:
                return result
        reason = "worker exited before finishing" if crashed else "draws timed out"
        result.notes.append(f"hypothesis {reason}; used validated fallback values")
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        process.close()
        reader.close()
