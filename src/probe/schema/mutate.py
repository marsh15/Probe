"""Bounded, deterministic boundary mutations and verified-invalid malformed inputs."""

import json
import subprocess
import sys
from collections import Counter, deque
from collections.abc import Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import islice
from math import ceil, floor, isfinite, nextafter
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry

from probe.engine.outcomes import Mode, ToolInfo
from probe.schema.cases import Case, CaseKind
from probe.schema.dialect import Schema, detect_dialect
from probe.schema.normalize import normalize

STRING_STRESS_BYTES = 64 * 1024
ARRAY_STRESS_ITEMS = 1000
PROPERTY_NAME_BYTES = 10 * 1024
NESTING_DEPTH = 64

_MAX_NODES = 4096
_MAX_DEPTH = 24
_MAX_PROPERTIES = 64
_MAX_ENUM = 128
_MAX_CANDIDATES = 512
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
_MAX_STRING_BYTES = 128 * 1024
_MAX_EXPANSION_WORK = 500_000
_VALIDATION_SECONDS = 2
_BOUNDARY_CAPS: dict[Mode, int] = {"quick": 2, "standard": 8, "deep": 20}
_MALFORMED_CAPS: dict[Mode, int] = {"quick": 2, "standard": 6, "deep": 15}


@dataclass
class MutationResult:
    """Selected cases, IDs omitted by the mode cap, and generation/filter diagnostics."""

    cases: list[Case] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class _Candidate:
    case: Case
    prop: str


def _size(value: Any, *, schema: bool = False) -> int:
    """Reject oversized/cyclic input before copying, encoding, or T20's recursive walks."""
    stack = [(value, 0)]
    nodes = size = refs = 0
    branches = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        size += 8
        if nodes > _MAX_NODES or depth > _MAX_DEPTH or size > _MAX_STRING_BYTES:
            raise ValueError("input exceeds node, depth, or byte work limit")
        if isinstance(node, Mapping):
            if len(node) > _MAX_NODES:
                raise ValueError("mapping exceeds work limit")
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ValueError("non-JSON mapping key")
                size += len(key.encode("utf-8", "surrogatepass"))
                if schema:
                    if key in {"$ref", "$dynamicRef"}:
                        refs += 1
                    if (
                        key == "properties"
                        and isinstance(child, dict)
                        and len(child) > _MAX_PROPERTIES
                    ):
                        raise ValueError("properties exceed work limit")
                    if key == "enum" and isinstance(child, list) and len(child) > _MAX_ENUM:
                        raise ValueError("enum exceeds work limit")
                    if key in {"oneOf", "anyOf", "allOf"} and isinstance(child, list):
                        branches += len(child)
                        if branches > 128:
                            raise ValueError("composition exceeds work limit")
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            if len(node) > _MAX_NODES:
                raise ValueError("list exceeds work limit")
            stack.extend((child, depth + 1) for child in node)
        elif isinstance(node, str):
            if len(node) > _MAX_STRING_BYTES:
                raise ValueError("string exceeds work limit")
            size += len(node.encode("utf-8", "surrogatepass"))
        elif isinstance(node, int) and node.bit_length() > 4096:
            raise ValueError("integer exceeds work limit")
        elif isinstance(node, float) and not isfinite(node):
            raise ValueError("non-finite JSON number")
        elif node is not None and not isinstance(node, int | float | bool):
            raise ValueError("non-JSON value")
    if schema and nodes * (refs + 1) ** 3 > _MAX_EXPANSION_WORK:
        raise ValueError("reference expansion exceeds work limit")
    if size > _MAX_STRING_BYTES:
        raise ValueError("input exceeds byte work limit")
    return size


def _facets(schema: Schema) -> Iterator[dict[str, Any]]:
    """Expose constraints from compositions without pretending branches are equivalent."""
    if not isinstance(schema, dict):
        return
    yield schema
    for keyword in ("allOf", "anyOf", "oneOf"):
        for child in schema.get(keyword, []):
            yield from _facets(child)
    for keyword in ("then", "else"):
        yield from _facets(schema.get(keyword, True))
    for child in schema.get("dependencies", {}).values():
        if isinstance(child, dict):
            yield from _facets(child)


def _properties(schema: Schema) -> dict[str, Schema]:
    groups: dict[str, list[Schema]] = {}
    for facet in _facets(schema):
        for name, child in facet.get("properties", {}).items():
            groups.setdefault(name, []).append(child)
    return {
        name: parts[0] if len(parts) == 1 else {"allOf": parts}
        for name, parts in sorted(groups.items())
    }


def _required(schema: Schema) -> set[str]:
    names: set[str] = set()
    for facet in _facets(schema):
        names.update(facet.get("required", []))
        for child in facet.get("dependencies", {}).values():
            if isinstance(child, list):
                names.update(child)
    return names


def _types(schema: Schema) -> set[str]:
    types: set[str] = set()
    for facet in _facets(schema):
        declared = facet.get("type", [])
        types.update([declared] if isinstance(declared, str) else declared)
        for kind, keywords in (
            ("string", ("minLength", "maxLength", "pattern")),
            ("number", ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")),
            ("array", ("items", "minItems", "maxItems")),
            ("object", ("properties", "required")),
        ):
            if any(key in facet for key in keywords):
                types.add(kind)
    return types


def _length(value: Any, maximum: int, notes: list[str], rule: str) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum:
        return value
    notes.append(f"Skipped {rule}: size exceeds work limit or is not a nonnegative integer.")
    return None


def _base_facets(schema: Schema) -> Iterator[dict[str, Any]]:
    if not isinstance(schema, dict):
        return
    yield {
        k: v
        for k, v in schema.items()
        if k not in {"allOf", "anyOf", "oneOf", "then", "else", "dependencies"}
    }
    for child in schema.get("allOf", []):
        yield from _base_facets(child)
    for keyword in ("anyOf", "oneOf"):
        branches = schema.get(keyword, [])
        if branches:
            yield from _base_facets(branches[0])


def _minimal_object(schema: Schema, notes: list[str], depth: int) -> dict[str, Any]:
    facets = list(_base_facets(schema))
    result: dict[str, Any] = {}
    # Dependency chains may add triggers; close them within a small, explicit budget.
    active: set[str] = set()
    for _ in range(8):
        merged = {"allOf": facets}
        props = _properties(merged)
        for name in sorted(_required(merged)):
            result[name] = _minimal(props.get(name, {}), notes, depth + 1)
        additions: list[Schema] = []
        for facet in _facets(schema):
            condition = json.dumps(facet.get("if", True))
            expensive = ("pattern", "patternProperties", "oneOf", "anyOf", "allOf", "uniqueItems")
            if "if" in facet and any(f'"{key}"' in condition for key in expensive):
                notes.append("Complex conditional omitted from simple base; supply a valid base.")
            elif "if" in facet:
                key = (
                    "then"
                    if Draft7Validator(facet["if"], registry=Registry()).is_valid(result)
                    else "else"
                )
                if key in facet:
                    additions.append(facet[key])
            for trigger, dependency in facet.get("dependencies", {}).items():
                if trigger in result:
                    additions.append(
                        {"required": dependency} if isinstance(dependency, list) else dependency
                    )
        changed = False
        for addition in additions:
            identity = json.dumps(addition, sort_keys=True)
            if identity not in active:
                active.add(identity)
                facets.extend(_base_facets(addition))
                changed = True
        if not changed:
            return result
    notes.append("Minimal base dependency work limit reached.")
    return result


def _minimal(schema: Schema, notes: list[str], depth: int = 0) -> Any:
    if depth >= 8:
        notes.append("Minimal base depth work limit reached.")
        return None
    facets = list(_base_facets(schema))
    selected: Schema = {"allOf": facets}
    for key in ("const", "enum", "default"):
        for facet in facets:
            if key in facet:
                value = facet[key]
                if key == "enum":
                    if not value:
                        continue
                    value = value[0]
                return deepcopy(value)
    kinds = _types(selected)
    if "object" in kinds or _properties(selected):
        return _minimal_object(schema, notes, depth)
    if "string" in kinds:
        minimum = max((f.get("minLength", 0) for f in facets), default=0)
        length = _length(minimum, STRING_STRESS_BYTES, notes, "minimal-string")
        return "a" * (length or 0)
    if kinds.intersection({"number", "integer"}):
        lower = max((f.get("minimum", -float("inf")) for f in facets), default=-float("inf"))
        upper = min((f.get("maximum", float("inf")) for f in facets), default=float("inf"))
        for facet in facets:
            if "exclusiveMinimum" in facet:
                bound = facet["exclusiveMinimum"]
                lower = max(
                    lower,
                    floor(bound) + 1 if "integer" in kinds else nextafter(bound, float("inf")),
                )
            if "exclusiveMaximum" in facet:
                bound = facet["exclusiveMaximum"]
                upper = min(
                    upper,
                    ceil(bound) - 1 if "integer" in kinds else nextafter(bound, -float("inf")),
                )
        value = min(max(0, lower), upper)
        if not isfinite(value):
            notes.append("Minimal number has no finite simple value.")
            return 0
        return (
            (floor(value) if value <= upper and value < 0 else ceil(value))
            if "integer" in kinds
            else value
        )
    if "array" in kinds:
        minimum = max((f.get("minItems", 0) for f in facets), default=0)
        length = _length(minimum, ARRAY_STRESS_ITEMS, notes, "minimal-array")
        return _array(selected, length or 0, notes, depth) or []
    if "boolean" in kinds:
        return False
    return None


def _array(schema: Schema, length: int, notes: list[str], depth: int = 0) -> list[Any] | None:
    facets = list(_facets(schema))
    items: Any = next((f["items"] for f in facets if "items" in f), {})
    tail: Any = next((f.get("additionalItems", {}) for f in facets if "items" in f), {})
    result = []
    spent = 0
    common = _minimal(items, notes, depth + 1) if not isinstance(items, list) else None
    try:
        for index in range(length):
            value = (
                _minimal(items[index] if index < len(items) else tail, notes, depth + 1)
                if isinstance(items, list)
                else common
            )
            spent += _size(value)
            if spent > _MAX_STRING_BYTES:
                raise ValueError("array payload exceeds work limit")
            result.append(deepcopy(value))
    except ValueError:
        notes.append("Skipped array construction: payload exceeds work limit.")
        return None
    return result


def _string_rules(schema: Schema, notes: list[str]) -> Iterator[tuple[str, Any]]:
    yield "string-empty", ""
    for facet in _facets(schema):
        for key, suffix, offsets in (
            ("minLength", "min-length", [(0, ""), (-1, "-minus-one")]),
            ("maxLength", "max-length", [(0, ""), (1, "-plus-one")]),
        ):
            if key not in facet:
                continue
            for offset, label in offsets:
                size = facet[key] + offset
                if size < 0:
                    continue
                rule = f"string-{suffix}{label}"
                length = _length(size, STRING_STRESS_BYTES, notes, rule)
                if length is not None:
                    yield rule, "a" * length
    yield "string-large", "a" * STRING_STRESS_BYTES
    for name, value in (
        ("emoji", "😀"),
        ("rtl", "\u202e"),
        ("combining", "e\u0301"),
        ("nul", "\0"),
    ):
        yield f"string-unicode-{name}", value


def _number_rules(schema: Schema, notes: list[str]) -> Iterator[tuple[str, Any]]:
    integer = "integer" in _types(schema)
    for facet in _facets(schema):
        for key, suffix, offset, label in (
            ("minimum", "minimum", -1, "minus-one"),
            ("maximum", "maximum", 1, "plus-one"),
            ("exclusiveMinimum", "exclusive-minimum", 1, "inside"),
            ("exclusiveMaximum", "exclusive-maximum", -1, "inside"),
        ):
            if key not in facet:
                continue
            value = facet[key]
            yield f"number-{suffix}", value
            try:
                if key.startswith("exclusive"):
                    adjacent = (
                        (floor(value) + 1 if offset > 0 else ceil(value) - 1)
                        if integer
                        else nextafter(value, float("inf") if offset > 0 else -float("inf"))
                    )
                else:
                    adjacent = value + offset
                if isinstance(adjacent, float) and not isfinite(adjacent):
                    raise OverflowError
            except OverflowError:
                notes.append(f"Skipped number-{suffix}-{label}: no finite adjacent value.")
                continue
            yield f"number-{suffix}-{label}", adjacent

    yield from (
        ("number-zero", 0),
        ("number-negative-one", -1),
        ("number-unsafe-integer", 2**53 + 1),
        ("number-min-int64", -(2**63)),
        ("number-large", 1e308),
    )


def _boundary_values(schema: Schema, notes: list[str]) -> Iterator[tuple[str, Any]]:
    kinds = _types(schema)
    if "string" in kinds:
        yield from _string_rules(schema, notes)
    if kinds.intersection({"integer", "number"}):
        yield from _number_rules(schema, notes)
    if "array" in kinds:
        yield "array-empty", []
        for facet in _facets(schema):
            for key, rule, offset in (
                ("minItems", "array-min-items", 0),
                ("maxItems", "array-max-items-plus-one", 1),
            ):
                if key in facet:
                    length = _length(facet[key] + offset, ARRAY_STRESS_ITEMS, notes, rule)
                    if length is not None:
                        value = _array(schema, length, notes)
                        if value is not None:
                            yield rule, value
        value = _array(schema, ARRAY_STRESS_ITEMS, notes)
        if value is not None:
            yield "array-large", value
    if "boolean" in kinds:
        yield "boolean-false", False
        yield "boolean-true", True
    for facet in _facets(schema):
        if "enum" in facet:
            members = facet["enum"]
            for member in members:
                yield "enum-member", member
            # More distinct strings than enum members guarantees an outsider, including
            # enums containing JSON booleans/numbers which Python considers equal.
            for index in range(len(members) + 1):
                outsider = f"probe-non-member-{index}"
                if outsider not in members:
                    yield "enum-non-member", outsider
                    break


def _boundary_mutations(
    schema: Schema, base: dict[str, Any], notes: list[str]
) -> Iterator[tuple[str, str, Any]]:
    pending = deque(
        (prop, iter(_boundary_values(child, notes))) for prop, child in _properties(schema).items()
    )
    while pending:
        prop, values = pending.popleft()
        try:
            rule, value = next(values)
        except StopIteration:
            continue
        yield rule, prop, {**base, prop: value}
        pending.append((prop, values))


def _malformed_values(schema: Schema, base: dict[str, Any]) -> Iterator[tuple[str, str, Any]]:
    value: Any
    for value in ([], "x", None):
        yield "root-not-object", "", value
    for prop in sorted(_required(schema)):
        if prop in base:
            yield "missing-required", prop, {k: v for k, v in base.items() if k != prop}
    for prop, child in _properties(schema).items():
        value = base[prop] if prop in base else _minimal(child, [])
        replacement: Any = "x"
        if isinstance(value, str):
            replacement = 0
        elif isinstance(value, bool | int | float):
            replacement = "x"
        elif isinstance(value, dict):
            replacement = []
        elif isinstance(value, list):
            replacement = {}
        yield "type-swap", prop, {**base, prop: replacement}
        yield "type-null", prop, {**base, prop: None}
    if any(f.get("additionalProperties") is False for f in _facets(schema)):
        name = _unknown_name(schema, base)
        yield "extra-property", "", {**base, name: None}
    nested: Any = None
    for _ in range(NESTING_DEPTH - 1):
        nested = {"child": nested}
    yield "nesting-64", "", {**base, _unknown_name(schema, base): nested}
    name = "p" * PROPERTY_NAME_BYTES
    names = set(base) | _properties(schema).keys()
    for index in range(len(names) + 1):
        name = str(index).zfill(PROPERTY_NAME_BYTES)
        if name not in names:
            break
    yield "huge-property-name", "", {**base, name: None}


def _unknown_name(schema: Schema, base: dict[str, Any]) -> str:
    names = set(_properties(schema)) | base.keys()
    index = 0
    while f"probe-extra-{index}" in names:
        index += 1
    return f"probe-extra-{index}"


def _validation_results(schema: dict[str, Any], values: list[Any]) -> list[str]:
    """Return invalid/valid/unknown using the original dialect and an offline registry."""
    cls = Draft7Validator if detect_dialect(schema).name == "draft-07" else Draft202012Validator
    validator = cls(schema, registry=Registry())
    results = []
    for value in values:
        try:
            results.append("valid" if validator.is_valid(value) else "invalid")
        except Exception as exc:  # Broken refs/schemas are not evidence of an invalid input.
            results.append(f"unknown ({type(exc).__name__})")
    return results


def _validate(schema: dict[str, Any], candidates: list[_Candidate], notes: list[str]) -> list[str]:
    values = [c.case.arguments for c in candidates]
    # Regex and composition execution cannot be bounded by counting schema nodes.
    # Isolate expensive validation; this worker only reads JSON and never fetches refs.
    encoded = json.dumps(schema, sort_keys=True)
    expensive = ("pattern", "patternProperties", "oneOf", "anyOf", "allOf", "uniqueItems")
    if not any(f'"{key}"' in encoded for key in expensive):
        return _validation_results(schema, values)
    script = (
        "import json,sys; from probe.schema.mutate import _validation_results; "
        "s,v=json.load(sys.stdin); print(json.dumps(_validation_results(s,v)))"
    )
    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter and code; data only on stdin
            [sys.executable, "-c", script],
            input=json.dumps([schema, values]),
            capture_output=True,
            text=True,
            timeout=_VALIDATION_SECONDS,
            check=True,
        )
        statuses: list[str] = json.loads(result.stdout)
        return statuses
    except (subprocess.SubprocessError, ValueError):
        notes.append("Original validation exceeded isolated regex work limit or failed.")
        return ["unknown (validation work limit)"] * len(candidates)


def _sample(candidates: list[_Candidate], cap: int, salt: str, notes: list[str]) -> MutationResult:
    ordered = sorted(candidates, key=lambda c: sha256(f"{salt}:{c.case.id}".encode()).digest())
    rules: Counter[str] = Counter()
    props: Counter[str] = Counter()
    sampled: list[Case] = []
    # Give each rule a turn, choosing a least-used property within that turn. IDs are
    # assigned before sampling so all modes partition the same candidate inventory.
    while ordered and len(sampled) < cap:
        candidate = min(ordered, key=lambda c: (rules[c.case.rule], props[c.prop]))
        ordered.remove(candidate)
        sampled.append(candidate.case)
        rules[candidate.case.rule] += 1
        props[candidate.prop] += 1
    return MutationResult(sampled, [c.case.id for c in ordered], notes)


def _mutate(
    tool: ToolInfo, base: Mapping[str, Any] | None, seed: int, mode: Mode, kind: CaseKind
) -> MutationResult:
    notes: list[str] = []
    try:
        _size(tool.input_schema, schema=True)
        if base is not None:
            _size(base)
        prepared = normalize(tool.input_schema)
        _size(prepared.schema, schema=True)
        notes.extend(prepared.dialect.notes)
        notes.extend(f"{a.kind} {a.path}: {a.detail}" for a in prepared.approximations)
        schema = prepared.schema
        minimal = _minimal(schema, notes) if base is None else dict(base)
        if not isinstance(minimal, dict):
            minimal = {}
            notes.append("Minimal root is not an object; using an empty arguments object.")
        _size(minimal)
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        return MutationResult(notes=[f"Schema/base preparation work limit or failure: {exc}"])
    if base is None:
        status = _validate(
            tool.input_schema, [_Candidate(Case(tool.name, kind, "base", 0, minimal), "")], notes
        )[0]
        if status != "valid":
            notes.append(
                f"Minimal base could not be verified valid: {status}; supply a valid base."
            )
    candidates: list[_Candidate] = []
    indices: Counter[str] = Counter()
    seen: set[tuple[str, str, str]] = set()
    spent = 0
    mutations: Iterator[tuple[str, str, Any]]
    if kind == "boundary":
        mutations = _boundary_mutations(schema, minimal, notes)
    else:
        mutations = _malformed_values(schema, minimal)
    for position, (rule, prop, arguments) in enumerate(islice(mutations, _MAX_CANDIDATES + 1)):
        if position == _MAX_CANDIDATES:
            notes.append("Candidate count work limit reached; remaining rules not expanded.")
            break
        encoded = json.dumps(arguments, sort_keys=True, ensure_ascii=True)
        identity = (rule, prop, encoded)
        if identity in seen:
            continue
        if len(candidates) >= _MAX_CANDIDATES or spent + len(encoded) > _MAX_PAYLOAD_BYTES:
            notes.append("Candidate count/byte work limit reached; remaining rules not expanded.")
            break
        seen.add(identity)
        index = indices[rule]
        indices[rule] += 1
        spent += len(encoded)
        candidates.append(_Candidate(Case(tool.name, kind, rule, index, deepcopy(arguments)), prop))
    if kind == "malformed":
        statuses = _validate(tool.input_schema, candidates, notes)
        retained = []
        for candidate, status in zip(candidates, statuses, strict=True):
            if status == "invalid":
                retained.append(candidate)
            else:
                reason = "stayed valid" if status == "valid" else status
                notes.append(f"Dropped {candidate.case.id}: {reason} under original schema.")
        candidates = retained
    digest = sha256(json.dumps(tool.input_schema, sort_keys=True).encode()).hexdigest()
    salt = f"{seed}:{tool.name}:{digest}:{mode}"
    cap = (_BOUNDARY_CAPS if kind == "boundary" else _MALFORMED_CAPS)[mode]
    return _sample(candidates, cap, salt, list(dict.fromkeys(notes)))


def boundary_cases(
    tool: ToolInfo, base: Mapping[str, Any] | None, *, seed: int, mode: Mode
) -> MutationResult:
    """Mutate property constraints; boundary cases may be accepted or rejected cleanly."""
    return _mutate(tool, base, seed, mode, "boundary")


def malformed_cases(
    tool: ToolInfo, base: Mapping[str, Any] | None, *, seed: int, mode: Mode
) -> MutationResult:
    """Return only mutations proven invalid under the original, offline schema."""
    return _mutate(tool, base, seed, mode, "malformed")
