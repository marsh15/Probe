"""Inline document-local references offline with a bounded reference depth."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from referencing import Registry
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7, DRAFT202012

from probe.schema.dialect import Schema, detect_dialect
from probe.schema.jsonschema_tools import find_refs, ref_problems

_SCHEMA_MAPS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)
_SCHEMA_ARRAYS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
_SCHEMA_VALUES = frozenset(
    {
        "additionalProperties",
        "additionalItems",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "unevaluatedProperties",
        "unevaluatedItems",
        "contentSchema",
    }
)
_ROOT_URI = "urn:probe:tool-schema"
_REMOTE_SCHEMES = frozenset({"http", "https", "file", "ftp"})


@dataclass(frozen=True)
class Approximation:
    """A generation-only change; paths are JSON pointers in the expanded schema."""

    kind: str
    path: str
    detail: str


@dataclass(frozen=True)
class RefResult:
    """Expanded schema, unique unresolved refs, and per-occurrence approximations."""

    schema: Schema
    problems: tuple[tuple[str, str], ...] = ()
    approximations: tuple[Approximation, ...] = ()


def pointer_child(path: str, key: str | int) -> str:
    """Append an escaped JSON pointer token."""
    return f"{path}/{str(key).replace('~', '~0').replace('/', '~1')}"


def map_subschemas(
    schema: dict[str, Any], path: str, transform: Callable[[Schema, str], Schema]
) -> dict[str, Any]:
    """Copy a schema, transforming only schema positions, never instance data or annotations."""
    result = deepcopy(schema)
    for key, value in schema.items():
        location = pointer_child(path, key)
        if key in _SCHEMA_MAPS or key == "dependencies":
            if isinstance(value, dict):
                result[key] = {
                    name: transform(child, pointer_child(location, name))
                    if isinstance(child, dict | bool)
                    else deepcopy(child)
                    for name, child in value.items()
                }
        elif key in _SCHEMA_ARRAYS or (key == "items" and isinstance(value, list)):
            if isinstance(value, list):
                result[key] = [
                    transform(child, pointer_child(location, index))
                    if isinstance(child, dict | bool)
                    else deepcopy(child)
                    for index, child in enumerate(value)
                ]
        elif (key in _SCHEMA_VALUES or key == "items") and isinstance(value, dict | bool):
            result[key] = transform(value, location)
    return result


def inline_refs(schema: Schema, *, max_depth: int = 3) -> RefResult:
    """Inline up to three ref hops per path; unavailable targets become unconstrained schemas.

    The registry contains only the document and its embedded resources. Its default retrieval
    fails closed, including for metaschema URLs: no network retrieval callback is installed.
    ``$dynamicRef`` uses referencing's dynamic scope, but is still recorded as best-effort.
    """
    if max_depth < 0:
        raise ValueError("max_depth must be nonnegative")
    if isinstance(schema, bool):
        return RefResult(schema)
    dialect = detect_dialect(schema)
    specification = DRAFT7 if dialect.name == "draft-07" else DRAFT202012
    declared = schema.get("$id")
    base = declared if isinstance(declared, str) and urlsplit(declared).scheme else _ROOT_URI
    registry: Registry[Any] = (
        Registry().with_resource(base, specification.create_resource(schema)).crawl()
    )
    known_problems = dict(ref_problems(schema)) if find_refs(schema) else {}
    problems: dict[str, str] = {}
    notes: list[Approximation] = []

    def visit(node: Schema, path: str, resolver: Any, depth: int, scoped: bool = False) -> Schema:
        if isinstance(node, bool):
            return node
        if not scoped:
            resolver = resolver.in_subresource(specification.create_resource(node))
        siblings = {key: value for key, value in node.items() if key not in {"$ref", "$dynamicRef"}}
        targets: list[Schema] = []
        for keyword in ("$ref", "$dynamicRef"):
            ref = node.get(keyword)
            if not isinstance(ref, str):
                continue
            location = pointer_child(path, keyword)
            if keyword == "$dynamicRef":
                notes.append(
                    Approximation("dynamic_ref", location, "Best-effort dynamic resolution.")
                )
            try:
                resolved = resolver.lookup(ref)
                if not isinstance(resolved.contents, dict | bool):
                    raise Unresolvable(ref=ref)
            except Unresolvable:
                reason = "unresolvable" if ref.startswith("#") else known_problems.get(ref)
                if reason is None:
                    scheme = urlsplit(urljoin(base, ref)).scheme
                    reason = "remote" if scheme in _REMOTE_SCHEMES else "unresolvable"
                problems[ref] = reason
                notes.append(
                    Approximation(f"ref_{reason}", location, f"Replaced {ref!r} with {{}}.")
                )
                targets.append({})
                continue
            if depth >= max_depth:
                notes.append(
                    Approximation("ref_depth", location, f"Cut {ref!r} after {max_depth} hops.")
                )
                targets.append({})
            else:
                targets.append(visit(resolved.contents, path, resolved.resolver, depth + 1, True))
        if not targets:
            return map_subschemas(node, path, lambda child, p: visit(child, p, resolver, depth))
        if dialect.name == "draft-07" and "$ref" in node:
            if siblings:
                notes.append(Approximation("ref_siblings", path, "Draft 7 ignores $ref siblings."))
            return targets[0]
        if siblings:
            targets.append(
                map_subschemas(siblings, path, lambda child, p: visit(child, p, resolver, depth))
            )
        return targets[0] if len(targets) == 1 else {"allOf": targets}

    expanded = visit(schema, "", registry.resolver(base), 0, True)
    return RefResult(expanded, tuple(problems.items()), tuple(notes))
