"""Prepare draft-7 generation schemas while retaining original-dialect diagnostics."""

from dataclasses import dataclass
from typing import Any

from probe.schema.dialect import Dialect, Schema, detect_dialect
from probe.schema.refs import Approximation, inline_refs, map_subschemas, pointer_child

_DRAFT7_URI = "http://json-schema.org/draft-07/schema#"
_DROPPED = frozenset(
    {"unevaluatedProperties", "unevaluatedItems", "$dynamicAnchor", "$vocabulary", "contentSchema"}
)


@dataclass(frozen=True)
class NormalizationResult:
    """Use ``schema`` for generation and ``dialect`` to validate against the original."""

    schema: Schema
    dialect: Dialect
    approximations: tuple[Approximation, ...] = ()
    ref_problems: tuple[tuple[str, str], ...] = ()


def _add_dependency(
    result: dict[str, Any], dependencies: dict[str, Any], name: str, dependency: Any
) -> None:
    if name not in dependencies:
        dependencies[name] = dependency
    elif isinstance(dependencies[name], list) and isinstance(dependency, list):
        dependencies[name] = list(dict.fromkeys([*dependencies[name], *dependency]))
    else:
        separate = dependency
        if isinstance(dependency, list):
            separate = dependencies[name]
            dependencies[name] = dependency
        result.setdefault("allOf", []).append({"dependencies": {name: separate}})


def normalize(schema: Schema) -> NormalizationResult:
    """Return a fresh draft-7 schema; candidates still require original-schema validation.

    Keyword translations are exact where possible. Losses, reference truncations, and dynamic
    resolution are recorded individually. Calling this again on its output is idempotent.
    """
    dialect = detect_dialect(schema)
    expanded = inline_refs(schema)
    notes = list(expanded.approximations)

    def visit(node: Schema, path: str) -> Schema:
        if isinstance(node, bool):
            return node
        result = map_subschemas(node, path, visit)
        for keyword in node:
            if keyword in _DROPPED or keyword in {"minContains", "maxContains"}:
                result.pop(keyword, None)
                notes.append(
                    Approximation(
                        keyword,
                        pointer_child(path, keyword),
                        "Unsupported by draft 7; validate original candidates.",
                    )
                )
        # Draft 7 requires a match whenever contains is present; minContains: 0 does not.
        if node.get("minContains") == 0:
            result.pop("contains", None)
        if "$schema" in result:
            result["$schema"] = _DRAFT7_URI
        if "$defs" in result:
            result["definitions"] = {**result.get("definitions", {}), **result.pop("$defs")}
        if "prefixItems" in result:
            prefix = result.pop("prefixItems")
            if prefix:
                tail = result.pop("items", True)
                result["items"] = prefix
                result["additionalItems"] = tail
        dependencies = result.get("dependencies", {}).copy()
        for keyword in ("dependentRequired", "dependentSchemas"):
            for name, dependency in result.pop(keyword, {}).items():
                # Expose required names to hypothesis-jsonschema's object generator. Its
                # incremental schema-dependency checks otherwise reject partial objects.
                required = dependency.get("required") if isinstance(dependency, dict) else None
                if isinstance(required, list) and required:
                    _add_dependency(result, dependencies, name, required)
                    dependency = {
                        key: value for key, value in dependency.items() if key != "required"
                    }
                    if not dependency:
                        continue
                _add_dependency(result, dependencies, name, dependency)
        if dependencies:
            result["dependencies"] = dependencies
        return result

    normalized = visit(expanded.schema, "")
    if isinstance(normalized, dict):
        normalized["$schema"] = _DRAFT7_URI
    return NormalizationResult(normalized, dialect, tuple(notes), expanded.problems)
