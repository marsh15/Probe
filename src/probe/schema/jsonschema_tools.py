"""Inspect the JSON Schemas servers publish for their tools, without trusting them.

Everything here is bounded and offline: walks are iterative, nothing is fetched, and a schema
that nests absurdly deep is reported rather than crashing the scan.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

from jsonschema.exceptions import SchemaError
from jsonschema.validators import Draft202012Validator, validator_for
from jsonschema_specifications import REGISTRY as STANDARD_RESOURCES
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012

# Keywords whose values are data, not subschemas.
_DATA_KEYWORDS = frozenset({"enum", "const", "default", "examples"})
_MAX_NODES = 50_000
_ROOT_URI = "urn:probe:tool-schema"
_REMOTE_SCHEMES = frozenset({"http", "https", "file", "ftp"})


def meta_problems(schema: Any) -> list[str]:
    """Why ``schema`` is not a valid JSON Schema (in its declared dialect, 2020-12 by default)."""
    if not isinstance(schema, bool | Mapping):
        return [f"not a JSON Schema (a {type(schema).__name__})"]
    try:
        validator_for(schema, default=Draft202012Validator).check_schema(schema)
    except SchemaError as exc:
        location = "/".join(str(p) for p in exc.absolute_path)
        return [f"{location or '(root)'}: {exc.message[:200]}"]
    except RecursionError:
        return ["schema is nested too deeply to check"]
    return []


def find_refs(schema: Any) -> list[str]:
    """Every ``$ref`` string in ``schema`` (data keywords such as enum and default skipped)."""
    refs: list[str] = []
    stack: list[Any] = [schema]
    seen = 0
    while stack and seen < _MAX_NODES:
        node = stack.pop()
        seen += 1
        if isinstance(node, Mapping):
            for key, value in node.items():
                if key in _DATA_KEYWORDS:
                    continue
                if key == "$ref" and isinstance(value, str):
                    refs.append(value)
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return refs


def ref_problems(schema: Any) -> list[tuple[str, str]]:
    """(ref, "remote" | "unresolvable") for each $ref that does not resolve within the schema.

    A ref resolves if it points inside the schema, at a subschema with a matching ``$id``, or at
    a standard JSON Schema metaschema (all available offline). Anything else would need the
    network ("remote") or points nowhere ("unresolvable").
    """
    if not isinstance(schema, Mapping):
        return []
    refs = find_refs(schema)
    if not refs:
        return []
    declared = schema.get("$id")
    base = declared if isinstance(declared, str) and urlsplit(declared).scheme else _ROOT_URI
    try:
        registry: Registry[Any] = STANDARD_RESOURCES.combine(Registry()).with_resource(
            base, Resource.from_contents(schema, default_specification=DRAFT202012)
        )
        resolver = registry.crawl().resolver(base)
    except Exception:  # an exotic or hostile schema: report nothing rather than crash
        return []
    problems: list[tuple[str, str]] = []
    for ref in dict.fromkeys(refs):  # unique, in order
        try:
            resolver.lookup(ref)
        except Unresolvable:
            target = urlsplit(urljoin(base, ref)).scheme
            problems.append((ref, "remote" if target in _REMOTE_SCHEMES else "unresolvable"))
        except Exception:
            problems.append((ref, "unresolvable"))
    return problems
