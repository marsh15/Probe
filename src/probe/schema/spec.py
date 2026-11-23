"""Validate what a server sends against the official MCP JSON Schema of its era."""

import json
from functools import cache
from importlib import resources
from typing import Any

from jsonschema.validators import Draft7Validator, validator_for

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
_FILES = {MODERN: "mcp-2026-07-28.schema.json", LEGACY: "mcp-2025-11-25.schema.json"}
_MAX_PROBLEMS = 20


@cache
def vendored_schema(version: str) -> dict[str, Any]:
    """The vendored schema.json for ``version`` (the exact releases Probe ships with)."""
    text = resources.files("probe.schema.vendored").joinpath(_FILES[version]).read_text("utf-8")
    loaded: dict[str, Any] = json.loads(text)
    return loaded


def schema_version_for(negotiated: str) -> str:
    """Which vendored schema judges a negotiated version: modern or the latest legacy one."""
    return MODERN if negotiated >= MODERN else LEGACY


def definition_problems(value: Any, definition: str, version: str) -> list[str]:
    """Violations of ``#/definitions/<definition>`` by ``value``, as "path: message" (capped)."""
    document = vendored_schema(schema_version_for(version))
    # The official files keep their types under "$defs" (older drafts used "definitions").
    key = "$defs" if "$defs" in document else "definitions"
    wrapper = {
        "$schema": document.get("$schema", "http://json-schema.org/draft-07/schema#"),
        "$ref": f"#/{key}/{definition}",
        key: document[key],
    }
    validator = validator_for(wrapper, default=Draft7Validator)(wrapper)
    problems = []
    for error in validator.iter_errors(value):
        where = "/".join(str(p) for p in error.absolute_path) or "(result)"
        problems.append(f"{where}: {error.message[:200]}")
        if len(problems) >= _MAX_PROBLEMS:
            break
    return sorted(problems)


def list_tools_problems(result: Any, negotiated_version: str) -> list[str]:
    """How a ``tools/list`` result departs from the spec."""
    return definition_problems(result, "ListToolsResult", negotiated_version)
