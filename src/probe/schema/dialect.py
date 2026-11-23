"""Select the original validation dialect before preparing a schema for generation."""

from dataclasses import dataclass
from typing import Any, Literal

type Schema = dict[str, Any] | bool


@dataclass(frozen=True)
class Dialect:
    """Original validator selection, with notes for unknown declarations."""

    name: Literal["2020-12", "draft-07"]
    notes: tuple[str, ...] = ()


def detect_dialect(schema: Schema) -> Dialect:
    """Default to 2020-12; recognize draft 7 without guessing other dialects."""
    if isinstance(schema, bool) or "$schema" not in schema:
        return Dialect("2020-12")
    declared = schema["$schema"]
    if isinstance(declared, str):
        uri = declared.removesuffix("#")
        if uri in {
            "http://json-schema.org/draft-07/schema",
            "https://json-schema.org/draft-07/schema",
        }:
            return Dialect("draft-07")
        if uri == "https://json-schema.org/draft/2020-12/schema":
            return Dialect("2020-12")
    return Dialect("2020-12", (f"Unknown $schema {declared!s}; treating as 2020-12.",))
