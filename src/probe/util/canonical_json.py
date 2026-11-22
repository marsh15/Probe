"""Canonical JSON: the single byte-exact encoding used for hashing and content addressing.

Sorted keys, no whitespace, UTF-8 (not ASCII-escaped), floats via ``repr``. Non-finite floats
and non-JSON types are rejected so two equal values can never encode differently.
"""

import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    # surrogatepass: a hostile server can send lone surrogates; hashing must not crash on them.
    return canonical_json(value).encode("utf-8", "surrogatepass")
