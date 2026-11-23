"""Fixed fixture values for schema formats and classified parameters."""

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

_URL = "http://public.probe.test/hello.txt"
_FORMATS = {
    "email": "probe@example.test",
    "date-time": "2026-01-01T00:00:00Z",
    "uri": _URL,
    "uri-reference": _URL,
    "iri": _URL,
    "url": _URL,
}


def format_values(
    name: str,
    schema: Mapping[str, Any],
    *,
    role: str | None = None,
    allowed_roots: Sequence[str] = (),
    id_values: Mapping[str, Sequence[Any]] | None = None,
) -> list[Any]:
    """Return preferred values; an empty list means no fixture value is available."""
    if name.endswith("_id") and id_values is not None and name in id_values:
        return list(id_values[name])
    if role == "url_param":
        return [_URL]
    if role == "path_param":
        return [str(PurePosixPath(root) / "hello.txt") for root in allowed_roots]
    value = _FORMATS.get(schema.get("format", ""))
    return [value] if value is not None else []
