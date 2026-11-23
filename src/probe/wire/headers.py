"""HTTP headers that streamable HTTP derives from the request body (2026-07-28).

``Mcp-Method`` and ``Mcp-Name`` come from the message; ``Mcp-Param-{Name}`` headers mirror tool
arguments that the tool's schema marks with ``x-mcp-header``. Values that are not plain ASCII
are carried in the Base64 sentinel format.
"""

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_PREFIX = "=?base64?"
_SUFFIX = "?="
_TCHAR_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_PRIMITIVE_TYPES = ("string", "integer", "boolean")
# Keywords whose values are data, not subschemas: an "x-mcp-header" key inside them is not an
# annotation.
_DATA_KEYWORDS = frozenset({"enum", "const", "default", "examples"})
_NAME_SOURCES = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


def encode_header_value(value: str) -> str:
    """The header value for ``value``: itself if safe plain ASCII, else the Base64 sentinel."""
    plain = (
        all(" " <= char <= "~" for char in value)
        and value == value.strip(" ")
        and not (value.startswith(_PREFIX) and value.endswith(_SUFFIX))
    )
    if plain:
        return value
    return _PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii") + _SUFFIX


def decode_header_value(value: str) -> str:
    """Inverse of ``encode_header_value``; raises ValueError for a malformed sentinel."""
    if not (value.startswith(_PREFIX) and value.endswith(_SUFFIX)):
        return value
    payload = value[len(_PREFIX) : -len(_SUFFIX)]
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("malformed Base64 header value") from exc


def standard_headers(method: str, params: Mapping[str, Any] | None) -> dict[str, str]:
    """``Mcp-Method`` for every request, plus ``Mcp-Name`` where the spec requires it."""
    headers = {"Mcp-Method": method}
    source = _NAME_SOURCES.get(method)
    name = params.get(source) if source is not None and params is not None else None
    if isinstance(name, str):
        headers["Mcp-Name"] = encode_header_value(name)
    return headers


@dataclass(frozen=True, slots=True)
class HeaderMirror:
    header: str  # e.g. "Mcp-Param-Region"
    path: tuple[str, ...]  # chain of ``properties`` keys leading to the annotated property


def parse_x_mcp_headers(
    input_schema: Mapping[str, Any] | None,
) -> tuple[tuple[HeaderMirror, ...], tuple[str, ...]]:
    """Collect valid ``x-mcp-header`` annotations and the reasons any are invalid.

    Any error makes the whole tool definition invalid; the caller excludes the tool.
    """
    if not isinstance(input_schema, Mapping):
        return (), ()
    mirrors: list[HeaderMirror] = []
    errors: list[str] = []
    seen: set[str] = set()

    def annotate(node: Mapping[str, Any], path: tuple[str, ...], reachable: bool) -> None:
        where = ".".join(path) or "(root)"
        value = node["x-mcp-header"]
        if not reachable or not path:
            errors.append(f"{where}: x-mcp-header is not reachable through properties keys only")
        elif not isinstance(value, str):
            errors.append(f"{where}: x-mcp-header must be a string")
        elif not value:
            errors.append(f"{where}: x-mcp-header must not be empty")
        elif not _TCHAR_TOKEN.fullmatch(value):
            errors.append(f"{where}: x-mcp-header {value!r} is not a valid header token")
        elif node.get("type") not in _PRIMITIVE_TYPES:
            errors.append(
                f"{where}: x-mcp-header needs a primitive type (string, integer, boolean)"
            )
        elif value.lower() in seen:
            errors.append(f"{where}: x-mcp-header {value!r} is not unique ignoring case")
        else:
            seen.add(value.lower())
            mirrors.append(HeaderMirror(f"Mcp-Param-{value}", path))

    def walk(node: Any, path: tuple[str, ...], reachable: bool) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, path, False)
        elif isinstance(node, Mapping):
            if "x-mcp-header" in node:
                annotate(node, path, reachable)
            for key, child in node.items():
                if key in _DATA_KEYWORDS or key == "x-mcp-header":
                    continue
                if key == "properties" and isinstance(child, Mapping):
                    for name, prop in child.items():
                        walk(prop, (*path, str(name)), reachable)
                else:
                    walk(child, path, False)

    walk(input_schema, (), True)
    return tuple(mirrors), tuple(errors)


def mirror_headers(
    mirrors: tuple[HeaderMirror, ...], arguments: Mapping[str, Any] | None
) -> dict[str, str]:
    """Headers for the argument values present at each mirrored path; absent values are omitted."""
    headers: dict[str, str] = {}
    for mirror in mirrors:
        value: Any = arguments
        for key in mirror.path:
            value = value.get(key) if isinstance(value, Mapping) else None
        text = _header_text(value)
        if text is not None:
            headers[mirror.header] = encode_header_value(text)
    return headers


def _header_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    return None
