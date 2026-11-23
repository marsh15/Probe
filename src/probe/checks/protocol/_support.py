"""Helpers shared by the protocol checks."""

from collections.abc import Mapping
from typing import Any

from probe.checks.context import ScanContext
from probe.checks.support import (
    ALL_MODES,
    close_fresh,
    list_all_tools,
    make_finding,
    open_fresh,
    raw_http_step,
    raw_stdio_step,
    request_step,
)
from probe.wire.jsonrpc import ErrorResponse, ResultResponse, encode
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpTransport, RawHttpResult

_MAX_PAGES = 100
__all__ = [
    "ALL_MODES",
    "accepted",
    "close_fresh",
    "error_codes",
    "http_transport",
    "json_body",
    "list_all_tools",
    "main_messages",
    "main_records",
    "make_finding",
    "message_view",
    "open_fresh",
    "raw_http_step",
    "raw_stdio_step",
    "request_methods",
    "request_step",
    "transport_of",
    "valid_http_request",
    "with_header",
    "without_header",
]


def transport_of(ctx: ScanContext) -> Transport:
    return ctx.client.transport


def main_records(ctx: ScanContext, direction: str) -> list[dict[str, Any]]:
    """Recorded messages of the main instance in one direction ("c2s" or "s2c")."""
    return [r for r in ctx.trace_records() if r.get("dir") == direction and "instance" not in r]


def message_view(record: dict[str, Any]) -> dict[str, Any] | None:
    """The message of a trace record as a dict: the body, or its summary if the body was cut.

    A summary has only the id, a few result fields and an error code, which is all the passive
    checks read, so a large response cannot hide a violation.
    """
    body = record.get("body")
    if isinstance(body, dict):
        return body
    summary = record.get("body_summary")
    return summary if isinstance(summary, dict) else None


def main_messages(ctx: ScanContext, direction: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(record, message) for each main-instance record that holds a readable message."""
    pairs = []
    for record in main_records(ctx, direction):
        view = message_view(record)
        if view is not None:
            pairs.append((record, view))
    return pairs


def request_methods(ctx: ScanContext) -> dict[Any, str]:
    """Request id -> method, from what Probe sent (to label responses in evidence)."""
    methods: dict[Any, str] = {}
    for _, body in main_messages(ctx, "c2s"):
        if isinstance(body, dict) and "id" in body and isinstance(body.get("method"), str):
            methods[body["id"]] = body["method"]
    return methods


def http_transport(ctx: ScanContext) -> HttpTransport:
    transport = ctx.client.transport
    if not isinstance(transport, HttpTransport):
        raise TypeError("this check needs an HTTP target")
    return transport


def with_header(headers: Mapping[str, str], name: str, value: str) -> dict[str, str]:
    """``headers`` with ``name`` set to ``value``, replacing any case variant of it."""
    kept = {k: v for k, v in headers.items() if k.lower() != name.lower()}
    kept[name] = value
    return kept


def without_header(headers: Mapping[str, str], name: str) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() != name.lower()}


def valid_http_request(
    ctx: ScanContext, method: str, params: Mapping[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, str]]:
    """A request and headers exactly as a correct client would send them, for tampering."""
    message = ctx.client.build_request(method, params)
    headers = {**http_transport(ctx).base_headers(), **ctx.client.headers_for(message)}
    return message, headers


def json_body(message: Mapping[str, Any]) -> bytes:
    return encode(message)[:-1]


def accepted(result: RawHttpResult) -> bool:
    """The server answered a request with a 2xx and an actual result."""
    return (
        result.status is not None
        and 200 <= result.status < 300
        and any(isinstance(r, ResultResponse) for r in result.responses)
    )


def error_codes(result: RawHttpResult) -> list[int]:
    return [r.error.code for r in result.responses if isinstance(r, ErrorResponse)]
