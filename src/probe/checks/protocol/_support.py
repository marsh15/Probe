"""Helpers shared by the protocol checks."""

import contextlib
from collections.abc import Mapping, Sequence
from typing import Any

from probe.checks.base import Check
from probe.checks.context import ScanContext
from probe.engine.outcomes import Evidence, Finding, Mode, ReproCase, Severity
from probe.util.redact import redact_headers
from probe.wire.jsonrpc import ErrorResponse, ResultResponse, encode
from probe.wire.session import Era as EraName
from probe.wire.session import Session
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpTransport, RawHttpResult

_MAX_PAGES = 100


def make_finding(
    check: Check,
    ctx: ScanContext,
    *,
    severity: Severity,
    title: str,
    message: str,
    case_id: str,
    steps: Sequence[Mapping[str, Any]],
    expect: Mapping[str, Any],
    observations: Mapping[str, Any] | None = None,
    excerpt: str | None = None,
    tool: str | None = None,
) -> Finding:
    """A finding with evidence and a repro case in the shapes the report expects."""
    return check.finding(
        ctx,
        severity=severity,
        title=title,
        message=message,
        tool=tool,
        evidence=Evidence(
            summary=message,
            request_refs=[],
            response_refs=[],
            observations=dict(observations or {}),
            excerpt=excerpt,
        ),
        repro=ReproCase(
            case_id=case_id,
            steps=[dict(step) for step in steps],
            expect=dict(expect),
            command=f"probe repro --check {check.meta.id} --case {case_id}",
        ),
    )


def request_step(method: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"kind": "request", "method": method, "params": dict(params or {})}


def raw_http_step(headers: Mapping[str, str], body: bytes, method: str = "POST") -> dict[str, Any]:
    return {
        "kind": "raw_http",
        "method": method,
        "headers": redact_headers(headers),
        "body": body.decode("utf-8", "replace"),
    }


def raw_stdio_step(line: bytes) -> dict[str, Any]:
    return {"kind": "raw_stdio", "line": line.decode("utf-8", "replace")}


async def open_fresh(ctx: ScanContext, era: EraName, label: str) -> Session | None:
    """A session on a brand-new instance of the target, or None if the runner cannot make one.

    Its traffic is labeled so that passive checks on the main instance ignore it. The caller
    closes it with ``close_fresh``.
    """
    if not ctx.second_instance_supported:
        return None
    transport = await ctx.runner.second_instance()
    if transport is None:
        return None
    transport.instance = label
    old = ctx.client
    try:
        return await Session.open(
            transport,
            era=era,
            client_capabilities=old.client_capabilities,
            seed=ctx.config.seed,
            probe_timeout=10.0,
            request_timeout=30.0,
        )
    except BaseException:
        with contextlib.suppress(Exception):
            await transport.close()
        raise


async def close_fresh(session: Session | None) -> None:
    if session is not None:
        with contextlib.suppress(Exception):
            await session.transport.close()


async def list_all_tools(ctx: ScanContext, session: Session) -> list[dict[str, Any]] | None:
    """Every tool the instance lists (budgeted per page), or None if listing failed."""
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(_MAX_PAGES):
        ctx.spend()
        outcome = await session.exchange("tools/list", {"cursor": cursor} if cursor else None)
        response = outcome.response
        if not isinstance(response, ResultResponse) or not isinstance(response.result, dict):
            return None
        page = response.result.get("tools")
        if not isinstance(page, list):
            return None
        tools += [t for t in page if isinstance(t, dict)]
        cursor = response.result.get("nextCursor")
        if not isinstance(cursor, str) or not cursor:
            return tools
    return tools


def transport_of(ctx: ScanContext) -> Transport:
    return ctx.client.transport


ALL_MODES: frozenset[Mode] = frozenset({"quick", "standard", "deep"})


def main_records(ctx: ScanContext, direction: str) -> list[dict[str, Any]]:
    """Recorded messages of the main instance in one direction ("c2s" or "s2c")."""
    return [r for r in ctx.trace_records() if r.get("dir") == direction and "instance" not in r]


def request_methods(ctx: ScanContext) -> dict[Any, str]:
    """Request id -> method, from what Probe sent (to label responses in evidence)."""
    methods: dict[Any, str] = {}
    for record in main_records(ctx, "c2s"):
        body = record.get("body")
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
