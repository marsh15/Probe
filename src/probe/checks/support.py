"""Helpers every check family uses: building findings and repro steps."""

import contextlib
import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from probe.checks.base import Check
from probe.checks.context import ScanContext
from probe.engine.outcomes import Evidence, Finding, Mode, ReproCase, Severity
from probe.util.redact import redact_headers
from probe.wire.jsonrpc import ResultResponse
from probe.wire.session import Era as EraName
from probe.wire.session import Session

ALL_MODES: frozenset[Mode] = frozenset({"quick", "standard", "deep"})
_MAX_PAGES = 100


def slug(text: str, limit: int = 48) -> str:
    """A tool name (hostile or not) as a safe fragment of a case id."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", text)[:limit]
    if safe != text:
        safe = f"{safe}-{hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"
    return safe or "empty"


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
