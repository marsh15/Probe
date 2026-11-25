"""safety.path_contained"""

import contextlib
import json
from collections.abc import Iterator
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.safety._support import (
    absolute,
    allowed_roots,
    data_root,
    is_inside,
    output_text,
    safe_call,
    tools_with_role,
    valid_arguments,
)
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetUnstable
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    ToolInfo,
    Transport,
)

_WRITES = frozenset({"write", "destructive", "exec", "unknown"})
# What the file next to the allowed root holds (the sandbox seed and the reference seed differ).
# A string must be exactly this to count: a refusal that quotes the root would match a phrase.
_EVIL_CONTENT = frozenset({"outside allowed root", "outside the allowed root (prefix sibling)"})


def _read_payloads(ctx: ScanContext) -> list[tuple[str, str]]:
    root, data = allowed_roots(ctx)[0], data_root(ctx)
    payloads = [
        ("dotdot", "../secret/SENTINEL"),
        ("absolute", f"{data}/secret/SENTINEL"),
        ("dotdot-absolute", f"{root}/../secret/SENTINEL"),
        ("encoded-dotdot", "..%2fsecret%2fSENTINEL"),
        ("prefix-sibling", f"{data}/allowed_evil/evil.txt"),
        ("symlink-out", f"{root}/link_out/SENTINEL"),
        ("nul-byte", f"{root}/notes/a.txt\u0000../../secret/SENTINEL"),
    ]
    return payloads[:4] if ctx.config.mode == "quick" else payloads


def _strings(value: Any, depth: int = 0) -> Iterator[str]:
    """Every string in a JSON value, and in the JSON a string itself holds (a tool's text block
    often carries the real answer as an encoded object)."""
    if isinstance(value, str):
        yield value
        if depth < 3 and value.lstrip()[:1] in ("{", "["):
            with contextlib.suppress(ValueError):
                yield from _strings(json.loads(value), depth + 1)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item, depth)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, depth)


def _leak(text: str, token: str) -> str | None:
    if f"PROBE-SENTINEL-{token}" in text:
        return f"PROBE-SENTINEL-{token}"
    with contextlib.suppress(ValueError):
        for found in _strings(json.loads(text)):
            if found.strip() in _EVIL_CONTENT:
                return found.strip()
    return None


@register
class PathContained(Check):
    meta = CheckMeta(
        id="safety.path_contained",
        family=Family.SAFETY,
        title="File tools stay inside their allowed directories",
        severity=Severity.CRITICAL,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"fixtures", "path_tools", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-22"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "A tool limited to one directory that can be talked into reading or writing "
            "elsewhere exposes every file the server's user can reach."
        ),
        remediation=(
            "Resolve the real path (following symlinks) and compare it to the resolved allowed "
            "root with a path-aware check, not a string prefix; reject NUL bytes."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        tested = False
        try:
            for tool, names in tools_with_role(ctx, "path_param"):
                base = await valid_arguments(ctx, tool)
                if base is None:
                    continue
                writes = tool.kind in _WRITES
                for name in names:
                    tested = True
                    if writes:
                        findings += await self._write_escape(ctx, tool, name, base)
                    else:
                        findings += await self._read_escape(ctx, tool, name, base)
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("path campaign interrupted before a verdict")
        if not tested:
            return CheckOutcome.na("no path parameter on a tool that can be called")
        return CheckOutcome(findings)

    async def _read_escape(
        self, ctx: ScanContext, tool: ToolInfo, name: str, base: dict[str, Any]
    ) -> list[Finding]:
        token = ctx.fixtures.token if ctx.fixtures is not None else ""
        found: list[Finding] = []
        for payload_id, path in _read_payloads(ctx):
            arguments = {**base, name: path}
            case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
            result = await safe_call(ctx, tool.name, arguments, case_id)
            if result is None or not result.ok:
                continue  # a refusal may quote the path it refused; only content is a leak
            text = output_text(result)
            marker = _leak(text, token)
            if marker is None:
                continue
            found.append(
                self._finding(
                    ctx,
                    tool,
                    Severity.HIGH,
                    f"{tool.name} returned a file outside its allowed directory ({payload_id})",
                    case_id,
                    arguments,
                    {"payload_id": payload_id, "marker": marker, "response": text[:600]},
                )
            )
        return found

    async def _write_escape(
        self, ctx: ScanContext, tool: ToolInfo, name: str, base: dict[str, Any]
    ) -> list[Finding]:
        fixtures = ctx.fixtures
        if fixtures is None:
            return []
        found: list[Finding] = []
        for payload_id, directory in (
            ("write-secret", "secret"),
            ("write-sibling", "allowed_evil"),
        ):
            target = f"{data_root(ctx)}/{directory}/probe-written-{fixtures.token}"
            arguments = {**base, name: target}
            case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
            await fixtures.reset()
            before = await fixtures.snapshot()
            await safe_call(ctx, tool.name, arguments, case_id)
            diff = fixtures.diff(before, await fixtures.snapshot())
            roots = allowed_roots(ctx)
            touched = (absolute(ctx, p) for p in [*diff.added, *diff.changed])
            outside = [p for p in touched if not is_inside(p, roots)]
            await fixtures.reset()
            if outside:
                found.append(
                    self._finding(
                        ctx,
                        tool,
                        Severity.CRITICAL,
                        f"{tool.name} wrote a file outside its allowed directory ({payload_id})",
                        case_id,
                        arguments,
                        {"payload_id": payload_id, "outside": outside[:5]},
                    )
                )
        return found

    def _finding(
        self,
        ctx: ScanContext,
        tool: ToolInfo,
        severity: Severity,
        title: str,
        case_id: str,
        arguments: dict[str, Any],
        observations: dict[str, Any],
    ) -> Finding:
        return make_finding(
            self,
            ctx,
            severity=severity,
            title=title,
            message=title,
            case_id=case_id,
            steps=[request_step("tools/call", {"name": tool.name, "arguments": arguments})],
            expect={"outside_the_allowed_root": "nothing read or written"},
            observations=observations,
            tool=tool.name,
        )
