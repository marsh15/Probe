"""protocol.official.conformance: run the official MCP conformance suite against an HTTP target.

The suite runs in a pinned container on the sandbox's private network (see
``images/conformance``). Its ``checks.json`` for each scenario is turned into findings here;
the parsing is pure so it is tested against recorded output. A failed official check is a
FAIL (medium; high for auth scenarios). A check that errored in the suite's own harness is an
ERROR, never a FAIL: Probe does not blame the server for the suite's trouble.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Severity,
    Transport,
)
from probe.sandbox.conformance import ConformanceImageUnavailable

LEGACY_VERSION = "0.1.16"
MODERN_VERSION = "0.2.0-alpha.11"
LEGACY_PREFIX = "/opt/c116"
MODERN_PREFIX = "/opt/c020a11"
TIMEOUT_S = 300
_SCENARIO = re.compile(r"^@@PROBE-SCENARIO@@ (.+)$")
_END = re.compile(r"^@@PROBE-END@@ (\d+)$")
_DIRNAME = re.compile(
    r"^server-(?P<scenario>.+)-\d{4}-\d{2}-\d{2}T[\d\-:.Z]+$|^server-(?P<plain>.+)$"
)
_PASS = {"success", "pass", "passed", "ok"}
_FAIL = {"failure", "fail", "failed", "error"}
_AUTH = re.compile(r"(?<![a-z0-9])auth(?![a-z0-9])", re.I)
_RECEIVED_STATUS = re.compile(r"\b(?:got|received|returned)(?:\s+HTTP)?\s+([1-5]\d\d)\b", re.I)
_HTTP_STATUS = re.compile(r"\b(?:HTTP|status(?: code)?)[\s:=]+([1-5]\d\d)\b", re.I)
_HOST = re.compile(r"\bhost(?:name| header)?\b|\bdns.rebinding\b", re.I)


class ConformanceRunner(Protocol):
    """Runs the suite and returns the container's output (see ``parse_stream``)."""

    async def run(self, command: list[str], timeout_s: float) -> str: ...


@dataclass(frozen=True, slots=True)
class OfficialCheck:
    scenario: str
    check_id: str
    name: str
    status: str  # "pass", "fail" or "other" (skipped, info, warning)
    message: str
    spec_refs: list[str] = field(default_factory=list)

    @property
    def harness_error(self) -> bool:
        return "harness-error" in self.check_id

    @property
    def host_rejection(self) -> bool:
        # Some checks describe both the expected status and the response they received.
        status = _RECEIVED_STATUS.search(self.message) or _HTTP_STATUS.search(self.message)
        if status is None:
            return False
        return status[1] == "421" or (status[1] == "403" and _HOST.search(self.message) is not None)


@dataclass(frozen=True, slots=True)
class Stream:
    checks: list[OfficialCheck]
    exit_status: int | None
    error: str | None


def scenario_name(dirname: str) -> str:
    """``server-<scenario>-<timestamp>`` to ``<scenario>``."""
    match = _DIRNAME.match(dirname)
    if match is None:
        return dirname
    return match.group("scenario") or match.group("plain") or dirname


def parse_checks(scenario: str, data: Any) -> list[OfficialCheck]:
    """One scenario's ``checks.json`` (an array); entries that are not objects are ignored."""
    if not isinstance(data, list):
        return []
    parsed = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("status", "")).lower()
        status = "pass" if raw in _PASS else "fail" if raw in _FAIL else "other"
        refs = entry.get("specReferences")
        parsed.append(
            OfficialCheck(
                scenario=scenario,
                check_id=str(entry.get("id", "unknown")),
                name=str(entry.get("name") or entry.get("id") or "unnamed check"),
                status=status,
                message=str(entry.get("errorMessage") or entry.get("description") or "")[:500],
                spec_refs=[
                    str(r.get("id") or r.get("url"))
                    for r in (refs if isinstance(refs, list) else [])
                    if isinstance(r, dict) and (r.get("id") or r.get("url"))
                ],
            )
        )
    return parsed


def parse_stream(text: str) -> Stream:
    """The container's output: ``@@PROBE-SCENARIO@@ <dir>`` then that scenario's JSON, and so on."""
    checks: list[OfficialCheck] = []
    scenario: str | None = None
    body: list[str] = []
    exit_status: int | None = None
    error: str | None = None

    def flush() -> None:
        nonlocal body
        if scenario is not None and body:
            try:
                checks.extend(parse_checks(scenario_name(scenario), json.loads("\n".join(body))))
            except ValueError:
                nonlocal error
                error = f"unreadable checks.json for {scenario}"
        body = []

    for line in text.splitlines():
        if line.startswith("@@PROBE-ERROR@@"):
            error = line.removeprefix("@@PROBE-ERROR@@").strip()
        elif (m := _SCENARIO.match(line)) is not None:
            flush()
            scenario = m.group(1)
        elif (m := _END.match(line)) is not None:
            flush()
            scenario = None
            exit_status = int(m.group(1))
        elif scenario is not None:
            body.append(line)
    flush()
    return Stream(checks, exit_status, error)


def command_for(modern: bool, url: str) -> list[str]:
    """The container arguments: install prefix, target URL, then the suite's own options."""
    if modern:
        return [MODERN_PREFIX, url, "--requirements", "2026-07-28"]
    return [LEGACY_PREFIX, url, "--suite", "active"]


def severity_for(scenario: str) -> Severity:
    return Severity.HIGH if _AUTH.search(scenario) else Severity.MEDIUM


@register
class OfficialConformance(Check):
    meta = CheckMeta(
        id="protocol.official.conformance",
        family=Family.PROTOCOL,
        title="The official MCP conformance suite passes",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"http"}),
        modes=frozenset({"standard", "deep"}),
        phase="post",
        spec_refs=["2026-07-28/basic"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "The MCP project publishes a conformance suite. Probe runs it against HTTP "
            "servers and reports each scenario check that fails, so protocol compliance rests "
            "on the official tests rather than Probe's reading of the spec."
        ),
        remediation=(
            "Run the official suite yourself (npx @modelcontextprotocol/conformance server "
            "--url ...) and fix the failing scenarios it names."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        runner = ctx.conformance
        if runner is None:
            return CheckOutcome.na("the official suite needs a sandboxed HTTP target")
        if ctx.profile is not None and ctx.profile.auth.type == "bearer":
            return CheckOutcome.na("the official suite does not accept a baseline bearer token")
        modern = ctx.era is Era.MODERN
        version = MODERN_VERSION if modern else LEGACY_VERSION
        url = ctx.runner.conformance_url() if hasattr(ctx.runner, "conformance_url") else None
        if url is None:
            return CheckOutcome.na(
                "this runner cannot give the suite a private address for the target"
            )
        remaining = ctx.budget.remaining_seconds
        if remaining <= 0:
            return CheckOutcome.error("scan time budget exhausted before official conformance")
        try:
            async with asyncio.timeout(remaining):
                if not await ctx.liveness():
                    return CheckOutcome.error("target failed the liveness check before the suite")
        except TimeoutError:
            return CheckOutcome.error("scan time budget expired during target liveness check")
        timeout = min(TIMEOUT_S * ctx.config.timeout_scale, ctx.budget.remaining_seconds)
        if timeout <= 0:
            return CheckOutcome.error("scan time budget exhausted before official conformance")
        try:
            output = await runner.run(command_for(modern, url), timeout)
        except ConformanceImageUnavailable:
            return CheckOutcome.na(
                "the conformance image is unavailable. Check registry access or --conformance-image"
            )
        except TimeoutError:
            return CheckOutcome.error("the conformance suite reached its time limit")
        except Exception as exc:
            return CheckOutcome.error(
                f"the conformance container did not run: {type(exc).__name__}"
            )
        stream = parse_stream(output)
        if not stream.checks:
            return CheckOutcome.error(stream.error or "the conformance run produced no checks")
        failures = [c for c in stream.checks if c.status == "fail"]
        failed = [c for c in failures if not c.harness_error and not c.host_rejection]
        findings = [
            make_finding(
                self,
                ctx,
                severity=severity_for(c.scenario),
                title=f"Official conformance check failed: {c.name}",
                message=(
                    f"{c.message or c.name} (delegated to the official MCP conformance suite "
                    f"v{version}, scenario {c.scenario})"
                ),
                case_id=f"official:{c.scenario}:{c.check_id}",
                steps=[],
                expect={"official_check": f"{c.scenario}/{c.check_id} passes"},
                observations={"scenario": c.scenario, "check": c.check_id, "spec": c.spec_refs},
            )
            for c in failed
        ]
        if findings:
            return CheckOutcome(findings)
        if stream.error is not None:
            # Some of the run could not be read, so the passes we did see are not a clean bill.
            return CheckOutcome.error(stream.error)
        if any(c.host_rejection for c in failures):
            return CheckOutcome.error("the target rejected the suite's HTTP Host")
        if failures:
            return CheckOutcome.error(f"the suite's own harness reported {len(failures)} error(s)")
        return CheckOutcome()
