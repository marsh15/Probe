"""Private-network and file URL disclosures, observed only through tool calls."""

import asyncio
import ipaddress
import json
from collections.abc import Iterator
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.config.profile import Profile
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
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
from probe.schema.valid_gen import generate_valid
from probe.wire.errors import RequestTimeout

_PUBLIC = "http://public.probe.test/hello.txt"
_NO_BASELINE = "cannot establish that the tool can fetch at all"


def _url_tools(ctx: ScanContext) -> Iterator[tuple[ToolInfo, list[str]]]:
    for tool in ctx.callable_tools():
        if "url_param" in tool.flags:
            names = [name for name, role in tool.param_roles.items() if role == "url_param"]
            if names:
                yield tool, names


async def _baseline(ctx: ScanContext, tool: ToolInfo, names: list[str]) -> dict[str, Any] | None:
    generated = await asyncio.to_thread(
        generate_valid,
        tool,
        seed=ctx.config.seed,
        mode=ctx.config.mode,
        profile=ctx.profile if isinstance(ctx.profile, Profile) else None,
    )
    arguments = next((c.arguments for c in generated.cases if isinstance(c.arguments, dict)), None)
    if arguments is None:
        return None
    arguments = {**arguments, **dict.fromkeys(names, _PUBLIC)}
    try:
        # A cached call to another URL cannot establish access to the public fixture.
        result = await ctx.establish_baseline(tool, arguments, reuse=False)
    except (TargetCrashed, RequestTimeout):
        return None
    return arguments if result is not None and result.ok else None


def _payloads(ip: str, token: str, *, quick: bool) -> list[tuple[str, str]]:
    address = ipaddress.IPv4Address(ip)
    dotted = str(address)
    payloads = [
        ("ip-dotted", f"http://{dotted}/{token}"),
        ("metadata", f"http://metadata.google.internal/computeMetadata/v1/?t={token}"),
        ("redirect", f"http://public.probe.test/redirect?to=http://{dotted}/{token}"),
    ]
    if not quick:
        octal = ".".join(f"0{int(part):o}" for part in dotted.split("."))
        payloads += [
            ("ip-decimal", f"http://{int(address)}/{token}"),
            ("ip-hex", f"http://{int(address):#x}/{token}"),
            ("ip-octal", f"http://{octal}/{token}"),
            ("ip-mapped", f"http://[::ffff:{dotted}]/{token}"),
            ("canary-host", f"http://canary.probe.test/{token}"),
            ("internal-host", f"http://internal.probe.test:8080/{token}"),
        ]
    return payloads


@register
class SsrfBlocked(Check):
    meta = CheckMeta(
        id="safety.ssrf_blocked",
        family=Family.SAFETY,
        title="URL tools block private networks and private redirect destinations",
        severity=Severity.HIGH,
        eras=frozenset({Era.MODERN, Era.LEGACY}),
        transports=frozenset({Transport.STDIO, Transport.HTTP}),
        requires=frozenset({"fixtures", "url_tools", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-918"],
        disclosure=DisclosureTier.PRIVATE,
        rationale="URL tools can expose internal services and cloud credentials through SSRF.",
        remediation=(
            "Allow only public HTTP(S) destinations. Resolve and validate every address and "
            "every redirect hop, then connect to the vetted address."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        tested = False
        try:
            for tool, names in _url_tools(ctx):
                override = ctx.profile.override_for(tool.name) if ctx.profile is not None else None
                if override is not None and override.allow_private_network is True:
                    findings.append(
                        make_finding(
                            self,
                            ctx,
                            severity=Severity.INFO,
                            title="Private network access is allowed by the profile",
                            message=(
                                f"Skipped {tool.name}: "
                                f"tools.{tool.name}.allow_private_network is true."
                            ),
                            case_id=f"{slug(tool.name)}:allow-private-network",
                            steps=[],
                            expect={"allow_private_network": True},
                            tool=tool.name,
                        )
                    )
                    continue
                baseline = await _baseline(ctx, tool, names)
                if baseline is None:
                    continue
                tested = True
                payloads = _payloads(
                    fixtures.canary_ip, fixtures.token, quick=ctx.config.mode == "quick"
                )
                for name in names:
                    for payload_id, url in payloads:
                        arguments = {**baseline, name: url}
                        case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
                        request = request_step(
                            "tools/call", {"name": tool.name, "arguments": arguments}
                        )
                        before = await fixtures.canary_hits()
                        cursor = max((int(h["sequence"]) for h in before), default=0)
                        try:
                            await ctx.call(tool.name, arguments, case_id=case_id)
                        except TargetCrashed:
                            continue  # A crash belongs to the engine, never to this verdict.
                        except RequestTimeout:
                            pass  # A timed-out call may still have reached the canary.
                        hits = await fixtures.canary_hits(since=cursor)
                        hit = next(
                            (
                                h
                                for h in hits
                                if any(
                                    fixtures.token in str(h.get(key, ""))
                                    for key in ("path", "query")
                                )
                            ),
                            None,
                        )
                        if hit is None:
                            continue
                        findings.append(
                            make_finding(
                                self,
                                ctx,
                                severity=(
                                    Severity.CRITICAL
                                    if ctx.runner.transport_kind is Transport.HTTP
                                    else Severity.HIGH
                                ),
                                title="URL tool reached a private canary",
                                message=(
                                    f"{tool.name} reached the private canary "
                                    f"with the scan token ({payload_id})."
                                ),
                                case_id=case_id,
                                steps=[request],
                                expect={"canary_hit": False},
                                observations={
                                    "payload_id": payload_id,
                                    "request": request,
                                    "canary_hit": hit,
                                },
                                tool=tool.name,
                            )
                        )
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("URL safety campaign interrupted before a verdict")
        if not tested and not findings:
            return CheckOutcome.na(_NO_BASELINE)
        return CheckOutcome(findings)


@register
class FileSchemeBlocked(Check):
    meta = CheckMeta(
        id="safety.file_scheme_blocked",
        family=Family.SAFETY,
        title="URL tools do not disclose local files through file URLs",
        severity=Severity.HIGH,
        eras=frozenset({Era.MODERN, Era.LEGACY}),
        transports=frozenset({Transport.STDIO, Transport.HTTP}),
        requires=frozenset({"fixtures", "url_tools", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-73"],
        disclosure=DisclosureTier.PRIVATE,
        rationale="A URL tool accepting file URLs can disclose files outside its intended scope.",
        remediation=(
            "Allow only HTTP(S) URL schemes and reject file URLs before opening a resource."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        tested = False
        try:
            for tool, names in _url_tools(ctx):
                baseline = await _baseline(ctx, tool, names)
                if baseline is None:
                    continue
                tested = True
                for name in names:
                    for payload_id, url in (
                        ("sentinel", "file:///data/secret/SENTINEL"),
                        ("passwd", "file:///etc/passwd"),
                    ):
                        arguments = {**baseline, name: url}
                        case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
                        try:
                            result = await ctx.call(tool.name, arguments, case_id=case_id)
                        except (TargetCrashed, RequestTimeout):
                            continue
                        output = json.dumps(result.response.to_obj(), ensure_ascii=False)
                        marker = next(
                            (
                                m
                                for m in (f"PROBE-SENTINEL-{fixtures.token}", "root:x:0:0")
                                if m in output
                            ),
                            None,
                        )
                        if marker is None:
                            continue
                        request = request_step(
                            "tools/call", {"name": tool.name, "arguments": arguments}
                        )
                        findings.append(
                            make_finding(
                                self,
                                ctx,
                                severity=Severity.HIGH,
                                title="URL tool disclosed a local file",
                                message=f"{tool.name} returned local file contents for {url}.",
                                case_id=case_id,
                                steps=[request],
                                expect={"file_disclosed": False},
                                observations={
                                    "payload_id": payload_id,
                                    "request": request,
                                    "marker": marker,
                                    "response": result.response.to_obj(),
                                },
                                tool=tool.name,
                            )
                        )
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("URL safety campaign interrupted before a verdict")
        if not tested and not findings:
            return CheckOutcome.na(_NO_BASELINE)
        return CheckOutcome(findings)
