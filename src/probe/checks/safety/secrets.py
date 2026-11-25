"""safety.no_secret_leak"""

import contextlib
import re

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.safety._support import (
    excerpt,
    safe_call,
    tool_replies,
    valid_arguments,
)
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.config.profile import Profile
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetUnstable
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)
from probe.util.redact import REDACTED

_MAX_FINDINGS = 10
_TOOLS_TRIGGERED = 6
_FAULT_CALLS = 2
_GENERIC = (
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    (
        "private key",
        re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?(?:-----END \1-----|$)", re.DOTALL),
    ),
    ("API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
)
_MIN_SECRET = 8


def _injected(ctx: ScanContext) -> list[str]:
    """The fake secret values Probe gave the server (they are evidence, not credentials)."""
    profile = ctx.profile
    if not isinstance(profile, Profile):
        return []
    return [
        s.value
        for s in profile.target.secrets.values()
        if not s.real and len(s.value) >= _MIN_SECRET
    ]


def _leaks(text: str, injected: list[str]) -> list[tuple[Severity, str, str]]:
    found: list[tuple[Severity, str, str]] = []
    masked = text
    for _, pattern in _GENERIC:
        masked = pattern.sub(REDACTED, masked)

    def sample(at: int) -> str:
        prefix = text[:at]
        for _, pattern in _GENERIC:
            prefix = pattern.sub(REDACTED, prefix)
        return excerpt(masked, len(prefix))

    for value in injected:
        at = text.find(value)
        if at >= 0:
            found.append((Severity.HIGH, "injected secret", sample(at)))
    for label, pattern in _GENERIC:
        match = pattern.search(text)
        if match:
            # Mask all matches before excerpting; a nearby credential must not leak either.
            found.append((Severity.MEDIUM, label, sample(match.start())))
    return found


@register
class NoSecretLeak(Check):
    meta = CheckMeta(
        id="safety.no_secret_leak",
        family=Family.SAFETY,
        title="Credentials the server holds never appear in what it sends back",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"fixtures", "tools"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-200", "CWE-532"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "A server that echoes an API key, token or private key in an answer or an error "
            "hands it to every client and model that sees the transcript."
        ),
        remediation=(
            "Keep credentials out of error text and logs sent to clients; redact them before "
            "any message leaves the server."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        with contextlib.suppress(BudgetExhausted, TargetUnstable):  # judge what was seen so far
            await self._provoke_backend_errors(ctx)
        injected = _injected(ctx)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for reply in tool_replies(ctx):
            for severity, kind, sample in _leaks(reply.text, injected):
                if (reply.tool, kind) in seen:
                    continue
                seen.add((reply.tool, kind))
                findings.append(
                    make_finding(
                        self,
                        ctx,
                        severity=severity,
                        title=f"{reply.tool} sent a {kind} to the client",
                        message=f"An answer from {reply.tool} contains a {kind}.",
                        case_id=f"secret-leak:{slug(reply.tool)}:{slug(kind)}",
                        steps=[
                            request_step(
                                "tools/call", {"name": reply.tool, "arguments": reply.arguments}
                            )
                        ],
                        expect={"secrets_in_output": "none"},
                        observations={"kind": kind, "excerpt": sample},
                        tool=reply.tool,
                    )
                )
        return CheckOutcome(findings[:_MAX_FINDINGS])

    async def _provoke_backend_errors(self, ctx: ScanContext) -> None:
        """Make tools that call the backend fail, because errors are where credentials leak."""
        fixtures = ctx.fixtures
        if fixtures is None:
            return
        tried = 0
        for tool in ctx.callable_tools():
            if tool.kind != "read" or tried >= _TOOLS_TRIGGERED:
                continue
            arguments = await valid_arguments(ctx, tool)
            if arguments is None:
                continue
            tried += 1
            before = await fixtures.backend_log()
            cursor = max((r["sequence"] for r in before), default=0)
            await safe_call(ctx, tool.name, arguments, f"secret-baseline:{slug(tool.name)}")
            routes = sorted({r["path"] for r in await fixtures.backend_log(cursor)})
            armed = False
            try:
                for route in routes:
                    armed |= await fixtures.backend_fault(route, count=_FAULT_CALLS)
                for _ in range(_FAULT_CALLS if armed else 0):
                    await safe_call(ctx, tool.name, arguments, f"secret-fault:{slug(tool.name)}")
            finally:
                if armed:
                    await fixtures.backend_fault(None)
