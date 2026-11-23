"""protocol.deprecated_features (information only)"""

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import ALL_MODES, http_transport, make_finding
from probe.checks.registry import register
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)

_SSE_PROBE_TIMEOUT_S = 3.0


@register
class DeprecatedFeatures(Check):
    meta = CheckMeta(
        id="protocol.deprecated_features",
        family=Family.PROTOCOL,
        title="Uses of deprecated MCP features",
        severity=Severity.INFO,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/deprecated"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Deprecated features stay in the spec for a while and then go away. Knowing which "
            "ones a server relies on tells its maintainers what to migrate."
        ),
        remediation="Follow the migration paths in the deprecated features registry.",
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        if "logging" in ctx.client.server_capabilities:
            findings.append(
                self._note(
                    ctx,
                    "deprecated:logging",
                    "Logging",
                    "The server advertises the logging capability, deprecated in 2026-07-28. "
                    "Log to stderr (stdio) or use OpenTelemetry instead.",
                )
            )
        if ctx.runner.transport_kind is Transport.HTTP and await self._offers_http_sse(ctx):
            findings.append(
                self._note(
                    ctx,
                    "deprecated:http-sse",
                    "HTTP+SSE transport",
                    "The endpoint serves the deprecated 2024-11-05 HTTP+SSE transport. "
                    "Migrate to Streamable HTTP.",
                )
            )
        return CheckOutcome(findings)

    async def _offers_http_sse(self, ctx: ScanContext) -> bool:
        headers = {**http_transport(ctx).base_headers(), "Accept": "text/event-stream"}
        headers.pop("Content-Type", None)
        result = await ctx.raw_http(headers, b"", method="GET", timeout=_SSE_PROBE_TIMEOUT_S)
        return (
            result.status == 200
            and result.content_type == "text/event-stream"
            and b"event: endpoint" in result.body
        )

    def _note(self, ctx: ScanContext, case_id: str, feature: str, message: str) -> Finding:
        return make_finding(
            self,
            ctx,
            severity=Severity.INFO,
            title=f"{feature} is deprecated",
            message=message,
            case_id=case_id,
            steps=[],
            expect={"feature": "not used"},
            observations={"feature": feature},
        )
