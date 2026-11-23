"""HTTP-only protocol checks: header validation and Origin validation (raw requests)."""

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import (
    ALL_MODES,
    accepted,
    error_codes,
    json_body,
    make_finding,
    raw_http_step,
    valid_http_request,
    with_header,
    without_header,
)
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
from probe.wire.session import HEADER_MISMATCH

EVIL_ORIGIN = "http://evil.probe.test"
# A header version no server supports in either era. A real older version (say 2025-11-25) would
# send a dual-era server down its legacy path, which fails for unrelated reasons (no session).
MISMATCHED_VERSION = "1999-01-01"
# The version header appeared in this legacy revision; servers that still support clients older
# than it may legitimately accept a request without the header.
_HEADER_SINCE = "2025-06-18"


@register
class HeaderMismatchRejected(Check):
    meta = CheckMeta(
        id="protocol.header_mismatch_rejected",
        family=Family.PROTOCOL,
        title="Headers that disagree with the request body are rejected",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"http"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/basic/transports/streamable-http#server-validation"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Gateways route and authorize on the Mcp-Method and version headers. If the server "
            "trusts the body when the headers disagree, a proxy can be tricked into applying "
            "the policy of one method to another."
        ),
        remediation=(
            "Compare Mcp-Method, Mcp-Name and MCP-Protocol-Version with the body and answer a "
            "mismatch with HTTP 400 and error -32020."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        # (case id, description, message, headers) built from one valid request each.
        call, call_headers = valid_http_request(
            ctx, "tools/call", {"name": "probe-header-mismatch", "arguments": {}}
        )
        listing, list_headers = valid_http_request(ctx, "tools/list")
        cases = [
            (
                "header-mismatch:method",
                "Mcp-Method says tools/list but the body is tools/call",
                call,
                with_header(call_headers, "Mcp-Method", "tools/list"),
            ),
            (
                "header-mismatch:version",
                "MCP-Protocol-Version differs from the version in _meta",
                listing,
                with_header(list_headers, "MCP-Protocol-Version", MISMATCHED_VERSION),
            ),
        ]
        for case_id, description, message, headers in cases:
            body = json_body(message)
            result = await ctx.raw_http(headers, body)
            codes = error_codes(result)
            if result.status == 400 and HEADER_MISMATCH in codes:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title="Header/body mismatch was not rejected",
                    message=(
                        f"{description}; expected HTTP 400 with -32020, got status "
                        f"{result.status} and error codes {codes}"
                    ),
                    case_id=case_id,
                    steps=[raw_http_step(headers, body)],
                    expect={"http_status": 400, "code": HEADER_MISMATCH},
                    observations={"http_status": result.status, "error_codes": codes},
                    excerpt=result.body.decode("utf-8", "replace"),
                )
            )
        return CheckOutcome(findings)


@register
class RequiredHeadersEnforced(Check):
    meta = CheckMeta(
        id="protocol.required_headers_enforced",
        family=Family.PROTOCOL,
        title="Requests missing the required headers are rejected",
        severity=Severity.LOW,
        eras=frozenset({Era.MODERN}),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"http"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/basic/transports/streamable-http#request-metadata"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "MCP-Protocol-Version and Mcp-Method are required so intermediaries can route "
            "without parsing bodies. A server that accepts requests without them makes those "
            "intermediaries unreliable."
        ),
        remediation="Reject requests without MCP-Protocol-Version or Mcp-Method with HTTP 400.",
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        older = any(v < _HEADER_SINCE for v in ctx.client.supported_versions)
        names = ["Mcp-Method"] if older else ["MCP-Protocol-Version", "Mcp-Method"]
        findings: list[Finding] = []
        for name in names:
            message, headers = valid_http_request(ctx, "tools/list")
            tampered = without_header(headers, name)
            body = json_body(message)
            result = await ctx.raw_http(tampered, body)
            if not accepted(result):
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title=f"Request without {name} was accepted",
                    message=f"The server returned a result for a request lacking {name}.",
                    case_id=f"required-header:{name.lower()}",
                    steps=[raw_http_step(tampered, body)],
                    expect={"http_status": 400},
                    observations={"http_status": result.status, "missing_header": name},
                )
            )
        return CheckOutcome(findings)


@register
class OriginValidated(Check):
    meta = CheckMeta(
        id="protocol.origin_validated",
        family=Family.PROTOCOL,
        title="A request from an untrusted Origin is rejected",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset({Transport.HTTP}),
        requires=frozenset({"http"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["2026-07-28/basic/transports/streamable-http#security-warning"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "Without Origin validation a web page the user visits can call a locally running "
            "MCP server (DNS rebinding) and use its tools with the user's authority."
        ),
        remediation=(
            "Validate the Origin header on every request and reject a present but untrusted "
            "origin with HTTP 403; bind local servers to 127.0.0.1."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        message, headers = valid_http_request(ctx, "tools/list")
        tampered = with_header(headers, "Origin", EVIL_ORIGIN)
        body = json_body(message)
        result = await ctx.raw_http(tampered, body)
        if not accepted(result):
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title="Request from an untrusted Origin was served",
                    message=f"A request with Origin {EVIL_ORIGIN} returned a result (HTTP "
                    f"{result.status}) instead of being rejected.",
                    case_id="origin:untrusted",
                    steps=[raw_http_step(tampered, body)],
                    expect={"http_status": 403},
                    observations={"http_status": result.status, "origin": EVIL_ORIGIN},
                )
            ]
        )
