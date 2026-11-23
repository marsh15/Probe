"""protocol.unsupported_version_error"""

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import ALL_MODES, make_finding, request_step
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.wire.jsonrpc import ErrorResponse
from probe.wire.session import META_VERSION, UNSUPPORTED_PROTOCOL_VERSION

UNKNOWN_VERSION = "1999-01-01"


@register
class UnsupportedVersionError(Check):
    meta = CheckMeta(
        id="protocol.unsupported_version_error",
        family=Family.PROTOCOL,
        title="An unsupported protocol version is rejected with -32022",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/basic/versioning#protocol-version-negotiation"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "There is no handshake: a client learns which versions a server speaks from the "
            "error to a request with a version it does not support. Without the right error "
            "clients cannot recover."
        ),
        remediation=(
            "Reject unsupported versions with code -32022 (HTTP 400) and data.supported listing "
            "your versions and data.requested echoing the version that was sent."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        outcome = await ctx.exchange(
            "tools/list", meta={META_VERSION: UNKNOWN_VERSION}, case_id="unsupported-version"
        )
        problems: list[str] = []
        response = outcome.response
        observed: dict[str, object] = {"sent_version": UNKNOWN_VERSION}
        if response is None:
            problems.append("no response")
        elif not isinstance(response, ErrorResponse):
            problems.append("the request succeeded instead of being rejected")
        else:
            error = response.error
            observed["code"] = error.code
            if error.code != UNSUPPORTED_PROTOCOL_VERSION:
                problems.append(f"error code is {error.code}, not {UNSUPPORTED_PROTOCOL_VERSION}")
            data = error.data if isinstance(error.data, dict) else {}
            supported = data.get("supported")
            if not (isinstance(supported, list) and all(isinstance(v, str) for v in supported)):
                problems.append("data.supported is missing or not a list of strings")
            if data.get("requested") != UNKNOWN_VERSION:
                problems.append(f"data.requested is not {UNKNOWN_VERSION!r}")
        if outcome.http is not None:
            observed["http_status"] = outcome.http.status
            if outcome.http.status != 400:
                problems.append(f"HTTP status is {outcome.http.status}, not 400")
        if not problems:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title="Unsupported protocol version is not reported as -32022",
                    message="; ".join(problems),
                    case_id="unsupported-version:1999",
                    steps=[request_step("tools/list", {"_meta": {META_VERSION: UNKNOWN_VERSION}})],
                    expect={"code": UNSUPPORTED_PROTOCOL_VERSION, "http_status": 400},
                    observations={**observed, "problems": problems},
                )
            ]
        )
