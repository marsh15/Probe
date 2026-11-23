"""protocol.unknown_method_error"""

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import ALL_MODES, make_finding, request_step
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.wire.jsonrpc import METHOD_NOT_FOUND, ErrorResponse

UNKNOWN_METHOD = "probe/does_not_exist"


@register
class UnknownMethodError(Check):
    meta = CheckMeta(
        id="protocol.unknown_method_error",
        family=Family.PROTOCOL,
        title="An unknown method is answered with -32601",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=[
            "https://www.jsonrpc.org/specification#error_object",
            "2026-07-28/basic/transports/streamable-http#sending-messages-to-the-server",
        ],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Clients probe for optional methods and rely on -32601 to learn a feature is "
            "absent. Any other answer makes feature detection unreliable."
        ),
        remediation=(
            "Answer unknown methods with error -32601 (Method not found); over modern HTTP "
            "also use status 404."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        outcome = await ctx.exchange(UNKNOWN_METHOD, case_id="unknown-method")
        problems: list[str] = []
        response = outcome.response
        observed: dict[str, object] = {}
        if response is None:
            problems.append("no response")
        elif not isinstance(response, ErrorResponse):
            problems.append("the server returned a result for a method that does not exist")
        else:
            observed["code"] = response.error.code
            if response.error.code != METHOD_NOT_FOUND:
                problems.append(f"error code is {response.error.code}, not {METHOD_NOT_FOUND}")
        if outcome.http is not None:
            observed["http_status"] = outcome.http.status
            if ctx.era is Era.MODERN and outcome.http.status != 404:
                problems.append(f"HTTP status is {outcome.http.status}, not 404")
        if not problems:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title="Unknown method is not reported as -32601",
                    message="; ".join(problems),
                    case_id="unknown-method:probe",
                    steps=[request_step(UNKNOWN_METHOD)],
                    expect={"code": METHOD_NOT_FOUND},
                    observations={**observed, "problems": problems},
                )
            ]
        )
