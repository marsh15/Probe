"""behavior.mrtr_wellformed"""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import Outcome, outcomes
from probe.checks.behavior._support import clip, input_policy
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity
from probe.engine.outcomes import Transport as TransportKind
from probe.wire.errors import RequestTimeout
from probe.wire.jsonrpc import ErrorResponse, Response
from probe.wire.mrtr import MAX_ROUNDS, call_with_mrtr, is_input_required

_TOOLS_TRIED = 3
_MISSING_CAPABILITY = -32021
_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"


def _required_capabilities(outcome: Outcome) -> dict[str, Any] | None:
    """What a server says it needs from the client before it will answer (error -32021)."""
    error = outcome.rpc_error
    if error is None or error.error.code != _MISSING_CAPABILITY:
        return None
    data = error.error.data
    required = data.get("requiredCapabilities") if isinstance(data, dict) else None
    return required if isinstance(required, dict) else None


@register
class MrtrWellformed(Check):
    meta = CheckMeta(
        id="behavior.mrtr_wellformed",
        family=Family.BEHAVIOR,
        title="Requests for input are well formed and the retry completes",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools", "mrtr"}),
        modes=frozenset({"quick", "standard", "deep"}),
        phase="active.write",
        min_version="2026-07-28",
        spec_refs=["2026-07-28/basic/patterns/mrtr"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A server that needs confirmation or more details answers with input requests the "
            "client must understand. A request with no method, an unknown method or a broken "
            "schema leaves the client unable to ask the user, so the call can never finish."
        ),
        remediation=(
            "Give every inputRequests entry a method (elicitation/create, sampling/createMessage "
            "or roots/list) and valid params, and complete the call once the retry carries the "
            "answers and the echoed requestState."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        valid = await outcomes(ctx, "valid")
        # Tools that asked for input, and tools that would if the client said it can answer.
        asking: dict[str, tuple[dict[str, Any], dict[str, Any] | None]] = {}
        for outcome in valid:
            if outcome.case.tool in asking:
                continue
            if is_input_required(outcome.response):
                asking[outcome.case.tool] = (outcome.params, None)
            elif (needs := _required_capabilities(outcome)) is not None:
                capabilities = {**ctx.client.client_capabilities, **needs}
                asking[outcome.case.tool] = (outcome.params, {_CAPABILITIES: capabilities})
        if not asking:
            return CheckOutcome.na("no tool asked for input during the valid-input campaign")
        policy = input_policy(ctx)
        findings = []
        for tool, (params, meta) in list(asking.items())[:_TOOLS_TRIED]:

            async def send(
                method: str,
                body: dict[str, Any],
                tool: str = tool,
                meta: dict[str, Any] | None = meta,
            ) -> Response:
                return await ctx.request(method, body, meta=meta, case_id=f"mrtr:{tool}")

            try:
                run = await call_with_mrtr(send, "tools/call", params, policy)
            except RequestTimeout:
                problems = ["the server did not answer a round in time"]
                rounds = 0
            else:
                problems = list(run.violations)
                rounds = len(run.rounds)
                if run.exceeded:
                    problems.append(f"still asking for input after {MAX_ROUNDS} retries")
                elif isinstance(run.final, ErrorResponse):
                    problems.append(
                        f"the retry failed with error {run.final.error.code}: "
                        f"{clip(run.final.error.message, 120)}"
                    )
            if not problems:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.MEDIUM,
                    title=f"{tool} did not complete its multi round-trip flow cleanly",
                    message=clip("; ".join(problems), 400),
                    tool=tool,
                    case_id=f"mrtr:{tool}",
                    steps=[request_step("tools/call", params)],
                    expect={"input_requests": "well formed", "retry": "completes"},
                    observations={"problems": problems[:8], "rounds": rounds},
                )
            )
        return CheckOutcome(findings)
