"""safety.request_state_integrity"""

from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import outcomes
from probe.checks.behavior._support import clip, input_askers, input_policy
from probe.checks.context import ScanContext
from probe.checks.registry import register
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
    Transport,
)
from probe.wire.errors import RequestTimeout
from probe.wire.jsonrpc import Response, ResultResponse
from probe.wire.mrtr import InputPolicy, is_input_required, retry_params

_TOOLS_TRIED = 2
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _flip(text: str, at: int) -> str:
    """``text`` with one character swapped for another valid base64url character."""
    char = text[at]
    other = _ALPHABET[(_ALPHABET.find(char) + 1) % len(_ALPHABET)] if char in _ALPHABET else "A"
    return text[:at] + other + text[at + 1 :]


def tampered(state: str) -> list[tuple[str, str]]:
    """Versions of ``state`` that stay well-formed text but differ: the last segment (usually a
    signature) and the first long one (usually the payload) with one character changed."""
    segments = state.split(".")
    variants: list[tuple[str, str]] = []
    last = segments[-1]
    if len(segments) > 1 and last:
        variants.append(("signature", ".".join([*segments[:-1], _flip(last, len(last) // 2)])))
    longest = max(range(len(segments)), key=lambda i: len(segments[i]))
    body = segments[longest]
    if len(body) > 2:
        edited = [*segments]
        edited[longest] = _flip(body, len(body) // 2)
        variants.append(("payload", ".".join(edited)))
    return [(label, value) for label, value in variants if value != state]


def _completed(response: Response | None) -> bool:
    """The server finished the request (a result that is not an error and wants no more input)."""
    if not isinstance(response, ResultResponse) or not isinstance(response.result, dict):
        return False
    return response.result.get("isError") is not True and not is_input_required(response)


def _state(response: Response | None) -> str | None:
    if is_input_required(response) and isinstance(response, ResultResponse):
        value = response.result.get("requestState") if isinstance(response.result, dict) else None
        return value if isinstance(value, str) and value else None
    return None


@register
class RequestStateIntegrity(Check):
    meta = CheckMeta(
        id="safety.request_state_integrity",
        family=Family.SAFETY,
        title="A forged or borrowed requestState is refused",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(Transport),
        requires=frozenset({"tools", "mrtr"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        min_version="2026-07-28",
        spec_refs=["2026-07-28/basic/patterns/mrtr#request-state"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "requestState travels through the client and comes back. A server that trusts it "
            "without checking a signature lets a caller edit the state, or reuse one from "
            "another request, and steer what the server does next."
        ),
        remediation=(
            "Sign (or encrypt) requestState, bind it to the request it belongs to and an "
            "expiry, and reject any state that does not verify."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        asking = input_askers(ctx, await outcomes(ctx, "valid"))
        if not asking:
            return CheckOutcome.na("no tool asked for input during the valid-input campaign")
        policy = input_policy(ctx)
        findings: list[Finding] = []
        judged = False
        try:
            for tool, (params, meta) in list(asking.items())[:_TOOLS_TRIED]:
                outcome = await self._judge(ctx, tool, params, meta, policy)
                if outcome is not None:
                    judged = True
                    findings += outcome
        except (RequestTimeout, BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("state campaign interrupted before a verdict")
        if not judged:
            return CheckOutcome.na("no clean retry could be completed to compare against")
        return CheckOutcome(findings)

    async def _send(
        self, ctx: ScanContext, tool: str, params: dict[str, Any], meta: dict[str, Any] | None
    ) -> Response:
        return await ctx.request("tools/call", params, meta=meta, case_id=f"state:{slug(tool)}")

    async def _judge(
        self,
        ctx: ScanContext,
        tool: str,
        params: dict[str, Any],
        meta: dict[str, Any] | None,
        policy: InputPolicy,
    ) -> list[Finding] | None:
        first = await self._send(ctx, tool, params, meta)
        state = _state(first)
        if state is None or not isinstance(first, ResultResponse):
            return None  # the tool no longer asks, or sends no state to tamper with
        result = first.result if isinstance(first.result, dict) else {}
        honest = retry_params(params, result, policy)
        if not _completed(await self._send(ctx, tool, honest, meta)):
            return None  # without a working retry there is nothing to compare against
        findings: list[Finding] = []
        for label, forged in tampered(state):
            retry = {**honest, "requestState": forged}
            if _completed(await self._send(ctx, tool, retry, meta)):
                findings.append(
                    self._finding(
                        ctx,
                        tool,
                        retry,
                        f"edited ({label})",
                        f"a requestState with one changed character in its {label}",
                    )
                )
        foreign = await self._foreign_state(ctx, tool, params, meta)
        if foreign is not None:
            retry = {**honest, "requestState": foreign}
            if _completed(await self._send(ctx, tool, retry, meta)):
                findings.append(
                    self._finding(
                        ctx, tool, retry, "borrowed", "a requestState issued for another call"
                    )
                )
        return findings

    async def _foreign_state(
        self, ctx: ScanContext, tool: str, params: dict[str, Any], meta: dict[str, Any] | None
    ) -> str | None:
        """A state the server issued for different arguments, or None when no other call asks."""
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            return None
        for key, value in arguments.items():
            if isinstance(value, int) and not isinstance(value, bool):
                other = {**params, "arguments": {**arguments, key: value + 1}}
                return _state(await self._send(ctx, tool, other, meta))
        return None

    def _finding(
        self, ctx: ScanContext, tool: str, retry: dict[str, Any], how: str, what: str
    ) -> Finding:
        return make_finding(
            self,
            ctx,
            severity=Severity.MEDIUM,
            title=f"{tool} accepted a {how} requestState",
            message=clip(f"{tool} completed a retry that carried {what}."),
            case_id=f"request-state:{slug(tool)}:{slug(how)}",
            steps=[request_step("tools/call", retry)],
            expect={"retry": "refused (invalid or expired state)"},
            observations={"variant": how},
            tool=tool,
        )
