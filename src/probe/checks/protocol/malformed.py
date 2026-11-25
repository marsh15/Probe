"""protocol.malformed_jsonrpc_handled"""

import asyncio
from functools import partial

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.protocol._support import (
    ALL_MODES,
    error_codes,
    http_transport,
    make_finding,
    raw_http_step,
    raw_stdio_step,
)
from probe.checks.registry import register
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)
from probe.wire.errors import UnmatchedResponse
from probe.wire.transport_stdio import StdioTransport

_PARSE_ERROR, _INVALID_REQUEST = -32700, -32600
_ACCEPTABLE = frozenset({_PARSE_ERROR, _INVALID_REQUEST})
_REPLY_WAIT_S = 3.0
_BATCHES_REMOVED_IN = "2025-06-18"
CASES: tuple[tuple[str, bytes], ...] = (
    ("invalid-json", b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"'),
    ("missing-jsonrpc", b'{"id": 1, "method": "tools/list"}'),
    ("batch-array", b'[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]'),
)


@register
class MalformedJsonrpcHandled(Check):
    meta = CheckMeta(
        id="protocol.malformed_jsonrpc_handled",
        family=Family.PROTOCOL,
        title="Malformed JSON-RPC input gets an error and does not hurt the server",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["https://www.jsonrpc.org/specification#error_object"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Any client or attacker can send garbage. A server must answer it with a JSON-RPC "
            "error and keep serving; one that hangs or dies on bad input can be taken down by it."
        ),
        remediation=(
            "Return -32700 for unparseable JSON and -32600 for an invalid request (HTTP 400), "
            "and never let a malformed message crash or wedge the server."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        not_reproduced: list[str] = []
        cases = [
            case
            for case in CASES
            if not (case[0] == "batch-array" and ctx.negotiated_version < _BATCHES_REMOVED_IN)
        ]
        for case_id, body in cases:
            try:
                verdict = await self._try_case(ctx, case_id, body)
            except (TargetUnstable, BudgetExhausted):
                # The restart or call budget ran out. If the server already failed this check,
                # say so; otherwise Probe could not finish and the engine reports why.
                if findings:
                    break
                raise
            if isinstance(verdict, Finding):
                findings.append(verdict)
            elif verdict == "not-reproduced":
                not_reproduced.append(case_id)
        if findings:
            return CheckOutcome(findings)
        if not_reproduced:
            return CheckOutcome.error(
                f"the server stopped answering after {', '.join(not_reproduced)} but the crash "
                "did not reproduce"
            )
        return CheckOutcome()

    async def _try_case(self, ctx: ScanContext, case_id: str, body: bytes) -> Finding | str | None:
        """Send one case. A Finding if it was mishandled or crashed the server (reproducibly),
        "not-reproduced" for a crash that did not happen again, None if all was well."""
        died = False
        codes: list[int] = []
        status: int | None = None
        try:
            codes, status = await self._send(ctx, case_id, body)
        except TargetCrashed:
            died = True  # the write itself failed; the target is already restarted
        if not died and await ctx.liveness():
            if _ACCEPTABLE & set(codes) or status == 400:
                return None
            return self._finding(ctx, case_id, body, codes, status)
        # The server stopped answering after this input. Hold that against it only if the same
        # input does it again on a fresh instance.
        # TargetUnstable means no restart is left, so nothing was re-sent: the crash was not
        # reproduced, and the caller reports an error rather than a finding.
        survived = await ctx.survives(partial(self._send, ctx, case_id, body))
        return "not-reproduced" if survived else self._crash_finding(ctx, case_id, body)

    async def _send(
        self, ctx: ScanContext, case_id: str, body: bytes
    ) -> tuple[list[int], int | None]:
        """Send one malformed message; return the error codes seen and the HTTP status."""
        transport = ctx.client.transport
        if isinstance(transport, StdioTransport):
            before = len(transport.events())
            await ctx.raw_stdio(body + b"\n", case_id=case_id)
            return await self._stdio_codes(transport, before), None
        result = await ctx.raw_http(self._http_headers(ctx), body)
        return error_codes(result), result.status

    @staticmethod
    def _http_headers(ctx: ScanContext) -> dict[str, str]:
        return {
            **http_transport(ctx).base_headers(),
            **ctx.client.headers_for({"method": "tools/list"}),
        }

    @staticmethod
    async def _stdio_codes(transport: StdioTransport, before: int) -> list[int]:
        deadline = asyncio.get_running_loop().time() + _REPLY_WAIT_S
        while True:
            codes = [
                e.error_code
                for e in transport.events()[before:]
                if isinstance(e, UnmatchedResponse) and e.error_code is not None
            ]
            if codes or not transport.alive() or asyncio.get_running_loop().time() >= deadline:
                return codes
            await asyncio.sleep(0.02)

    def _step(self, ctx: ScanContext, body: bytes) -> dict[str, object]:
        if isinstance(ctx.client.transport, StdioTransport):
            return raw_stdio_step(body + b"\n")
        return raw_http_step(self._http_headers(ctx), body)

    def _finding(
        self, ctx: ScanContext, case_id: str, body: bytes, codes: list[int], status: int | None
    ) -> Finding:
        return make_finding(
            self,
            ctx,
            severity=Severity.MEDIUM,
            title="Malformed JSON-RPC was not answered with an error",
            message=(
                f"Case {case_id!r}: expected -32700 or -32600 (or HTTP 400); got error codes "
                f"{codes} and HTTP status {status}."
            ),
            case_id=f"malformed:{case_id}",
            steps=[self._step(ctx, body)],
            expect={"codes": sorted(_ACCEPTABLE), "http_status": 400},
            observations={"error_codes": codes, "http_status": status},
        )

    def _crash_finding(self, ctx: ScanContext, case_id: str, body: bytes) -> Finding:
        return make_finding(
            self,
            ctx,
            severity=Severity.MEDIUM,
            title="Malformed JSON-RPC makes the server stop answering",
            message=f"After case {case_id!r} the server stopped answering, also when retried.",
            case_id=f"malformed:{case_id}:crash",
            steps=[self._step(ctx, body)],
            expect={"alive_after": True},
            observations={"reproduced_on_fresh_instance": True},
        )
