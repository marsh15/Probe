"""What tools return for big requests and for requests that match nothing."""

import json
import re
from typing import Any

from jsonschema.validators import Draft202012Validator, validator_for

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.behavior._campaign import Outcome, campaign, run_case
from probe.checks.behavior._support import (
    ALL_MODES,
    Verdict,
    conclude,
    drop_paging,
    tool_findings,
)
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, ToolInfo
from probe.engine.outcomes import Transport as TransportKind
from probe.schema.cases import Case
from probe.wire.limits import MAX_MESSAGE_BYTES, MAX_RESULT_BYTES_CHECK

_LIMIT_NAME = re.compile(
    r"(limit|page_?size|per_?page|max_?results?|max_?items|count|top|top_?k|size)", re.IGNORECASE
)
_QUERY_NAME = re.compile(
    r"(query|q|search|term|keywords?|text|filter|pattern|title|tag|name)", re.IGNORECASE
)
_BIG_FILE = "/data/allowed/big.log"
_UNBOUNDED_LIMIT = 1_000_000
_MAX_TOOLS = 6
# A tool that caps its data at 1 MiB wraps it in JSON, and escaping (newlines, quotes) adds a
# few percent; an unbounded tool is off by far more than that.
_FRAMING_SLACK = MAX_RESULT_BYTES_CHECK // 10


def _valid(tool: ToolInfo, arguments: Any) -> bool:
    schema = tool.input_schema
    try:
        return bool(validator_for(schema, default=Draft202012Validator)(schema).is_valid(arguments))
    except Exception:
        return False


def _properties(tool: ToolInfo) -> dict[str, Any]:
    properties = tool.input_schema.get("properties")
    return properties if isinstance(properties, dict) else {}


def _base(book_valid: list[Case]) -> dict[str, Any] | None:
    """The first generated valid arguments (an object), or None."""
    first = next((c.arguments for c in book_valid if isinstance(c.arguments, dict)), None)
    return drop_paging(first) if first is not None else None


def _result_bytes(outcome: Outcome) -> int:
    """The payload size: the text blocks, or the structured value if that is larger. (The same
    data often appears in both; JSON framing around it is not counted.)"""
    result = outcome.result
    if result is None:
        return 0
    blocks = result.get("content")
    text = (
        sum(
            len(b["text"].encode("utf-8", "replace"))
            for b in blocks
            if isinstance(b, dict) and isinstance(b.get("text"), str)
        )
        if isinstance(blocks, list)
        else 0
    )
    structured = result.get("structuredContent")
    return max(text, len(json.dumps(structured)) if structured is not None else 0)


def _case(tool: ToolInfo, rule: str, index: int, arguments: dict[str, Any]) -> Case:
    return Case(tool.name, "valid", rule, index, arguments)


@register
class OutputBounded(Check):
    meta = CheckMeta(
        id="behavior.output_bounded",
        family=Family.BEHAVIOR,
        title="A single result stays under 1 MiB",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.stress",
        spec_refs=["2026-07-28/server/tools"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A tool that returns a whole large file or table in one result can exhaust the "
            "client's memory and the model's context. List, search and read tools must page "
            "or truncate."
        ),
        remediation=(
            "Cap the size of every result (default and maximum page size, byte limit on file "
            "reads) and tell the caller how to get the rest."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(self._requests(t) for t in ctx.callable_tools() if t.kind == "read"):
            return Applicability.no("no read tool has a page-size or path parameter to push")
        return Applicability.yes()

    @staticmethod
    def _requests(tool: ToolInfo) -> list[tuple[str, dict[str, Any]]]:
        """(rule, arguments) pairs aimed at making the result as large as the tool allows."""
        properties = _properties(tool)
        base: dict[str, Any] = {
            name: None for name in tool.input_schema.get("required", []) if name in properties
        }
        found: list[tuple[str, dict[str, Any]]] = []
        for name, spec in properties.items():
            if (
                _LIMIT_NAME.fullmatch(name)
                and isinstance(spec, dict)
                and spec.get("type")
                in (
                    "integer",
                    "number",
                )
            ):
                top = spec.get("maximum", _UNBOUNDED_LIMIT)
                found.append((f"max-{name}", {**base, name: top}))
        for name, role in tool.param_roles.items():
            if role == "path_param":
                found.append((f"big-file-{name}", {**base, name: _BIG_FILE}))
        return found

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        bad: dict[str, list[Verdict]] = {}
        judged = 0
        for plan in book.plans:
            tool = plan.tool
            if tool.kind != "read":
                continue
            seed = _base(plan.valid) or {}
            for index, (rule, wanted) in enumerate(self._requests(tool)[:3]):
                arguments = {**seed, **{k: v for k, v in wanted.items() if v is not None}}
                if not _valid(tool, arguments):
                    continue
                outcome = await run_case(ctx, _case(tool, rule, index, arguments))
                judged += 1
                http = outcome.exchange.http if outcome.exchange is not None else None
                size = _result_bytes(outcome)
                if http is not None and http.aborted:
                    reason = f"the result passed {MAX_MESSAGE_BYTES // 2**20} MiB and was cut off"
                elif size > MAX_RESULT_BYTES_CHECK + _FRAMING_SLACK:
                    reason = f"one result was {size / 2**20:.2f} MiB (limit 1 MiB)"
                else:
                    continue
                bad.setdefault(tool.name, []).append(Verdict(outcome, reason))
            if judged >= _MAX_TOOLS * 3:
                break
        if not judged:
            return CheckOutcome.na("could not build a request that asks for a large result")
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                bad,
                severity=Severity.MEDIUM,
                title="Unbounded result size",
                case_prefix="output-bounded",
                expect={"result_bytes": f"<= {MAX_RESULT_BYTES_CHECK}"},
            )
        )


@register
class EmptyResultOk(Check):
    meta = CheckMeta(
        id="behavior.empty_result_ok",
        family=Family.BEHAVIOR,
        title="A search that matches nothing is not an error",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="active.safe",
        spec_refs=["2026-07-28/server/tools#error-handling"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Finding nothing is a normal outcome. A server that answers it with a protocol "
            "error or a crash breaks clients that search first and act on the result."
        ),
        remediation="Return an empty result (not a JSON-RPC error) when nothing matches.",
    )

    @staticmethod
    def _queries(tool: ToolInfo) -> list[str]:
        return [
            name
            for name, spec in _properties(tool).items()
            if isinstance(spec, dict)
            and spec.get("type") == "string"
            and _QUERY_NAME.fullmatch(name)
        ]

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(self._queries(t) for t in ctx.callable_tools() if t.kind == "read"):
            return Applicability.no("no read tool takes a free-text query")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        book = await campaign(ctx)
        needle = f"zz-probe-no-match-{ctx.config.seed:x}"
        bad: dict[str, list[Verdict]] = {}
        unreproduced: list[Outcome] = []
        judged = 0
        for plan in book.plans:
            if plan.tool.kind != "read" or judged >= _MAX_TOOLS:
                continue
            base = _base(plan.valid)
            for name in self._queries(plan.tool)[:1]:
                if base is None or not _valid(plan.tool, {**base, name: needle}):
                    continue
                if not (await run_case(ctx, _case(plan.tool, "no-match-baseline", 0, base))).ok:
                    continue
                outcome = await run_case(
                    ctx, _case(plan.tool, "no-match", 0, {**base, name: needle})
                )
                judged += 1
                if outcome.rpc_error is not None:
                    reason = f"a JSON-RPC error ({outcome.rpc_error.error.code}) for an empty match"
                elif outcome.failed_hard and outcome.reproduced:
                    reason = "the server stopped answering on an empty match"
                elif outcome.failed_hard:
                    unreproduced.append(outcome)
                    continue
                else:
                    continue
                bad.setdefault(plan.tool.name, []).append(Verdict(outcome, reason))
        if not judged:
            return CheckOutcome.na("no eligible query tool had a successful baseline call")
        findings = tool_findings(
            self,
            ctx,
            bad,
            severity=Severity.LOW,
            title="Empty match treated as an error",
            case_prefix="empty-result",
            expect={"result": "an empty, successful result"},
        )
        return conclude(findings, unreproduced)
