"""safety.no_stack_traces, safety.no_hidden_instructions: what a server's words give away or
smuggle in."""

import json
import re
from collections.abc import Iterator
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.safety._support import ToolReply, excerpt, tool_replies
from probe.checks.support import ALL_MODES, make_finding, request_step, slug
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Transport,
)

_MAX_FINDINGS = 10

_PYTHON = re.compile(r"Traceback \(most recent call last\)")
_NODE = re.compile(r"^\s+at .+\(.+:\d+:\d+\)", re.MULTILINE)
_GO = re.compile(r"goroutine \d+ \[")
_JAVA = re.compile(r"^\s*at [\w.$]+\(", re.MULTILINE)


def _stack_trace(text: str) -> str | None:
    if _PYTHON.search(text):
        return "Python traceback"
    if len(_NODE.findall(text)) >= 2:
        return "Node.js stack"
    if _GO.search(text):
        return "Go goroutine dump"
    if len(_JAVA.findall(text)) >= 2:
        return "Java stack trace"
    return None


@register
class NoStackTraces(Check):
    meta = CheckMeta(
        id="safety.no_stack_traces",
        family=Family.SAFETY,
        title="Errors do not show stack traces",
        severity=Severity.LOW,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["CWE-209"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A stack trace in a tool's answer shows file paths, library versions and code "
            "structure, and it goes to whatever model reads the answer."
        ),
        remediation=(
            "Catch exceptions at the tool boundary, log the trace on the server, and return a "
            "short message that says what the caller can do about it."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not tool_replies(ctx):
            return Applicability.no("no tool answers were recorded")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        seen: set[str] = set()
        for reply in tool_replies(ctx):
            kind = _stack_trace(reply.text)
            if kind is None or reply.tool in seen:
                continue
            seen.add(reply.tool)
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.LOW,
                    title=f"{reply.tool} showed a {kind}",
                    message=f"An answer from {reply.tool} contains a {kind}.",
                    case_id=f"stack-trace:{slug(reply.tool)}",
                    steps=[
                        request_step(
                            "tools/call", {"name": reply.tool, "arguments": reply.arguments}
                        )
                    ],
                    expect={"stack_trace": "none in tool answers"},
                    observations={"kind": kind, "excerpt": reply.text[:300]},
                    tool=reply.tool,
                )
            )
            if len(findings) >= _MAX_FINDINGS:
                break
        return CheckOutcome(findings)


_TAGS = re.compile("[\U000e0000-\U000e007f]")
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_PHRASE = re.compile(
    r"(?i)(ignore (all )?(previous|prior) instructions|you must now"
    r"|<\s*important\s*>|system prompt)"
)


def _strings(value: Any) -> Iterator[str]:
    """Every string in a JSON value (decoded, so an escaped character shows up as itself)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _decoded(text: str) -> Iterator[str]:
    yield text
    try:
        parsed = json.loads(text)
    except ValueError:
        return
    if isinstance(parsed, dict | list):
        yield from _strings(parsed)


def hidden_text(text: str, echoed: str = "") -> list[tuple[str, str]]:
    """(kind, excerpt) for each hidden or instruction-like thing in ``text``, ignoring what the
    caller sent in itself (``echoed``): a server that repeats the input is not smuggling it."""
    found: list[tuple[str, str]] = []
    for part in _decoded(text):
        for kind, pattern in (
            ("invisible Unicode tag characters", _TAGS),
            ("bidirectional override characters", _BIDI),
        ):
            for match in pattern.finditer(part):
                if match.group(0) not in echoed:
                    found.append((kind, excerpt(part, match.start())))
        for match in _ZERO_WIDTH.finditer(part):
            mid_text = 0 < match.start() < len(part) - 1  # a byte order mark at the start is fine
            if mid_text and match.group(0) not in echoed:
                found.append(("zero-width characters inside text", excerpt(part, match.start())))
        for match in _PHRASE.finditer(part):
            if match.group(0).lower() not in echoed.lower():
                found.append(("instruction-like phrase", excerpt(part, match.start())))
    return found


def _descriptions(ctx: ScanContext) -> Iterator[tuple[str, str]]:
    """(tool, text) for every description a model reads when it chooses a tool."""
    for tool in ctx.tools:
        if tool.description:
            yield tool.name, tool.description
        properties = tool.input_schema.get("properties")
        for param in properties.values() if isinstance(properties, dict) else ():
            if isinstance(param, dict) and isinstance(param.get("description"), str):
                yield tool.name, param["description"]


@register
class NoHiddenInstructions(Check):
    meta = CheckMeta(
        id="safety.no_hidden_instructions",
        family=Family.SAFETY,
        title="Descriptions and answers carry no hidden or injected instructions",
        severity=Severity.MEDIUM,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset(),
        modes=ALL_MODES,
        phase="passive",
        spec_refs=["OWASP-LLM01"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Invisible characters and phrases such as 'ignore previous instructions' in a tool "
            "description or answer are how prompt injection reaches a model unseen."
        ),
        remediation=(
            "Strip invisible and bidirectional control characters from descriptions and "
            "answers, and do not put instructions to the model in tool output."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for tool, text in _descriptions(ctx):
            for kind, sample in hidden_text(text):
                if (tool, kind) not in seen:
                    seen.add((tool, kind))
                    findings.append(self._finding(ctx, tool, "description", kind, sample, None))
        for reply in tool_replies(ctx):
            echoed = json.dumps(reply.arguments, ensure_ascii=False)
            for kind, sample in hidden_text(reply.text, echoed):
                if (reply.tool, kind) not in seen:
                    seen.add((reply.tool, kind))
                    findings.append(self._finding(ctx, reply.tool, "answer", kind, sample, reply))
        return CheckOutcome(findings[:_MAX_FINDINGS])

    def _finding(
        self,
        ctx: ScanContext,
        tool: str,
        where: str,
        kind: str,
        sample: str,
        reply: ToolReply | None,
    ) -> Finding:
        steps = (
            [request_step("tools/call", {"name": tool, "arguments": reply.arguments})]
            if reply is not None
            else [request_step("tools/list")]
        )
        return make_finding(
            self,
            ctx,
            severity=Severity.MEDIUM,
            title=f"{tool}: {kind} in a {where}",
            message=f"The {where} of {tool} contains {kind}.",
            case_id=f"hidden:{slug(tool)}:{where}:{slug(kind)}",
            steps=steps,
            expect={"hidden_instructions": "none"},
            observations={"kind": kind, "where": where, "excerpt": ascii(sample)},
            tool=tool,
        )
