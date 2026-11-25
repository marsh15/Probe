"""safety.no_command_injection, safety.readonly_enforced"""

from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.safety._support import (
    absolute,
    canary_dir,
    output_text,
    safe_call,
    tools_with_role,
    valid_arguments,
)
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
    ToolInfo,
    Transport,
)

_SQL = (
    ("stacked-delete", "SELECT 1; DELETE FROM notes;"),
    ("commit-drop", "COMMIT; DROP TABLE notes;"),
    ("cte-delete", "WITH x AS (DELETE FROM notes RETURNING *) SELECT * FROM x"),
    ("attach", "ATTACH DATABASE '{allowed}/x.db' AS x"),
)


def _marker(ctx: ScanContext) -> str:
    """The file a successful injection would create."""
    token = ctx.fixtures.token if ctx.fixtures is not None else ""
    return f"{canary_dir(ctx)}/{token}"


def _command_payloads(ctx: ScanContext) -> list[tuple[str, str]]:
    marker = _marker(ctx)
    payloads = [
        ("semicolon", f"; touch {marker}"),
        ("substitution", f"$(touch {marker})"),
        ("backtick", f"`touch {marker}`"),
        ("pipe", f"| touch {marker}"),
        ("upload-pack", f"--upload-pack=touch {marker}"),
        ("ssh-command", f"-c core.sshCommand=touch {marker}"),
        ("output-option", f"--output={marker}"),
    ]
    return payloads[:4] if ctx.config.mode == "quick" else payloads


async def _changed_by(
    ctx: ScanContext, tool: ToolInfo, arguments: dict[str, Any], case_id: str
) -> tuple[list[str], str]:
    """What one call changed in the fixtures, and what it answered."""
    fixtures = ctx.fixtures
    if fixtures is None:
        return [], ""
    await fixtures.reset()
    before = await fixtures.snapshot()
    result = await safe_call(ctx, tool.name, arguments, case_id)
    diff = fixtures.diff(before, await fixtures.snapshot())
    changes = [
        *(absolute(ctx, p) for p in (*diff.added, *diff.changed, *diff.removed)),
        *diff.sqlite_changed,
        *diff.collections_changed,
    ]
    await fixtures.reset()
    return sorted(changes), output_text(result)


def _finding(
    check: Check,
    ctx: ScanContext,
    tool: ToolInfo,
    title: str,
    case_id: str,
    arguments: dict[str, Any],
    observations: dict[str, Any],
    expect: dict[str, Any],
) -> Finding:
    return make_finding(
        check,
        ctx,
        severity=Severity.CRITICAL,
        title=title,
        message=title,
        case_id=case_id,
        steps=[request_step("tools/call", {"name": tool.name, "arguments": arguments})],
        expect=expect,
        observations=observations,
        tool=tool.name,
    )


@register
class NoCommandInjection(Check):
    meta = CheckMeta(
        id="safety.no_command_injection",
        family=Family.SAFETY,
        title="Input cannot add commands or options to what a tool runs",
        severity=Severity.CRITICAL,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"fixtures", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-78", "CWE-88"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "A tool that builds a shell command or a program's arguments from client input "
            "lets anyone who can call it run their own commands as the server."
        ),
        remediation=(
            "Never pass input through a shell. Pass an argument list, validate values against "
            "an allow-list, and put `--` or `--end-of-options` before user-supplied values."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if not any(True for _ in tools_with_role(ctx, "command_param")):
            return Applicability.no("no tool takes a command or argument parameter")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        fixtures = ctx.fixtures
        if fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        tested = False
        try:
            for tool, names in tools_with_role(ctx, "command_param"):
                override = ctx.profile.override_for(tool.name) if ctx.profile is not None else None
                if override is not None and override.intended_exec is True:
                    continue  # running commands is this tool's job
                base = await valid_arguments(ctx, tool)
                if base is None:
                    continue
                for name in names:
                    tested = True
                    for payload_id, payload in _command_payloads(ctx):
                        arguments = {**base, name: payload}
                        case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
                        changes, text = await _changed_by(ctx, tool, arguments, case_id)
                        marker = _marker(ctx)
                        hits = await fixtures.canary_hits()
                        landed = marker in changes or any(
                            fixtures.token in str(h.get("path", "")) for h in hits
                        )
                        if not landed:
                            continue
                        findings.append(
                            _finding(
                                self,
                                ctx,
                                tool,
                                f"Input to {tool.name} ran as a command or option ({payload_id})",
                                case_id,
                                arguments,
                                {"payload_id": payload_id, "created": marker, "answer": text[:400]},
                                {"command_executed": False},
                            )
                        )
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("command campaign interrupted before a verdict")
        if not tested:
            return CheckOutcome.na("no command parameter on a tool that Probe may call")
        return CheckOutcome(findings)


@register
class ReadonlyEnforced(Check):
    meta = CheckMeta(
        id="safety.readonly_enforced",
        family=Family.SAFETY,
        title="Read tools cannot be made to change anything",
        severity=Severity.CRITICAL,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"fixtures", "side_effects"}),
        modes=ALL_MODES,
        phase="active.adversarial",
        spec_refs=["CWE-89", "CWE-88"],
        disclosure=DisclosureTier.PRIVATE,
        rationale=(
            "A tool that promises read-only access but accepts stacked SQL statements or "
            "options that write files lets any caller modify data."
        ),
        remediation=(
            "Open the database read-only, allow a single SELECT statement, and refuse option-like "
            "values for command arguments."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        read_tools = (
            t
            for t in ctx.callable_tools()
            if t.kind == "read" and {"sql_param", "command_param"} & set(t.param_roles.values())
        )
        if not any(True for _ in read_tools):
            return Applicability.no("no read tool takes a SQL or command parameter")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        if ctx.fixtures is None:
            return CheckOutcome.na("requires sandbox fixtures")
        findings: list[Finding] = []
        tested = False
        allowed = ctx.profile.fixtures.fs.allowed_roots[0] if _has_fs(ctx) else "/data/allowed"
        try:
            for tool in ctx.callable_tools():
                if tool.kind != "read" or not {"sql_param", "command_param"} & set(
                    tool.param_roles.values()
                ):
                    continue
                base = await valid_arguments(ctx, tool)
                if base is None:
                    continue
                # What an ordinary call changes by itself (access logs, WAL and cache files) is
                # not the payload's doing.
                baseline, _ = await _changed_by(ctx, tool, base, f"{slug(tool.name)}:baseline")
                for name in [n for n, r in tool.param_roles.items() if r == "sql_param"]:
                    tested = True
                    for payload_id, sql in _SQL:
                        statement = sql.format(allowed=allowed)
                        findings += await self._try(
                            ctx, tool, base, name, payload_id, statement, baseline
                        )
                for name in [n for n, r in tool.param_roles.items() if r == "command_param"]:
                    tested = True
                    option = f"--output={_marker(ctx)}"
                    findings += await self._try(
                        ctx, tool, base, name, "option-write", option, baseline
                    )
        except (BudgetExhausted, TargetUnstable):
            if not findings:
                return CheckOutcome.error("read-only campaign interrupted before a verdict")
        if not tested:
            return CheckOutcome.na("no read tool with a SQL or command parameter can be called")
        return CheckOutcome(findings)

    async def _try(
        self,
        ctx: ScanContext,
        tool: ToolInfo,
        base: dict[str, Any],
        name: str,
        payload_id: str,
        value: str,
        baseline: list[str],
    ) -> list[Finding]:
        arguments = {**base, name: value}
        case_id = f"{slug(tool.name)}:{slug(name)}:{payload_id}"
        changes, text = await _changed_by(ctx, tool, arguments, case_id)
        changes = [c for c in changes if c not in baseline]
        if not changes:
            return []
        return [
            _finding(
                self,
                ctx,
                tool,
                f"{tool.name}, a read tool, changed data ({payload_id})",
                case_id,
                arguments,
                {"payload_id": payload_id, "changed": changes[:8], "answer": text[:400]},
                {"state_changed": False},
            )
        ]


def _has_fs(ctx: ScanContext) -> bool:
    profile = ctx.profile
    return bool(
        profile is not None
        and profile.fixtures.fs is not None
        and profile.fixtures.fs.allowed_roots
    )
