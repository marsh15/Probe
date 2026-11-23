"""Schema checks that read the tool definitions the server published."""

import re
from typing import Any

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.schema._support import (
    ALL_MODES,
    listing_applicable,
    named_tools,
    tool_findings,
)
from probe.checks.support import make_finding, request_step
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport
from probe.schema.jsonschema_tools import meta_problems, ref_problems
from probe.schema.spec import list_tools_problems
from probe.wire.headers import parse_x_mcp_headers

_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_BOTH = frozenset(Era)
_TRANSPORTS = frozenset(Transport)


def _meta(check_id: str, title: str, severity: Severity, **fields: Any) -> CheckMeta:
    base: dict[str, Any] = {
        "family": Family.SCHEMA,
        "eras": _BOTH,
        "transports": _TRANSPORTS,
        "requires": frozenset(),
        "modes": ALL_MODES,
        "phase": "static",
        "disclosure": DisclosureTier.PUBLIC,
    }
    base.update(fields)
    return CheckMeta(id=check_id, title=title, severity=severity, **base)


@register
class ToolsListValid(Check):
    meta = _meta(
        "schema.tools_list_valid",
        "tools/list results conform to the protocol schema",
        Severity.HIGH,
        spec_refs=["2026-07-28/server/tools#listing-tools"],
        rationale=(
            "Clients parse tools/list with the official schema. A tool without inputSchema or "
            "a result with the wrong shape breaks every client that validates strictly."
        ),
        remediation="Return tools/list results that validate against the version's schema.json.",
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        if ctx.listing is None or not ctx.listing.pages:
            reason = ctx.listing.error if ctx.listing and ctx.listing.error else None
            return Applicability.no(reason or "tools/list returned no pages")
        return Applicability.yes()

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        listing = ctx.listing
        if listing is None:
            return CheckOutcome.na("tools/list was not captured")
        findings = []
        for number, page in enumerate(listing.pages, start=1):
            problems = list_tools_problems(page, ctx.negotiated_version)
            if not problems:
                continue
            findings.append(
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title=f"tools/list page {number} does not match the schema",
                    message="; ".join(problems[:5]),
                    case_id=f"tools-list:page-{number}",
                    steps=[request_step("tools/list")],
                    expect={"schema": f"ListToolsResult ({ctx.negotiated_version})"},
                    observations={"page": number, "problems": problems},
                )
            )
        return CheckOutcome(findings)


@register
class InputSchemaValid(Check):
    meta = _meta(
        "schema.input_schema_valid",
        "Every inputSchema is a valid JSON Schema with an object root",
        Severity.HIGH,
        spec_refs=["2026-07-28/server/tools#tool"],
        rationale=(
            "Clients build forms and validate arguments from inputSchema. An invalid schema "
            "cannot be used, and a non-object root cannot describe named arguments."
        ),
        remediation=(
            "Publish a valid JSON Schema (2020-12 unless $schema says otherwise) whose root "
            'has "type": "object".'
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        issues: dict[str, list[str]] = {}
        for label, tool in named_tools(ctx):
            if "inputSchema" not in tool:
                continue  # reported by schema.tools_list_valid
            schema = tool["inputSchema"]
            problems = meta_problems(schema)
            if isinstance(schema, dict) and schema.get("type") != "object":
                problems.append(f"root type is {schema.get('type')!r}, not 'object'")
            if problems:
                issues[label] = problems
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                issues,
                severity=Severity.HIGH,
                title="Invalid inputSchema",
                case_prefix="input-schema",
                expect={"inputSchema": "valid JSON Schema with an object root"},
            )
        )


@register
class RefsResolvable(Check):
    meta = _meta(
        "schema.refs_resolvable",
        "Schema references resolve inside the schema",
        Severity.MEDIUM,
        spec_refs=["2026-07-28/server/tools#tool"],
        rationale=(
            "A $ref that points nowhere makes the schema unusable. A remote $ref makes clients "
            "fetch URLs the server chose, which leaks requests and invites SSRF."
        ),
        remediation=(
            "Inline remote definitions under $defs and make every $ref point inside the schema."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        issues: dict[str, list[str]] = {}
        for label, tool in named_tools(ctx):
            problems = [
                f"{where}: {ref} is {kind}"
                for where in ("inputSchema", "outputSchema")
                for ref, kind in ref_problems(tool.get(where))
            ]
            if problems:
                issues[label] = problems
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                issues,
                severity=Severity.MEDIUM,
                title="Unresolvable or remote $ref",
                case_prefix="refs",
                expect={"$ref": "resolves within the schema"},
            )
        )


@register
class ToolNamesValid(Check):
    meta = _meta(
        "schema.tool_names_valid",
        "Tool names are well formed and unique",
        Severity.LOW,
        spec_refs=["2026-07-28/server/tools#tool-names"],
        rationale=(
            "Names are identifiers clients show, route on and put in headers. Odd characters or "
            "duplicates make tools unreachable or ambiguous."
        ),
        remediation=(
            "Use unique names of 1-128 characters from A-Z, a-z, 0-9, underscore, dash and dot."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        issues: dict[str, list[str]] = {}
        seen: dict[str, int] = {}
        for label, tool in named_tools(ctx):
            name = tool.get("name")
            problems: list[str] = []
            if not isinstance(name, str):
                problems.append("name is missing or not a string")
            else:
                if not _NAME.fullmatch(name):
                    problems.append(
                        "name must be 1-128 characters from A-Z a-z 0-9 _ - ."
                        if name
                        else "name is empty"
                    )
                seen[name] = seen.get(name, 0) + 1
            if problems:
                issues.setdefault(label, []).extend(problems)
        for name, count in seen.items():
            if count > 1:
                issues.setdefault(name, []).append(f"name is used by {count} tools")
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                issues,
                severity=Severity.LOW,
                title="Invalid tool name",
                case_prefix="tool-name",
                expect={"name": "1-128 characters of [A-Za-z0-9_.-], unique"},
            )
        )


@register
class DescriptionsPresent(Check):
    meta = _meta(
        "schema.descriptions_present",
        "Tools and their required parameters are described",
        Severity.LOW,
        spec_refs=["2026-07-28/server/tools#tool"],
        rationale=(
            "Models choose tools and fill arguments from descriptions. Undescribed tools and "
            "required parameters are guessed at."
        ),
        remediation="Give every tool a description and every required parameter a description.",
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        issues: dict[str, list[str]] = {}
        for label, tool in named_tools(ctx):
            problems: list[str] = []
            description = tool.get("description")
            if not (isinstance(description, str) and description.strip()):
                problems.append("tool has no description")
            schema = tool.get("inputSchema")
            if isinstance(schema, dict):
                required = schema.get("required")
                properties = schema.get("properties")
                if isinstance(required, list) and isinstance(properties, dict):
                    for param in required:
                        prop = properties.get(param) if isinstance(param, str) else None
                        text = prop.get("description") if isinstance(prop, dict) else None
                        if not (isinstance(text, str) and text.strip()):
                            problems.append(f"required parameter {param!r} has no description")
            if problems:
                issues[label] = problems
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                issues,
                severity=Severity.LOW,
                title="Missing description",
                case_prefix="description",
                expect={"description": "present on the tool and on required parameters"},
            )
        )


@register
class XMcpHeaderValid(Check):
    meta = _meta(
        "schema.x_mcp_header_valid",
        "x-mcp-header annotations obey their constraints",
        Severity.LOW,
        eras=frozenset({Era.MODERN}),
        spec_refs=[
            "2026-07-28/basic/transports/streamable-http#custom-headers-from-tool-parameters"
        ],
        rationale=(
            "Clients mirror annotated parameters into HTTP headers and must drop tools whose "
            "annotations are invalid, so a bad annotation makes the tool unavailable over HTTP."
        ),
        remediation=(
            "Annotate only string, integer or boolean parameters reachable through properties, "
            "with unique token-syntax names."
        ),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        issues = {
            label: list(errors)
            for label, tool in named_tools(ctx)
            if (errors := parse_x_mcp_headers(tool.get("inputSchema"))[1])
        }
        return CheckOutcome(
            tool_findings(
                self,
                ctx,
                issues,
                severity=Severity.LOW,
                title="Invalid x-mcp-header",
                case_prefix="x-mcp-header",
                expect={"x-mcp-header": "valid per the streamable HTTP rules"},
            )
        )


@register
class InputSchemaStrict(Check):
    meta = _meta(
        "schema.input_schema_strict",
        "Input schemas are strict (information only)",
        Severity.INFO,
        spec_refs=["2026-07-28/server/tools#tool"],
        rationale=(
            "Schemas that forbid extra properties and list required ones reject malformed "
            "calls early. Loose ones accept whatever a model invents."
        ),
        remediation='Set "additionalProperties": false and list required parameters.',
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return listing_applicable(ctx)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        loose: list[str] = []
        for label, tool in named_tools(ctx):
            schema = tool.get("inputSchema")
            if not isinstance(schema, dict) or schema.get("type") != "object":
                continue
            has_required = isinstance(schema.get("required"), list) and bool(schema["required"])
            has_properties = bool(schema.get("properties"))
            if schema.get("additionalProperties") is not False or (
                has_properties and not has_required
            ):
                loose.append(label)
        if not loose:
            return CheckOutcome()
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.INFO,
                    title="Some input schemas are not strict",
                    message=(
                        f"{len(loose)} tool(s) allow additional properties or list no "
                        "required parameters."
                    ),
                    case_id="input-schema-strict:summary",
                    steps=[request_step("tools/list")],
                    expect={"additionalProperties": False},
                    observations={"tools": loose[:100], "count": len(loose)},
                )
            ]
        )
