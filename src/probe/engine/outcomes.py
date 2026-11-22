"""Vocabulary and result types shared by checks, the engine, and reports.

Every model forbids unknown fields (typos fail loudly) and serializes set-valued fields in
sorted order, so a report written twice is byte-identical.
"""

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, field_validator

from probe.util.sanitize_console import sanitize_console

EXCERPT_MAX_BYTES = 2048


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Status(StrEnum):
    PASS = "pass"  # noqa: S105 - a result status, not a password
    FAIL = "fail"
    NA = "not_applicable"
    ERROR = "error"
    SKIPPED = "skipped"


class Family(StrEnum):
    PROTOCOL = "protocol"
    SCHEMA = "schema"
    BEHAVIOR = "behavior"
    SAFETY = "safety"
    OPERABILITY = "operability"


class Era(StrEnum):
    MODERN = "modern"
    LEGACY = "legacy"


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"


class DisclosureTier(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


Requirement = Literal[
    "tools",
    "fixtures",
    "side_effects",
    "url_tools",
    "path_tools",
    "auth_identities",
    "tasks_ext",
    "mrtr",
    "second_instance",
    "llm",
    "http",
    "slow_case",
    "write_tools",
    "paginated",
]
Mode = Literal["quick", "standard", "deep"]
Phase = Literal[
    "static",
    "active.safe",
    "active.write",
    "active.adversarial",
    "active.stress",
    "passive",
    "post",
]
ToolKind = Literal["read", "write", "destructive", "exec", "unknown"]
ToolFlag = Literal[
    "url_param", "path_param", "sql_param", "command_param", "paginated", "sensitive_param"
]


def _sorted[T](values: Iterable[T]) -> list[T]:
    return sorted(values, key=str)


EraSet = Annotated[frozenset[Era], PlainSerializer(_sorted, return_type=list[Era])]
TransportSet = Annotated[
    frozenset[Transport], PlainSerializer(_sorted, return_type=list[Transport])
]
RequirementSet = Annotated[
    frozenset[Requirement], PlainSerializer(_sorted, return_type=list[Requirement])
]
ModeSet = Annotated[frozenset[Mode], PlainSerializer(_sorted, return_type=list[Mode])]
FlagSet = Annotated[set[ToolFlag], PlainSerializer(_sorted, return_type=list[ToolFlag])]


class CheckMeta(StrictModel):
    id: str  # "safety.ssrf_blocked": stable forever once released
    family: Family
    title: str
    severity: Severity  # catalog severity: the scoring weight
    eras: EraSet
    transports: TransportSet
    requires: RequirementSet
    modes: ModeSet
    phase: Phase
    spec_refs: list[str]
    disclosure: DisclosureTier
    rationale: str  # why it matters (shown in the report and docs)
    remediation: str  # how to fix it (shown in the report and docs)
    min_version: str | None = None  # e.g. outputSchema checks need >= 2025-06-18


class Evidence(StrictModel):
    summary: str
    request_refs: list[int]  # indexes into trace.jsonl
    response_refs: list[int]
    observations: dict[str, Any]  # e.g. canary hits, state diff, the payload used
    excerpt: str | None = None  # sanitized, at most EXCERPT_MAX_BYTES of UTF-8

    @field_validator("excerpt")
    @classmethod
    def _clean_excerpt(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = sanitize_console(value)
        encoded = cleaned.encode("utf-8", "surrogatepass")
        if len(encoded) <= EXCERPT_MAX_BYTES:
            return cleaned
        # Cut on a character boundary: drop any half-cut trailing character.
        return encoded[:EXCERPT_MAX_BYTES].decode("utf-8", "ignore")


class ReproCase(StrictModel):
    case_id: str  # deterministic, e.g. "ssrf:fetch:url:decimal-ip"
    steps: list[dict[str, Any]]  # wire-level requests (params only; ids are reassigned on replay)
    expect: dict[str, Any]  # predicate `probe repro` uses to decide REPRODUCED
    command: str  # the one-liner shown in the report


class Finding(StrictModel):
    finding_id: str
    check_id: str
    family: Family
    severity: Severity  # this instance's severity (may differ from the catalog severity)
    tool: str | None
    title: str
    message: str
    evidence: Evidence
    repro: ReproCase
    disclosure: DisclosureTier


class CheckResult(StrictModel):
    check_id: str
    status: Status
    reason: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: int = 0
    calls: int = 0


class CrashEvent(StrictModel):
    check_id: str
    case_id: str | None
    exit_code: int | None
    oom_killed: bool
    stderr_tail: str

    @field_validator("stderr_tail")
    @classmethod
    def _clean_stderr(cls, value: str) -> str:
        return sanitize_console(value)


class ToolInfo(StrictModel):
    name: str
    title: str | None
    description: str | None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]
    kind: ToolKind
    flags: FlagSet
    classification_source: Literal["profile", "annotations", "heuristic"]
    classification_reason: str
    param_roles: dict[str, str]  # {"url": "url_param", ...}
