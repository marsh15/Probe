"""The scan report (report.json). Shape and field names follow the report schema v1.0."""

from typing import Annotated, Any, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from probe.engine.outcomes import (
    CrashEvent,
    Family,
    Finding,
    Severity,
    Status,
    StrictModel,
    ToolFlag,
    ToolKind,
    Transport,
)

SCHEMA_VERSION = "1.0"
HONESTY = "No issues found by Probe v1.0 checks is not a security guarantee."


class ScanInfo(StrictModel):
    id: str
    scan_key: str
    status: Literal["completed", "target_unavailable", "aborted"]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    duration_ms: int
    mode: str
    seed: int
    sandboxed: bool
    platform: str
    runtime: Literal["runc", "runsc", "none"]


class EraInfo(StrictModel):
    kind: Literal["modern", "legacy", "dual"] | None  # None: the target never answered
    negotiated_version: str | None
    supported_versions: list[str]


class PackageInfo(StrictModel):
    ecosystem: str
    name: str
    version: str


class TargetInfo(StrictModel):
    name: str
    transport: Transport
    era: EraInfo
    server_info: dict[str, Any]
    package: PackageInfo | None
    image_digest: str | None
    profile_hash: str | None
    capabilities: dict[str, Any]
    extensions: list[str]


class ToolSummary(StrictModel):
    name: str
    kind: ToolKind
    flags: list[ToolFlag]
    classification_source: Literal["profile", "annotations", "heuristic"]
    classification_reason: str
    annotations: dict[str, Any]
    input_schema_hash: str
    cases_run: int


class ResultSummary(StrictModel):
    check_id: str
    family: Family
    title: str
    severity: Severity
    status: Status
    reason: str | None
    spec_refs: list[str]
    duration_ms: int
    calls: int
    finding_ids: list[str]


Percentage = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
Grade = Literal["A", "B", "C", "D", "F"]
ScoringProfile = Literal["full", "public-interim"]


class FamilyScore(StrictModel):
    score: Percentage | None
    applicable_weight: int = Field(ge=0, strict=True)
    failed_weight: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def _consistent_weights(self) -> Self:
        if self.failed_weight > self.applicable_weight:
            raise ValueError("failed weight cannot exceed applicable weight")
        if (self.score is None) != (self.applicable_weight == 0):
            raise ValueError("family score must be null exactly when applicable weight is zero")
        return self


class Score(StrictModel):
    overall: Percentage | None
    grade: Grade | None
    coverage: Percentage
    caps_applied: list[str]
    families: dict[Family, FamilyScore]

    @model_validator(mode="after")
    def _consistent_grade(self) -> Self:
        if (self.overall is None) != (self.grade is None):
            raise ValueError("overall and grade must be null together")
        return self


class Stats(StrictModel):
    calls: int
    protocol_errors: int
    tool_errors: int
    restarts: int
    crashes: list[CrashEvent]
    bytes_in: int
    bytes_out: int
    phase_ms: dict[str, int]


class LlmStats(StrictModel):
    model: str
    recovery_rate: float
    lift: float
    cases: int
    cache_hits: int
    cost_usd: float


class ScanReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    probe_version: str
    catalog_version: str
    scoring_version: str
    scoring_profile: ScoringProfile = "full"
    scan: ScanInfo
    target: TargetInfo
    tools: list[ToolSummary]
    results: list[ResultSummary]
    findings: list[Finding]
    score: Score
    stats: Stats
    llm: LlmStats | None = None
    limitations: list[str] = Field(default_factory=list)
    honesty: str = HONESTY
