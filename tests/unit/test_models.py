"""The data model: strict, round-trippable, and deterministic when serialized."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from probe.engine.outcomes import (
    SEVERITY_WEIGHT,
    CheckMeta,
    CheckResult,
    CrashEvent,
    DisclosureTier,
    Era,
    Evidence,
    Family,
    Finding,
    ReproCase,
    Severity,
    Status,
    ToolInfo,
    Transport,
)
from probe.report.models import (
    HONESTY,
    SCHEMA_VERSION,
    EraInfo,
    FamilyScore,
    ScanInfo,
    ScanReport,
    Score,
    Stats,
    TargetInfo,
)


def make_meta(**overrides: Any) -> CheckMeta:
    fields: dict[str, Any] = {
        "id": "safety.ssrf_blocked",
        "family": Family.SAFETY,
        "title": "URL tools block internal addresses",
        "severity": Severity.HIGH,
        "eras": {Era.MODERN, Era.LEGACY},
        "transports": {Transport.STDIO, Transport.HTTP},
        "requires": {"tools", "url_tools", "fixtures"},
        "modes": {"standard", "quick", "deep"},
        "phase": "active.adversarial",
        "spec_refs": ["2026-07-28/server/tools#security-considerations"],
        "disclosure": DisclosureTier.PRIVATE,
        "rationale": "Why it matters.",
        "remediation": "How to fix.",
    }
    fields.update(overrides)
    return CheckMeta(**fields)


def make_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "finding_id": "0123456789abcdef",
        "check_id": "safety.ssrf_blocked",
        "family": Family.SAFETY,
        "severity": Severity.HIGH,
        "tool": "fetch",
        "title": "fetch reached an internal address",
        "message": "The canary was hit.",
        "evidence": Evidence(
            summary="canary hit",
            request_refs=[3],
            response_refs=[4],
            observations={"canary_hits": ["10.0.0.5"]},
            excerpt="hit",
        ),
        "repro": ReproCase(
            case_id="ssrf:fetch:url:decimal-ip",
            steps=[{"method": "tools/call", "params": {"name": "fetch"}}],
            expect={"canary_hit": True},
            command="probe repro report.json --finding 0123456789abcdef",
        ),
        "disclosure": DisclosureTier.PRIVATE,
    }
    fields.update(overrides)
    return Finding(**fields)


def test_severity_weights_match_the_scoring_table() -> None:
    assert SEVERITY_WEIGHT == {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }


def test_enum_values_are_the_lowercase_wire_strings() -> None:
    assert Status.NA.value == "not_applicable"
    assert Family.OPERABILITY.value == "operability"
    assert Era.MODERN.value == "modern"
    assert Transport.HTTP.value == "http"
    assert DisclosureTier.PRIVATE.value == "private"


def test_check_meta_serializes_sets_in_sorted_order() -> None:
    dumped = make_meta().model_dump(mode="json")
    assert dumped["modes"] == ["deep", "quick", "standard"]
    assert dumped["eras"] == ["legacy", "modern"]
    assert dumped["transports"] == ["http", "stdio"]
    assert dumped["requires"] == ["fixtures", "tools", "url_tools"]


def test_check_meta_rejects_unknown_requirement_mode_and_phase() -> None:
    with pytest.raises(ValidationError):
        make_meta(requires={"telepathy"})
    with pytest.raises(ValidationError):
        make_meta(modes={"turbo"})
    with pytest.raises(ValidationError):
        make_meta(phase="whenever")


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_finding(surprise=1)


def test_finding_round_trips_through_json() -> None:
    finding = make_finding()
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_evidence_excerpt_is_sanitized_and_capped_at_2_kib() -> None:
    evidence = Evidence(
        summary="s",
        request_refs=[],
        response_refs=[],
        observations={},
        excerpt="\x1b[31m" + "é" * 5000,
    )
    assert evidence.excerpt is not None
    assert "\x1b" not in evidence.excerpt
    assert len(evidence.excerpt.encode("utf-8")) <= 2048
    assert evidence.excerpt.startswith("é")


def test_evidence_excerpt_may_be_absent() -> None:
    evidence = Evidence(summary="s", request_refs=[], response_refs=[], observations={})
    assert evidence.excerpt is None


def test_crash_event_stderr_tail_is_sanitized() -> None:
    crash = CrashEvent(
        check_id="behavior.survives_campaign",
        case_id=None,
        exit_code=-9,
        oom_killed=True,
        stderr_tail="\x1b]0;pwned\x07boom",
    )
    assert crash.stderr_tail == "boom"


def test_check_result_defaults_for_a_not_applicable_check() -> None:
    result = CheckResult(check_id="x.y", status=Status.NA, reason="no url tools")
    assert result.findings == []
    assert result.duration_ms == 0
    assert result.calls == 0


def test_tool_info_serializes_flags_sorted() -> None:
    tool = ToolInfo(
        name="fetch",
        title=None,
        description=None,
        input_schema={"type": "object"},
        output_schema=None,
        annotations={},
        kind="read",
        flags={"url_param", "paginated"},
        classification_source="heuristic",
        classification_reason="name matches fetch",
        param_roles={"url": "url_param"},
    )
    assert tool.model_dump(mode="json")["flags"] == ["paginated", "url_param"]


def make_report(**overrides: Any) -> ScanReport:
    now = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)
    fields: dict[str, Any] = {
        "probe_version": "0.1.0.dev0",
        "catalog_version": "1",
        "scoring_version": "1.0",
        "scan": ScanInfo(
            id="scan-1",
            scan_key="k" * 64,
            status="completed",
            started_at=now,
            finished_at=now,
            duration_ms=1200,
            mode="standard",
            seed=1337,
            sandboxed=False,
            platform="darwin/arm64",
            runtime="none",
        ),
        "target": TargetInfo(
            name="refserver",
            transport=Transport.STDIO,
            era=EraInfo(
                kind="modern", negotiated_version="2026-07-28", supported_versions=["2026-07-28"]
            ),
            server_info={"name": "refserver", "version": "0.1"},
            package=None,
            image_digest=None,
            profile_hash=None,
            capabilities={},
            extensions=[],
        ),
        "tools": [],
        "results": [],
        "findings": [],
        "score": Score(overall=None, grade=None, coverage=0.0, caps_applied=[], families={}),
        "stats": Stats(
            calls=0,
            protocol_errors=0,
            tool_errors=0,
            restarts=0,
            crashes=[],
            bytes_in=0,
            bytes_out=0,
            phase_ms={},
        ),
    }
    fields.update(overrides)
    return ScanReport(**fields)


def test_report_has_schema_version_and_honesty_statement() -> None:
    report = make_report()
    assert report.schema_version == SCHEMA_VERSION == "1.0"
    assert report.honesty == HONESTY
    assert "not a security guarantee" in HONESTY
    assert report.llm is None
    assert report.limitations == []


def test_report_round_trips_through_json() -> None:
    report = make_report(
        findings=[make_finding()],
        score=Score(
            overall=90.2,
            grade="B",
            coverage=0.92,
            caps_applied=["high_instance_caps_at_B"],
            families={
                Family.SAFETY: FamilyScore(score=83.3, applicable_weight=30, failed_weight=5)
            },
        ),
    )
    assert ScanReport.model_validate_json(report.model_dump_json()) == report


def test_report_json_is_deterministic() -> None:
    assert make_report().model_dump_json() == make_report().model_dump_json()


def test_report_rejects_an_unknown_schema_version() -> None:
    with pytest.raises(ValidationError):
        make_report(schema_version="2.0")


def test_scan_times_must_be_timezone_aware() -> None:
    naive = datetime(2026, 11, 23, 9, 0)
    with pytest.raises(ValidationError):
        ScanInfo(
            id="s",
            scan_key="k",
            status="completed",
            started_at=naive,
            finished_at=naive,
            duration_ms=0,
            mode="standard",
            seed=1,
            sandboxed=False,
            platform="p",
            runtime="none",
        )


@pytest.mark.parametrize("field", ["overall", "coverage"])
@pytest.mark.parametrize("value", [-0.1, 100.1, float("nan"), float("inf"), -float("inf")])
def test_score_rejects_invalid_percentages(field: str, value: float) -> None:
    values = dict(overall=90.0, grade="A", coverage=50.0, caps_applied=[], families={})
    values[field] = value
    with pytest.raises(ValidationError):
        Score(**values)


@pytest.mark.parametrize(
    "values",
    [
        dict(score=101, applicable_weight=1, failed_weight=0),
        dict(score=float("nan"), applicable_weight=1, failed_weight=0),
        dict(score=0, applicable_weight=1, failed_weight=2),
        dict(score=100, applicable_weight=-1, failed_weight=0),
        dict(score=100, applicable_weight=0, failed_weight=0),
        dict(score=None, applicable_weight=1, failed_weight=0),
    ],
)
def test_family_score_rejects_impossible_weights_and_nulls(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        FamilyScore(**values)


@pytest.mark.parametrize(("overall", "grade"), [(None, "A"), (90.0, None)])
def test_score_and_grade_are_null_together(overall: float | None, grade: str | None) -> None:
    with pytest.raises(ValidationError):
        Score(overall=overall, grade=grade, coverage=0, caps_applied=[], families={})


def test_report_records_scoring_profile_with_a_backwards_compatible_default() -> None:
    assert make_report().scoring_profile == "full"
    scanned = make_report(scoring_profile="public-interim")
    assert ScanReport.model_validate_json(scanned.model_dump_json()) == scanned
    with pytest.raises(ValidationError):
        make_report(scoring_profile="unknown")
