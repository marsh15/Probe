"""Public scoring API: catalog weights, judged results, coverage and disclosure profiles."""

from itertools import permutations

import pytest

from probe.engine.outcomes import (
    CheckMeta,
    CheckResult,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    Status,
    Transport,
)
from probe.scoring import compute_score
from tests.checks.helpers import evidence, make_meta, repro


def result(meta: CheckMeta, status: Status = Status.PASS, *severities: Severity) -> CheckResult:
    return CheckResult(
        check_id=meta.id,
        status=status,
        findings=[
            Finding(
                finding_id=f"{meta.id}-{i}",
                check_id=meta.id,
                family=meta.family,
                severity=severity,
                tool=f"tool-{i}",
                title="test finding",
                message="test evidence",
                evidence=evidence(),
                repro=repro(),
                disclosure=meta.disclosure,
            )
            for i, severity in enumerate(severities)
        ],
    )


def test_catalog_weight_and_one_failure_per_check_despite_many_instances() -> None:
    failed = make_meta("safety.failed", severity=Severity.LOW)
    passed = make_meta("safety.passed", severity=Severity.HIGH)
    score = compute_score(
        [failed, passed],
        [result(failed, Status.FAIL, *([Severity.HIGH] * 20)), result(passed)],
        Transport.STDIO,
    )
    family = score.families[Family.SAFETY]
    assert (family.applicable_weight, family.failed_weight, family.score) == (6, 1, 83.3)
    assert (score.overall, score.grade, score.coverage) == (83.3, "B", 100.0)
    assert score.caps_applied == ["high_instance_caps_at_B"]


@pytest.mark.parametrize("status", list(Status))
def test_only_pass_and_fail_are_applicable(status: Status) -> None:
    meta = make_meta(severity=Severity.HIGH)
    score = compute_score([meta], [result(meta, status, Severity.CRITICAL)], Transport.STDIO)
    family = score.families[Family.PROTOCOL]
    judged = status in (Status.PASS, Status.FAIL)
    assert family.applicable_weight == (5 if judged else 0)
    assert family.failed_weight == (5 if status is Status.FAIL else 0)
    assert family.score == (0.0 if status is Status.FAIL else 100.0 if judged else None)
    assert score.coverage == (100.0 if judged else 0.0)
    assert score.caps_applied == (["critical_instance_caps_at_D"] if status is Status.FAIL else [])


@pytest.mark.parametrize("transport", list(Transport))
def test_coverage_filters_both_sides_by_transport_but_keeps_other_eras(
    transport: Transport,
) -> None:
    other = Transport.HTTP if transport is Transport.STDIO else Transport.STDIO
    judged = make_meta("protocol.judged", severity=Severity.HIGH, transports={transport})
    modern = make_meta(
        "protocol.modern", severity=Severity.HIGH, eras={Era.MODERN}, transports={transport}
    )
    foreign = make_meta("protocol.foreign", severity=Severity.CRITICAL, transports={other})
    # A foreign-transport FAIL row cannot penalize or inflate the target's score or coverage.
    score = compute_score(
        [judged, modern, foreign],
        [
            result(judged),
            result(modern, Status.NA),
            result(foreign, Status.FAIL, Severity.CRITICAL),
        ],
        transport,
    )
    assert (score.overall, score.grade, score.coverage, score.caps_applied) == (100, "A", 50, [])


def test_skipped_and_missing_results_remain_in_the_coverage_denominator() -> None:
    metas = [make_meta(f"schema.c{i}", severity=Severity.LOW) for i in range(4)]
    score = compute_score(
        metas,
        [result(metas[0]), result(metas[1], Status.SKIPPED), result(metas[2], Status.ERROR)],
        Transport.STDIO,
    )
    assert (score.overall, score.grade, score.coverage) == (100, "A", 25)
    assert score.families[Family.SCHEMA].applicable_weight == 1


@pytest.mark.parametrize("status", [Status.PASS, Status.FAIL])
def test_info_observations_and_llm_checks_have_zero_weight_and_no_caps(status: Status) -> None:
    info = make_meta("safety.info", severity=Severity.INFO)
    llm = make_meta("behavior.judge", severity=Severity.CRITICAL, requires={"llm"})
    passed = make_meta("protocol.passed", severity=Severity.LOW)
    score = compute_score(
        [info, llm, passed],
        [
            result(info, status, Severity.CRITICAL),
            result(llm, status, Severity.HIGH),
            result(passed),
        ],
        Transport.STDIO,
    )
    assert (score.overall, score.grade, score.coverage, score.caps_applied) == (100, "A", 100, [])
    assert score.families[Family.SAFETY].score is None
    assert score.families[Family.BEHAVIOR].score is None


def test_unrelated_findings_and_nonjudged_evidence_cannot_trigger_caps() -> None:
    failed = make_meta("protocol.failed", severity=Severity.LOW)
    passed = make_meta("protocol.passed", severity=Severity.CRITICAL)
    unrelated = make_meta("schema.unrelated")
    row = result(failed, Status.FAIL, Severity.LOW)
    row.findings.extend(result(unrelated, Status.FAIL, Severity.CRITICAL).findings)
    row.findings.extend(
        [
            f.model_copy(update={"family": Family.SCHEMA})
            for f in result(failed, Status.FAIL, Severity.HIGH).findings
        ]
    )
    score = compute_score([failed, passed], [row, result(passed)], Transport.STDIO)
    assert (score.overall, score.grade, score.caps_applied) == (90.9, "A", [])


@pytest.mark.parametrize("private_status", list(Status))
@pytest.mark.parametrize("private_severity", [Severity.LOW, Severity.HIGH, Severity.CRITICAL])
def test_public_interim_excludes_private_checks_uniformly(
    private_status: Status, private_severity: Severity
) -> None:
    public = make_meta("protocol.public", severity=Severity.LOW)
    private = make_meta(
        "safety.future_private", severity=Severity.CRITICAL, disclosure=DisclosureTier.PRIVATE
    )
    rows = [result(public), result(private, private_status, private_severity)]
    before = [row.model_dump_json() for row in rows]
    score = compute_score(
        [private, public], rows, Transport.STDIO, scoring_profile="public-interim"
    )
    public_only = compute_score([public], [result(public)], Transport.STDIO)
    assert score == public_only
    assert [row.model_dump_json() for row in rows] == before  # no publishing/redaction side effects


def test_full_profile_keeps_private_pass_and_fail_weights_and_caps() -> None:
    public = make_meta("safety.public", severity=Severity.CRITICAL)
    private = make_meta("safety.private", severity=Severity.LOW, disclosure=DisclosureTier.PRIVATE)
    passed = compute_score([public, private], [result(public), result(private)], Transport.STDIO)
    failed = compute_score(
        [public, private],
        [result(public), result(private, Status.FAIL, Severity.CRITICAL)],
        Transport.STDIO,
        scoring_profile="full",
    )
    assert passed.families[Family.SAFETY].applicable_weight == 11
    assert (passed.overall, passed.grade, passed.coverage) == (100, "A", 100)
    assert (failed.overall, failed.grade, failed.coverage) == (90.9, "D", 100)
    assert failed.caps_applied == ["critical_instance_caps_at_D"]


@pytest.mark.parametrize(
    ("private_severity", "full_grade", "full_caps"),
    [
        (Severity.HIGH, "B", ["high_instance_caps_at_B"]),
        (Severity.CRITICAL, "D", ["critical_instance_caps_at_D"]),
    ],
)
def test_private_findings_on_public_checks_cannot_change_interim_caps(
    private_severity: Severity, full_grade: str, full_caps: list[str]
) -> None:
    failed = make_meta("safety.public_failed", severity=Severity.LOW)
    passed = make_meta("safety.public_passed", severity=Severity.CRITICAL)
    rows = [result(failed, Status.FAIL, Severity.LOW), result(passed)]
    catalog = [failed, passed]
    before = compute_score(catalog, rows, Transport.STDIO, scoring_profile="public-interim")
    private = (
        result(failed, Status.FAIL, private_severity)
        .findings[0]
        .model_copy(update={"finding_id": "private-finding", "disclosure": DisclosureTier.PRIVATE})
    )
    rows[0].findings.append(private)
    evidence_before = [row.model_dump_json() for row in rows]

    interim = compute_score(catalog, rows, Transport.STDIO, scoring_profile="public-interim")
    full = compute_score(catalog, rows, Transport.STDIO)

    assert (before.overall, before.grade, before.coverage, before.caps_applied) == (
        90.9,
        "A",
        100.0,
        [],
    )
    assert interim == before
    assert (full.overall, full.grade, full.caps_applied) == (90.9, full_grade, full_caps)
    assert [row.model_dump_json() for row in rows] == evidence_before


def test_private_pass_does_not_boost_interim_coverage_when_public_results_are_missing() -> None:
    public = make_meta("schema.public", severity=Severity.LOW)
    private = make_meta(
        "schema.private", severity=Severity.CRITICAL, disclosure=DisclosureTier.PRIVATE
    )
    score = compute_score(
        [public, private], [result(private)], Transport.STDIO, scoring_profile="public-interim"
    )
    assert (score.overall, score.grade, score.coverage, score.caps_applied) == (None, None, 0, [])


@pytest.mark.parametrize("kind", ["empty", "missing", "info", "llm", "private"])
def test_no_weighted_applicable_checks_means_null_score_not_a_perfect_grade(kind: str) -> None:
    meta = make_meta(
        severity=Severity.INFO if kind == "info" else Severity.HIGH,
        requires={"llm"} if kind == "llm" else set(),
        disclosure=DisclosureTier.PRIVATE if kind == "private" else DisclosureTier.PUBLIC,
    )
    score = compute_score(
        [] if kind == "empty" else [meta],
        [] if kind in ("empty", "missing") else [result(meta)],
        Transport.STDIO,
        scoring_profile="public-interim",
    )
    assert (score.overall, score.grade, score.coverage, score.caps_applied) == (None, None, 0, [])
    assert set(score.families) == set(Family)
    assert all(f.score is None for f in score.families.values())


@pytest.mark.parametrize(
    ("failed", "grade"),
    [
        (0, "A"),
        (10, "A"),
        (11, "B"),
        (20, "B"),
        (21, "C"),
        (30, "C"),
        (31, "D"),
        (40, "D"),
        (41, "F"),
        (100, "F"),
    ],
)
def test_grade_boundaries(failed: int, grade: str) -> None:
    metas = [make_meta(f"schema.c{i}", severity=Severity.LOW) for i in range(100)]
    rows = [
        result(meta, Status.FAIL if i < failed else Status.PASS, Severity.LOW)
        for i, meta in enumerate(metas)
    ]
    score = compute_score(metas, rows, Transport.STDIO)
    assert (score.overall, score.grade) == (100 - failed, grade)


@pytest.mark.parametrize(
    ("failed_count", "severities", "grade", "caps"),
    [
        (1, [Severity.HIGH], "B", ["high_instance_caps_at_B"]),
        (1, [Severity.CRITICAL], "D", ["critical_instance_caps_at_D"]),
        (
            1,
            [Severity.HIGH, Severity.CRITICAL],
            "D",
            ["critical_instance_caps_at_D", "high_instance_caps_at_B"],
        ),
        (
            5,
            [Severity.HIGH, Severity.CRITICAL],
            "F",
            ["critical_instance_caps_at_D", "high_instance_caps_at_B"],
        ),
    ],
)
def test_caps_are_deterministic_and_never_raise_a_lower_grade(
    failed_count: int, severities: list[Severity], grade: str, caps: list[str]
) -> None:
    metas = [make_meta(f"safety.c{i}", severity=Severity.LOW) for i in range(10)]
    rows = [
        result(m, Status.FAIL if i < failed_count else Status.PASS, *severities)
        for i, m in enumerate(metas)
    ]
    score = compute_score(metas, rows, Transport.STDIO)
    assert score.grade == grade
    assert score.caps_applied == caps


def test_input_order_does_not_change_serialized_score() -> None:
    metas = [make_meta("safety.a"), make_meta("schema.b"), make_meta("protocol.c")]
    rows = [
        result(metas[0], Status.FAIL, Severity.HIGH, Severity.CRITICAL),
        result(metas[1]),
        result(metas[2], Status.NA),
    ]
    expected = compute_score(metas, rows, Transport.STDIO).model_dump_json()
    for catalog_order in permutations(metas):
        for result_order in permutations(rows):
            assert (
                compute_score(catalog_order, result_order, Transport.STDIO).model_dump_json()
                == expected
            )


@pytest.mark.parametrize(
    "invalid", ["duplicate_catalog", "duplicate_result", "unknown_result", "profile", "transport"]
)
def test_invalid_scoring_inputs_are_rejected_instead_of_inflating_scores(invalid: str) -> None:
    meta = make_meta()
    with pytest.raises(ValueError):
        compute_score(
            [meta, meta] if invalid == "duplicate_catalog" else [meta],
            [result(meta), result(meta)]
            if invalid == "duplicate_result"
            else [result(make_meta("schema.unknown") if invalid == "unknown_result" else meta)],
            "telepathy" if invalid == "transport" else Transport.STDIO,  # type: ignore[arg-type]
            scoring_profile="secret" if invalid == "profile" else "full",  # type: ignore[arg-type]
        )
