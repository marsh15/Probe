"""Worked example and exact-intermediate arithmetic through the public API."""

from probe.engine.outcomes import Family, Severity, Status, Transport
from probe.scoring import compute_score
from tests.checks.helpers import make_meta
from tests.scoring.test_compute import result


def test_worked_example_renormalizes_and_caps_the_raw_a_at_b() -> None:
    catalog = []
    rows = []
    for family, applicable, failed in [
        (Family.SAFETY, 30, 5),
        (Family.BEHAVIOR, 25, 2),
        (Family.SCHEMA, 18, 1),
        (Family.PROTOCOL, 12, 0),
        (Family.OPERABILITY, 6, 1),
    ]:
        for i in range(applicable):
            meta = make_meta(f"{family.value}.c{i}", severity=Severity.LOW)
            catalog.append(meta)
            rows.append(
                result(
                    meta,
                    Status.FAIL if i < failed else Status.PASS,
                    Severity.HIGH if family is Family.SAFETY and i == 0 else Severity.LOW,
                )
            )
    score = compute_score(catalog, rows, Transport.STDIO)
    assert (score.overall, score.grade, score.coverage) == (90.2, "B", 100)
    assert score.caps_applied == ["high_instance_caps_at_B"]
    assert [
        score.families[f].score
        for f in (
            Family.SAFETY,
            Family.BEHAVIOR,
            Family.SCHEMA,
            Family.PROTOCOL,
            Family.OPERABILITY,
        )
    ] == [83.3, 92, 94.4, 100, 83.3]


def test_null_families_are_excluded_and_intermediates_are_not_rounded() -> None:
    catalog = []
    rows = []
    for family, count, failed in [(Family.SAFETY, 3, 1), (Family.SCHEMA, 14, 1)]:
        for i in range(count):
            meta = make_meta(f"{family.value}.c{i}", severity=Severity.LOW)
            catalog.append(meta)
            rows.append(result(meta, Status.FAIL if i < failed else Status.PASS, Severity.LOW))
    score = compute_score(catalog, rows, Transport.STDIO)
    # Exact: 77.142857... -> 77.1. Rounding the family scores first would yield 77.2.
    assert score.overall == 77.1
    assert score.families[Family.BEHAVIOR].score is None


def test_grade_uses_the_displayed_overall_and_half_even_rounding() -> None:
    catalog = [make_meta(f"schema.c{i}", severity=Severity.LOW) for i in range(2000)]
    rows = [
        result(m, Status.FAIL if i < 201 else Status.PASS, Severity.LOW)
        for i, m in enumerate(catalog)
    ]
    score = compute_score(catalog, rows, Transport.STDIO)
    # 89.95 is exactly halfway: half-even at one decimal is 90.0 (A).
    assert (score.overall, score.grade) == (90.0, "A")
