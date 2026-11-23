"""Compute exact family aggregates, transport coverage and grades without changing evidence."""

from collections.abc import Iterable
from fractions import Fraction

from probe.engine.outcomes import (
    CheckMeta,
    CheckResult,
    DisclosureTier,
    Family,
    Severity,
    Status,
    Transport,
)
from probe.report.models import FamilyScore, Score, ScoringProfile
from probe.scoring.grade import capped_grade
from probe.scoring.weights import FAMILY_WEIGHT, check_weight


def _display(value: Fraction) -> float:
    return float(round(value, 1))


def compute_score(
    catalog: Iterable[CheckMeta],
    results: Iterable[CheckResult],
    transport: Transport,
    *,
    scoring_profile: ScoringProfile = "full",
) -> Score:
    """Score one transport against the supplied whole catalog; see the package scoring contract."""
    if scoring_profile not in ("full", "public-interim"):
        raise ValueError(f"unknown scoring_profile {scoring_profile!r}")
    transport = Transport(transport)
    metadata: dict[str, CheckMeta] = {}
    for meta in catalog:
        if meta.id in metadata:
            raise ValueError(f"duplicate catalog id {meta.id!r}")
        metadata[meta.id] = meta
    rows: dict[str, CheckResult] = {}
    for result in results:
        if result.check_id not in metadata:
            raise ValueError(f"unknown result id {result.check_id!r}")
        if result.check_id in rows:
            raise ValueError(f"duplicate result id {result.check_id!r}")
        rows[result.check_id] = result

    applicable = dict.fromkeys(Family, 0)
    failed = dict.fromkeys(Family, 0)
    denominator = 0
    cap_severities: set[Severity] = set()
    for check_id, meta in metadata.items():
        if transport not in meta.transports or (
            scoring_profile == "public-interim" and meta.disclosure is DisclosureTier.PRIVATE
        ):
            continue
        weight = check_weight(meta)
        denominator += weight
        row = rows.get(check_id)
        if not weight or row is None or row.status not in (Status.PASS, Status.FAIL):
            continue
        applicable[meta.family] += weight
        if row.status is Status.FAIL:
            failed[meta.family] += weight
            cap_severities.update(
                f.severity
                for f in row.findings
                if f.check_id == check_id
                and f.family is meta.family
                and (scoring_profile == "full" or f.disclosure is not DisclosureTier.PRIVATE)
            )

    families = {}
    weighted_sum = Fraction(0)
    headline_weight = 0
    for family in Family:
        total = applicable[family]
        exact = Fraction(100 * (total - failed[family]), total) if total else None
        families[family] = FamilyScore(
            score=_display(exact) if exact is not None else None,
            applicable_weight=total,
            failed_weight=failed[family],
        )
        if exact is not None:
            weighted_sum += FAMILY_WEIGHT[family] * exact
            headline_weight += FAMILY_WEIGHT[family]
    overall = _display(weighted_sum / headline_weight) if headline_weight else None
    grade, caps = capped_grade(overall, cap_severities)
    coverage = Fraction(100 * sum(applicable.values()), denominator) if denominator else Fraction(0)
    return Score(
        overall=overall,
        grade=grade,
        coverage=_display(coverage),
        caps_applied=caps,
        families=families,
    )
