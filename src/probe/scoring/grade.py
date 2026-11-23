"""Grade the rounded overall and record triggered instance caps in fixed severity order."""

from collections.abc import Set

from probe.engine.outcomes import Severity
from probe.report.models import Grade

_GRADES: tuple[Grade, ...] = ("A", "B", "C", "D", "F")
_THRESHOLDS: tuple[tuple[int, Grade], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))
_CAPS: tuple[tuple[Severity, Grade], ...] = ((Severity.CRITICAL, "D"), (Severity.HIGH, "B"))


def capped_grade(
    overall: float | None, severities: Set[Severity]
) -> tuple[Grade | None, list[str]]:
    if overall is None:
        return None, []
    grade: Grade = "F"
    for threshold, candidate in _THRESHOLDS:
        if overall >= threshold:
            grade = candidate
            break
    caps = []
    for severity, ceiling in _CAPS:
        if severity in severities:
            caps.append(f"{severity.value}_instance_caps_at_{ceiling}")
            grade = _GRADES[max(_GRADES.index(grade), _GRADES.index(ceiling))]
    return grade, caps
