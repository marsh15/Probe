"""A shields.io endpoint badge (``badge.json``)."""

from typing import Any, Literal

from probe.report.models import ScanReport

BadgeStyle = Literal["grade", "coverage"]
_COLOUR = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


def badge_json(report: ScanReport, style: BadgeStyle = "grade") -> dict[str, Any]:
    score = report.score
    if style == "coverage":
        return {
            "schemaVersion": 1,
            "label": "probe coverage",
            "message": f"{score.coverage:.1f}%",
            "color": "blue",
        }
    if score.grade is None or score.overall is None:
        return {"schemaVersion": 1, "label": "probe", "message": "not graded", "color": "lightgrey"}
    return {
        "schemaVersion": 1,
        "label": "probe",
        "message": f"{score.grade} · {score.overall:.1f}",
        "color": _COLOUR[score.grade],
    }
