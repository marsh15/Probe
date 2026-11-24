"""Render a report in each output format and read one back from disk."""

import json
from pathlib import Path

from probe.report.badge import BadgeStyle, badge_json
from probe.report.html import render_html
from probe.report.markdown import summary_md
from probe.report.models import ScanReport
from probe.report.sarif import to_sarif

FORMATS = ("json", "html", "sarif", "md", "badge")
FILE_NAMES = {
    "json": "report.json",
    "html": "report.html",
    "sarif": "report.sarif",
    "md": "summary.md",
    "badge": "badge.json",
}


class ReportError(Exception):
    """The file is missing or is not a Probe report."""


def load_report(path: Path) -> ScanReport:
    try:
        return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ReportError(f"{path} is not a Probe report: {str(exc).splitlines()[0]}") from exc


def render(
    report: ScanReport, fmt: str, *, anchor: str = "README.md", badge_style: BadgeStyle = "grade"
) -> str:
    if fmt == "html":
        return render_html(report)
    if fmt == "sarif":
        return json.dumps(to_sarif(report, anchor), indent=2) + "\n"
    if fmt == "md":
        return summary_md(report)
    if fmt == "badge":
        return json.dumps(badge_json(report, badge_style)) + "\n"
    if fmt == "json":
        return report.model_dump_json(indent=2) + "\n"
    raise ValueError(f"unknown format {fmt!r}")
