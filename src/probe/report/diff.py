"""Compare two reports: score change, new findings, fixed findings.

Findings are matched by check, tool and case, not by finding id: the id includes the target's
identity, so a rebuilt image gets new ids for the same problems.
"""

from typing import Any

from probe.engine.outcomes import Finding
from probe.report.markdown import top_findings
from probe.report.models import ScanReport
from probe.report.text import md_text


def _key(finding: Finding) -> tuple[str, str | None, str]:
    return (finding.check_id, finding.tool, finding.repro.case_id)


def _change(base: float | None, head: float | None) -> dict[str, Any]:
    delta = None if base is None or head is None else round(head - base, 1)
    return {"base": base, "head": head, "delta": delta}


def _summary(finding: Finding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "check_id": finding.check_id,
        "tool": finding.tool,
        "case_id": finding.repro.case_id,
        "severity": finding.severity.value,
        "title": finding.title,
    }


def diff_reports(base: ScanReport, head: ScanReport) -> dict[str, Any]:
    base_keys = {_key(f) for f in base.findings}
    head_keys = {_key(f) for f in head.findings}
    new = [f for f in top_findings(head.findings) if _key(f) not in base_keys]
    fixed = [f for f in top_findings(base.findings) if _key(f) not in head_keys]
    families = {
        family.value: _change(
            base.score.families[family].score if family in base.score.families else None,
            head.score.families[family].score if family in head.score.families else None,
        )
        for family in head.score.families
    }
    return {
        "base": {"name": base.target.name, "scan_id": base.scan.id},
        "head": {"name": head.target.name, "scan_id": head.scan.id},
        "grade": {"base": base.score.grade, "head": head.score.grade},
        "score": {
            "overall": _change(base.score.overall, head.score.overall),
            "coverage": _change(base.score.coverage, head.score.coverage),
            "families": families,
        },
        "new": [_summary(f) for f in new],
        "fixed": [_summary(f) for f in fixed],
        "unchanged": len(base_keys & head_keys),
    }


def _signed(delta: float | None) -> str:
    return "n/a" if delta is None else f"{delta:+.1f}"


def _show(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


def _table(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["| Severity | Check | Tool | Finding |", "| --- | --- | --- | --- |"]
    for r in rows:
        tool = md_text(r["tool"]) if r["tool"] else "-"
        lines.append(
            f"| {r['severity']} | {md_text(r['check_id'])} | {tool} | {md_text(r['title'])} |"
        )
    return lines


def render_diff_md(diff: dict[str, Any]) -> str:
    overall = diff["score"]["overall"]
    coverage = diff["score"]["coverage"]
    grade = diff["grade"]
    lines = [
        "## Probe diff",
        "",
        f"Grade {grade['base'] or 'none'} → {grade['head'] or 'none'}; "
        f"score {_show(overall['base'])} → {_show(overall['head'])} ({_signed(overall['delta'])}); "
        f"coverage {_show(coverage['base'])} → {_show(coverage['head'])} "
        f"({_signed(coverage['delta'])}).",
        "",
        "| Family | Base | Head | Change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, row in diff["score"]["families"].items():
        lines.append(
            f"| {name} | {_show(row['base'])} | {_show(row['head'])} | {_signed(row['delta'])} |"
        )
    lines += ["", f"### New findings ({len(diff['new'])})", ""]
    lines += _table(diff["new"]) if diff["new"] else ["None."]
    lines += ["", f"### Fixed findings ({len(diff['fixed'])})", ""]
    lines += _table(diff["fixed"]) if diff["fixed"] else ["None."]
    lines += ["", f"{diff['unchanged']} finding(s) unchanged.", ""]
    return "\n".join(lines)
