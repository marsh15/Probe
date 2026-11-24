"""``summary.md``: grade, families and the top findings, safe to paste into a pull request."""

from probe.engine.outcomes import Finding, Severity
from probe.report.models import ScanReport
from probe.report.text import md_text

TOP_FINDINGS = 10
_RANK = {s: i for i, s in enumerate(Severity)}  # critical first


def top_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_RANK[f.severity], f.family.value, f.check_id))


def summary_md(report: ScanReport, html_link: str = "report.html") -> str:
    score = report.score
    if score.grade is None or score.overall is None:
        head = f"## Probe: not graded (coverage {score.coverage:.1f}%)"
    else:
        head = f"## Probe: {score.grade} · {score.overall:.1f} (coverage {score.coverage:.1f}%)"
    era = report.target.era.negotiated_version or "unknown"
    lines = [
        head,
        "",
        f"Target {md_text(report.target.name)} · {report.target.transport.value} · protocol {era}"
        f" · Probe {md_text(report.probe_version)}",
    ]
    if score.caps_applied:
        lines += ["", f"Grade capped: {md_text('; '.join(score.caps_applied).replace('_', ' '))}."]
    lines += ["", "| Family | Score | Pass | Fail |", "| --- | ---: | ---: | ---: |"]
    for family, fam in score.families.items():
        passed = sum(1 for r in report.results if r.family == family and r.status.value == "pass")
        failed = sum(1 for r in report.results if r.family == family and r.status.value == "fail")
        value = "n/a" if fam.score is None else f"{fam.score:.1f}"
        lines.append(f"| {family.value} | {value} | {passed} | {failed} |")
    ordered = top_findings(report.findings)
    shown = ordered[:TOP_FINDINGS]
    lines += ["", f"### Findings ({len(ordered)})", ""]
    if not shown:
        lines.append("No findings.")
    else:
        lines += [
            "| Severity | Check | Tool | Finding | Reproduce |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in shown:
            tool = md_text(f.tool) if f.tool else "-"
            lines.append(
                f"| {f.severity.value} | {md_text(f.check_id)} | {tool} | {md_text(f.title)} "
                f"| `probe repro report.json --finding {f.finding_id}` |"
            )
        if len(ordered) > len(shown):
            lines += ["", f"{len(ordered) - len(shown)} more in report.json."]
    lines += ["", f"Full report: {md_text(html_link)}", "", f"_{md_text(report.honesty, 300)}_", ""]
    return "\n".join(lines)
