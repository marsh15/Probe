"""The single-file HTML report ("lab report" design: evidence first, calm, no external requests).

Everything the scanned server said is escaped by Jinja's autoescape; the only markup that is
not escaped is the static stylesheet and script shipped with Probe and SVG built from numbers.
The page carries a Content-Security-Policy that allows no network access and only the one
script, pinned by hash.
"""

import base64
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

import probe.checks.behavior
import probe.checks.official
import probe.checks.operability
import probe.checks.protocol
import probe.checks.safety
import probe.checks.schema  # noqa: F401 - registers the checks whose texts the report shows
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Family, Finding, Severity, Status
from probe.report.models import ScanReport
from probe.report.svg_charts import meter

_HERE = Path(__file__).parent
HTML_FILE = "report.html"
MAX_FINDINGS = 300
_OBSERVATION_CHARS = 1500
_GLYPH = {"critical": "✖", "high": "▲", "medium": "◆", "low": "●", "info": "○"}
_STATUS_GLYPH = {"pass": "✓", "fail": "✖", "error": "!", "not_applicable": "-", "skipped": "-"}
_FAMILY_ORDER = [Family.SAFETY, Family.BEHAVIOR, Family.SCHEMA, Family.PROTOCOL, Family.OPERABILITY]
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_env = Environment(
    loader=FileSystemLoader(_HERE / "templates"),
    autoescape=select_autoescape(["html", "j2"], default=True),
    undefined=StrictUndefined,
)


def _era(report: ScanReport) -> str:
    era = report.target.era
    if era.kind is None:
        return "protocol era unknown"
    if era.kind == "legacy":
        return f"legacy ({era.negotiated_version})"
    return "2026-07-28 ✓" + (" + legacy" if era.kind == "dual" else "")


def _catalog(check_id: str) -> dict[str, Any]:
    try:
        meta = REGISTRY.get(check_id).meta
    except KeyError:
        return {"rationale": "", "remediation": ""}
    return {"rationale": meta.rationale, "remediation": meta.remediation}


def _observations(finding: Finding) -> str:
    if not finding.evidence.observations:
        return ""
    text = json.dumps(finding.evidence.observations, indent=2, sort_keys=True, default=str)
    return text if len(text) <= _OBSERVATION_CHARS else text[:_OBSERVATION_CHARS] + "\n…"


def _families(report: ScanReport) -> list[dict[str, Any]]:
    counts: dict[str, Counter[str]] = {f.value: Counter() for f in _FAMILY_ORDER}
    for row in report.results:
        key = {
            Status.PASS: "passed",
            Status.FAIL: "failed",
            Status.NA: "na",
        }.get(row.status, "other")
        counts[row.family.value][key] += 1
    rows = []
    for family in _FAMILY_ORDER:
        score = report.score.families[family].score if family in report.score.families else None
        c = counts[family.value]
        rows.append(
            {
                "name": family.value,
                "score": score,
                "meter": meter(score, f"{family.value} score"),
                "counts": {k: c[k] for k in ("passed", "failed", "na", "other")},
            }
        )
    return rows


def _groups(findings: list[Finding]) -> list[dict[str, Any]]:
    order = {f: i for i, f in enumerate(_FAMILY_ORDER)}
    by_severity: dict[Severity, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity].append(finding)
    groups = []
    for severity in _SEVERITY_ORDER:
        items = sorted(
            by_severity[severity], key=lambda f: (order[f.family], f.check_id, f.tool or "")
        )
        if items:
            groups.append(
                {
                    "severity": severity.value,
                    "label": severity.value.capitalize(),
                    "glyph": _GLYPH[severity.value],
                    "findings": items,
                }
            )
    return groups


def _ungraded_reason(report: ScanReport) -> str:
    if report.scan.status != "completed":
        return f"The scan ended with status {report.scan.status}, so no checks could be scored."
    return "No check that counts toward the score could be applied to this server."


def render_html(report: ScanReport) -> str:
    css = (_HERE / "static" / "style.css").read_text(encoding="utf-8")
    js = (_HERE / "static" / "report.js").read_text(encoding="utf-8").strip()
    digest = base64.b64encode(hashlib.sha256(js.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'sha256-{digest}'; img-src data:; base-uri 'none'; form-action 'none'"
    )
    ordered = [f for g in _groups(report.findings) for f in g["findings"]]
    shown = ordered[:MAX_FINDINGS]
    shown_ids = {f.finding_id for f in shown}
    groups = _groups([f for f in report.findings if f.finding_id in shown_ids])
    details = {
        check_id: {**_catalog(check_id), "spec_refs": []}
        for check_id in {f.check_id for f in shown}
    }
    for row in report.results:
        if row.check_id in details:
            details[row.check_id]["spec_refs"] = row.spec_refs
    info = report.target.server_info
    version = info.get("version") if isinstance(info.get("version"), str) else ""
    started = report.scan.started_at.strftime("%Y-%m-%d %H:%M UTC")
    scan = report.scan
    metadata = [
        ("scan id", scan.id),
        ("scan key", scan.scan_key),
        ("mode", scan.mode),
        ("seed", str(scan.seed)),
        ("status", scan.status),
        ("duration", f"{scan.duration_ms / 1000:.1f} s"),
        ("platform", scan.platform),
        ("sandbox", f"{'yes' if scan.sandboxed else 'no'} ({scan.runtime})"),
        ("image digest", report.target.image_digest or "none"),
        ("profile hash", report.target.profile_hash or "none"),
        ("catalog version", report.catalog_version),
        ("scoring version", report.scoring_version),
        ("calls", str(report.stats.calls)),
    ]
    page = _env.get_template("report.html.j2").render(
        report=report,
        score=report.score,
        name=report.target.name,
        version=version,
        transport=report.target.transport.value,
        era=_era(report),
        scanned=started,
        css=Markup(css),  # noqa: S704 - static file shipped with Probe
        js=Markup(js),  # noqa: S704 - static file shipped with Probe
        csp=Markup(csp),  # noqa: S704 - built here from a hash and fixed text
        coverage_meter=meter(report.score.coverage, "Coverage"),
        ungraded_reason=_ungraded_reason(report),
        families=_families(report),
        groups=groups,
        details=details,
        observations={f.finding_id: _observations(f) for f in shown},
        hidden_findings=len(report.findings) - len(shown),
        shown_findings=len(shown),
        glyphs=_GLYPH,
        status_glyph=_STATUS_GLYPH,
        statuses=sorted({r.status.value for r in report.results}),
        metadata=metadata,
    )
    return page


def write_html(report: ScanReport, out_dir: Path) -> Path:
    path = out_dir / HTML_FILE
    path.write_text(render_html(report), encoding="utf-8")
    return path
