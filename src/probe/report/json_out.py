"""Turn what a scan found into ``report.json``."""

from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from probe.checks.registry import Registry
from probe.engine.outcomes import (
    CheckResult,
    Family,
    Finding,
    Status,
    ToolInfo,
)
from probe.report.models import (
    ResultSummary,
    ToolSummary,
)
from probe.util.hashing import canonical_hash

REPORT_FILE = "report.json"


def tool_summaries(
    tools: Iterable[ToolInfo], cases_run: Mapping[str, int] | None = None
) -> list[ToolSummary]:
    cases = cases_run or {}
    return [
        ToolSummary(
            name=t.name,
            kind=t.kind,
            flags=sorted(t.flags),
            classification_source=t.classification_source,
            classification_reason=t.classification_reason,
            annotations=t.annotations,
            input_schema_hash=canonical_hash(t.input_schema),
            cases_run=cases.get(t.name, 0),
        )
        for t in tools
    ]


def result_summaries(results: Iterable[CheckResult], registry: Registry) -> list[ResultSummary]:
    """One row per check, with the metadata the report shows next to its outcome."""
    rows = []
    for result in results:
        meta = registry.get(result.check_id).meta
        rows.append(
            ResultSummary(
                check_id=result.check_id,
                family=meta.family,
                title=meta.title,
                severity=meta.severity,
                status=result.status,
                reason=result.reason,
                spec_refs=list(meta.spec_refs),
                duration_ms=result.duration_ms,
                calls=result.calls,
                finding_ids=[f.finding_id for f in result.findings],
            )
        )
    return rows


def all_findings(results: Iterable[CheckResult]) -> list[Finding]:
    return [f for r in results for f in r.findings]


def status_counts(rows: Iterable[ResultSummary]) -> dict[Family, Counter[Status]]:
    counts: dict[Family, Counter[Status]] = {family: Counter() for family in Family}
    for row in rows:
        counts[row.family][row.status] += 1
    return counts


def report_json(report: Any) -> str:
    """The report as indented JSON (keys in schema order, sets already sorted)."""
    return str(report.model_dump_json(indent=2)) + "\n"


def write_report(report: Any, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / REPORT_FILE
    path.write_text(report_json(report), encoding="utf-8")
    return path
