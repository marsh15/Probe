"""Judge the job results against the expectations and write selfval/report.{json,md}."""

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from probe.selfval.expected import CLEAN, Expectation
from probe.selfval.runner import JobResult


@dataclass(slots=True)
class BugRow:
    bug: str
    family: str
    expected: tuple[str, ...]
    transports: tuple[str, ...]
    jobs: int
    detected_jobs: int
    detected: bool
    unexpected: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # scans that did not complete


@dataclass(slots=True)
class Summary:
    implemented: int
    detected: int
    false_positives: list[str]
    unexpected: dict[str, list[str]]
    by_family: dict[str, tuple[int, int]]  # family -> (detected, total)
    rows: list[BugRow]
    clean_problems: list[str]

    @property
    def passed(self) -> bool:
        return (
            self.detected == self.implemented
            and not self.false_positives
            and not self.unexpected
            and not self.clean_problems
        )


def _incomplete(results: list[JobResult]) -> list[str]:
    return [
        f"{r.job.label}: {r.note or r.scan_status}" for r in results if r.scan_status != "completed"
    ]


def judge(expected: dict[str, Expectation], results: list[JobResult]) -> Summary:
    by_bug: dict[str, list[JobResult]] = defaultdict(list)
    for result in results:
        by_bug[result.job.bug].append(result)
    rows: list[BugRow] = []
    unexpected: dict[str, list[str]] = {}
    for name, want in expected.items():
        if name == CLEAN or name not in by_bug:
            continue
        mine = by_bug[name]
        hits = [
            r for r in mine if r.scan_status == "completed" and set(want.primary) <= set(r.failed)
        ]
        extra = sorted({c for r in mine for c in r.failed if c not in want.allowed})
        row = BugRow(
            name,
            want.family,
            want.primary,
            want.transports,
            len(mine),
            len(hits),
            len(hits) == len(mine) > 0,
            extra,
            _incomplete(mine),
        )
        rows.append(row)
        if extra:
            unexpected[name] = extra
    clean = by_bug.get(CLEAN, [])
    false_positives = sorted({c for r in clean for c in r.failed})
    families: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        families[row.family][1] += 1
        families[row.family][0] += int(row.detected)
    return Summary(
        len(rows),
        sum(r.detected for r in rows),
        false_positives,
        unexpected,
        {f: (d, t) for f, (d, t) in sorted(families.items())},
        rows,
        _incomplete(clean),
    )


def render_markdown(summary: Summary, *, mode: str, seeds: list[int], backend: str) -> str:
    lines = [
        "# Probe self-validation",
        "",
        f"Mode `{mode}`, seeds {', '.join(map(str, seeds))}, run {backend}.",
        "",
        f"**Detected {summary.detected} of {summary.implemented} injected bugs.** "
        f"False positives on the clean server: {len(summary.false_positives)}. "
        f"Bugs with unexpected failures: {len(summary.unexpected)}.",
        "",
        "| Family | Detected | Total |",
        "|---|---|---|",
        *(f"| {f} | {d} | {t} |" for f, (d, t) in summary.by_family.items()),
        "",
        "| Bug | Family | Expected check | Detected | Scans | Unexpected failures |",
        "|---|---|---|---|---|---|",
    ]
    for r in summary.rows:
        mark = "yes" if r.detected else "NO"
        scans = f"{r.detected_jobs}/{r.jobs}"
        lines.append(
            f"| {r.bug} | {r.family} | {', '.join(r.expected)} | {mark} | {scans} | "
            f"{', '.join(r.unexpected) or '-'} |"
        )
    if summary.false_positives:
        lines += ["", "False positives: " + ", ".join(summary.false_positives)]
    problems = [p for r in summary.rows for p in r.problems] + summary.clean_problems
    if problems:
        lines += ["", "Scans that did not complete:", *(f"- {p}" for p in problems)]
    return "\n".join(lines) + "\n"


def write_reports(
    summary: Summary,
    results: list[JobResult],
    out_dir: Path,
    *,
    mode: str,
    seeds: list[int],
    backend: str,
) -> Path:
    target = out_dir / "selfval"
    target.mkdir(parents=True, exist_ok=True)
    document: dict[str, Any] = {
        "mode": mode,
        "seeds": seeds,
        "backend": backend,
        "implemented": summary.implemented,
        "detected": summary.detected,
        "false_positives": summary.false_positives,
        "unexpected": summary.unexpected,
        "by_family": {f: {"detected": d, "total": t} for f, (d, t) in summary.by_family.items()},
        "bugs": [asdict(r) for r in summary.rows],
        "jobs": [
            {
                "bug": r.job.bug,
                "transport": r.job.transport,
                "seed": r.job.seed,
                "scan_status": r.scan_status,
                "failed": list(r.failed),
                "errored": list(r.errored),
                "note": r.note,
            }
            for r in results
        ],
        "passed": summary.passed,
    }
    (target / "report.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    (target / "report.md").write_text(
        render_markdown(summary, mode=mode, seeds=seeds, backend=backend)
    )
    return target
