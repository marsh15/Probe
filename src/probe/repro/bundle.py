"""Repro bundles: everything needed to run one finding's check again, written beside the report.

``<out>/repro/<finding_id>/repro.json`` holds how the target was started, the scan settings
that matter (mode, seed, era, side effects, profile), the wire steps the check recorded and
what it expected. Secrets never go in: ``--secret-env`` values are left out (only the names
are kept, and replay reads them from the environment again) and the profile is stored with
its ``{secret:NAME}`` placeholders unresolved.
"""

import gzip
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import Field

from probe.engine.outcomes import Finding, StrictModel
from probe.engine.runscan import TRACE_FILE, RunConfig
from probe.report.models import ScanReport

BUNDLE_DIR = "repro"
BUNDLE_FILE = "repro.json"
EXCERPT_FILE = "trace-excerpt.jsonl"
_FINDING_ID = re.compile(r"[0-9a-f]{16}")


class BundleError(Exception):
    """The report or bundle cannot be used (exit code 2)."""


class ReproTarget(StrictModel):
    name: str
    transport: str
    command: list[str] | None = None
    url: str | None = None
    image: str | None = None
    image_digest: str | None = None
    sandbox: bool | None = None
    i_have_permission: bool = False


class ReproRun(StrictModel):
    mode: str
    seed: int
    era: str  # the --era choice: auto, modern or legacy
    negotiated_version: str | None = None  # what the scan actually spoke
    allow_side_effects: bool = False
    timeout_scale: float = 1.0
    secret_env: list[str] = Field(default_factory=list)
    target_env: dict[str, str] = Field(default_factory=dict)


class ReproBundle(StrictModel):
    bundle_version: int = 1
    finding_id: str
    check_id: str
    tool: str | None
    case_id: str
    severity: str
    title: str
    probe_version: str
    catalog_version: str
    target: ReproTarget
    run: ReproRun
    profile: dict[str, Any]
    steps: list[dict[str, Any]]
    expect: dict[str, Any]


def bundle_for(finding: Finding, report: ScanReport, cfg: RunConfig) -> ReproBundle:
    secret_names = set(cfg.secret_env)
    return ReproBundle(
        finding_id=finding.finding_id,
        check_id=finding.check_id,
        tool=finding.tool,
        case_id=finding.repro.case_id,
        severity=finding.severity.value,
        title=finding.title,
        probe_version=report.probe_version,
        catalog_version=report.catalog_version,
        target=ReproTarget(
            name=report.target.name,
            transport=report.target.transport.value,
            command=list(cfg.command) if cfg.command else None,
            url=cfg.url,
            image=cfg.image,
            image_digest=report.target.image_digest,
            sandbox=cfg.sandbox,
            i_have_permission=cfg.i_have_permission,
        ),
        run=ReproRun(
            mode=cfg.mode,
            seed=cfg.seed,
            era=cfg.era,
            negotiated_version=report.target.era.negotiated_version,
            allow_side_effects=cfg.allow_side_effects,
            timeout_scale=cfg.timeout_scale,
            secret_env=sorted(secret_names),
            target_env={k: v for k, v in cfg.target_env.items() if k not in secret_names},
        ),
        profile=cfg.profile.model_dump(mode="json"),
        steps=finding.repro.steps,
        expect=finding.repro.expect,
    )


def _trace_excerpt(trace: Path, indexes: Iterable[int]) -> list[str]:
    wanted = set(indexes)
    if not wanted:
        return []
    gz = trace.with_name(trace.name + ".gz")
    path = gz if gz.exists() else trace
    if not path.exists():
        return []
    opener = gzip.open if path == gz else open
    with opener(path, "rt", encoding="utf-8") as handle:
        return [line.rstrip("\n") for i, line in enumerate(handle) if i in wanted]


def write_bundles(report: ScanReport, cfg: RunConfig, out_dir: Path) -> list[Path]:
    """Write one bundle per finding under ``out_dir/repro``; returns the bundle files."""
    written: list[Path] = []
    for finding in report.findings:
        directory = out_dir / BUNDLE_DIR / finding.finding_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / BUNDLE_FILE
        path.write_text(
            bundle_for(finding, report, cfg).model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        refs = [*finding.evidence.request_refs, *finding.evidence.response_refs]
        excerpt = _trace_excerpt(out_dir / TRACE_FILE, refs)
        if excerpt:
            (directory / EXCERPT_FILE).write_text("\n".join(excerpt) + "\n", encoding="utf-8")
        written.append(path)
    return written


def known_finding_ids(report_path: Path) -> list[str]:
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot read report {report_path}: {exc}") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise BundleError(f"{report_path} is not a Probe report")
    return [f["finding_id"] for f in findings if isinstance(f, dict) and "finding_id" in f]


def load_bundle(report_path: Path, finding_id: str) -> ReproBundle:
    """The bundle for ``finding_id`` next to ``report_path``."""
    ids = known_finding_ids(report_path)
    if not _FINDING_ID.fullmatch(finding_id) or finding_id not in ids:
        listed = ", ".join(ids) if ids else "none (the report has no findings)"
        raise BundleError(f"no finding {finding_id!r} in {report_path}; findings: {listed}")
    path = report_path.parent / BUNDLE_DIR / finding_id / BUNDLE_FILE
    try:
        return ReproBundle.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot read the repro bundle {path}: {exc}") from exc
