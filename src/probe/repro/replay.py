"""Run a finding's check again on a fresh target and say whether the finding comes back.

The replay is the original check, same mode, seed, era and profile, restricted to that one
check (``only``). A finding counts as reproduced when the check reports one with the same
check, tool and case: the finding id is not compared, because it includes the target's
identity and a rebuilt or fixed target has a different one.
"""

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from probe.config.profile import Profile
from probe.engine.outcomes import Finding, Status
from probe.engine.runscan import RunConfig, run_scan
from probe.repro.bundle import ReproBundle

Verdict = Literal["reproduced", "not_reproduced", "inconclusive", "target_unavailable"]


@dataclass(frozen=True)
class ReplayOutcome:
    verdict: Verdict
    detail: str
    matched: Finding | None = None
    other: tuple[Finding, ...] = ()  # findings the check reported that are not this one


def config_for(
    bundle: ReproBundle,
    out_dir: Path,
    *,
    target_env: Mapping[str, str] | None = None,
    image: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> RunConfig:
    """The scan settings for the replay: the bundle's, with the caller's overrides on top."""
    env = {**bundle.run.target_env, **(target_env or {})}
    host = environ or {}
    for name in bundle.run.secret_env:
        if name in host and name not in env:
            env[name] = host[name]  # secret values are never stored: take them from the host
    return RunConfig(
        out_dir=out_dir,
        command=bundle.target.command,
        url=bundle.target.url,
        profile=Profile.model_validate(bundle.profile),
        mode=cast(Any, bundle.run.mode),
        seed=bundle.run.seed,
        era=cast(Any, bundle.run.era),
        allow_side_effects=bundle.run.allow_side_effects,
        only=[bundle.check_id],
        timeout_scale=bundle.run.timeout_scale,
        image=image or bundle.target.image,
        sandbox=bundle.target.sandbox,
        i_have_permission=bundle.target.i_have_permission,
        secret_env=bundle.run.secret_env,
        target_env=env,
        environ=dict(host) if environ is not None else None,
    )


def _same_case(finding: Finding, bundle: ReproBundle) -> bool:
    return (
        finding.check_id == bundle.check_id
        and finding.tool == bundle.tool
        and finding.repro.case_id == bundle.case_id
    )


async def replay(
    bundle: ReproBundle,
    *,
    target_env: Mapping[str, str] | None = None,
    image: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ReplayOutcome:
    with tempfile.TemporaryDirectory(prefix="probe-repro-") as scratch:
        cfg = config_for(bundle, Path(scratch), target_env=target_env, image=image, environ=environ)
        report = await run_scan(cfg)
    if report.scan.status != "completed":
        return ReplayOutcome("target_unavailable", "the target did not start or answer")
    result = next((r for r in report.results if r.check_id == bundle.check_id), None)
    matched = next((f for f in report.findings if _same_case(f, bundle)), None)
    other = tuple(f for f in report.findings if f is not matched)
    if matched is not None:
        return ReplayOutcome("reproduced", matched.message, matched, other)
    if result is not None and result.status in (Status.PASS, Status.FAIL):
        detail = (
            f"the check {result.status.value}ed without this finding"
            if result.status is Status.PASS
            else "the check failed, but not with this finding"
        )
        return ReplayOutcome("not_reproduced", detail, None, other)
    state = result.status.value if result is not None else "did not run"
    reason = f": {result.reason}" if result is not None and result.reason else ""
    return ReplayOutcome("inconclusive", f"the check {state}{reason}", None, other)
