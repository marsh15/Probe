"""Run checks against a connected target and turn what happens into ``CheckResult``s.

Order is fixed (phases, then check id) so a scan is reproducible. Before each active phase the
fixtures are reset (and a dead target restarted); after each active check a liveness probe
makes sure the next check starts against a live server. A check that raises is ERROR: that is
a Probe fault and is never counted against the server.
"""

import time
from collections.abc import Iterable

from probe.checks.base import FAILING, Check
from probe.checks.context import ScanContext
from probe.checks.registry import PHASE_ORDER, REGISTRY
from probe.engine.budget import BudgetExhausted
from probe.engine.crash import TargetCrashed, TargetUnstable
from probe.engine.outcomes import CheckResult, Status
from probe.engine.phases import ACTIVE_PHASES, gate
from probe.util.sanitize_console import sanitize_console

_REASON_MAX = 300


def ordered(checks: Iterable[type[Check]]) -> list[type[Check]]:
    return sorted(checks, key=lambda c: (PHASE_ORDER.index(c.meta.phase), c.meta.id))


async def run_checks(
    ctx: ScanContext, checks: Iterable[type[Check]] | None = None
) -> list[CheckResult]:
    results: list[CheckResult] = []
    phase: str | None = None
    for cls in ordered(REGISTRY if checks is None else checks):
        meta = cls.meta
        if (blocked := gate(meta, ctx)) is not None:
            results.append(
                CheckResult(check_id=meta.id, status=blocked.status, reason=blocked.reason)
            )
            continue
        instance = cls()
        applicable = instance.applicable(ctx)
        if not applicable.ok:
            results.append(
                CheckResult(check_id=meta.id, status=Status.NA, reason=applicable.reason)
            )
            continue
        active = meta.phase in ACTIVE_PHASES
        if active and ctx.crashes.unstable:
            results.append(
                CheckResult(check_id=meta.id, status=Status.ERROR, reason="target_unstable")
            )
            continue
        if active and meta.phase != phase:
            await _begin_active_phase(ctx)
        phase = meta.phase
        result = await _run_one(instance, ctx)
        results.append(result)
        if active and not ctx.crashes.unstable:
            await ctx.liveness()
    return results


async def _begin_active_phase(ctx: ScanContext) -> None:
    await ctx.restart_if_dead("found not running at the start of a phase")
    if ctx.fixtures is not None:
        await ctx.fixtures.reset()


async def _run_one(check: Check, ctx: ScanContext) -> CheckResult:
    meta = check.meta
    ctx.begin_check(meta.id)
    started = time.monotonic()
    result = await _execute(check, ctx)
    return result.model_copy(
        update={"duration_ms": int((time.monotonic() - started) * 1000), "calls": ctx.calls}
    )


async def _execute(check: Check, ctx: ScanContext) -> CheckResult:
    meta = check.meta

    def error(reason: str) -> CheckResult:
        return CheckResult(check_id=meta.id, status=Status.ERROR, reason=_clip(reason))

    try:
        outcome = await check.run(ctx)
    except TargetCrashed as crash:
        return error(
            f"target crashed (exit code {crash.event.exit_code}) and the check did not reproduce "
            "it; crash recorded"
        )
    except TargetUnstable:
        return error("target_unstable")
    except BudgetExhausted as exc:
        return error(f"{exc} before the check reached a verdict")
    except Exception as exc:
        return error(f"check raised {type(exc).__name__}: {exc}")

    findings = outcome.findings
    if any(f.check_id != meta.id for f in findings):
        return error("a finding names a different check id")
    failing = any(f.severity in FAILING for f in findings)
    status = outcome.status
    if status is None:
        status = Status.FAIL if failing else Status.PASS
    elif status is Status.PASS and failing:
        return error("check reported PASS but returned findings of severity low or higher")
    elif status is Status.FAIL and not failing:
        return error("check reported FAIL without a finding of severity low or higher")
    elif status in (Status.NA, Status.SKIPPED, Status.ERROR) and findings:
        return error(f"check reported {status.value} but returned findings")
    reason = _clip(outcome.reason) if status in (Status.NA, Status.SKIPPED, Status.ERROR) else None
    if status in (Status.NA, Status.SKIPPED, Status.ERROR) and not reason:
        reason = "no reason given"
    return CheckResult(check_id=meta.id, status=status, reason=reason, findings=list(findings))


def _clip(text: str | None) -> str:
    cleaned = sanitize_console(text or "")
    return cleaned if len(cleaned) <= _REASON_MAX else cleaned[: _REASON_MAX - 1] + "…"
