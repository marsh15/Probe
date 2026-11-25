"""behavior.survives_campaign"""

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._support import ALL_MODES, clip
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding
from probe.engine.outcomes import CheckMeta, DisclosureTier, Era, Family, Severity, Transport

_LISTED = 10


@register
class SurvivesCampaign(Check):
    meta = CheckMeta(
        id="behavior.survives_campaign",
        family=Family.BEHAVIOR,
        title="The server stays up for the whole scan",
        severity=Severity.HIGH,
        eras=frozenset(Era),
        transports=frozenset(Transport),
        requires=frozenset({"tools"}),
        modes=ALL_MODES,
        phase="post",
        spec_refs=["2026-07-28/server/tools"],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "Every crash, out-of-memory kill or hang during the scan is a way to take the "
            "server down with input a client can send."
        ),
        remediation=(
            "Find the input behind each crash (the case ids are listed) and make the server "
            "reject or survive it. Bound memory, recursion depth and run time per request."
        ),
    )

    drives_target = False  # it reports the crashes already recorded, even for an unstable target

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        events = ctx.crashes.events
        if not events:
            return CheckOutcome()
        listed = [
            {
                "check": e.check_id,
                "case": e.case_id,
                "exit_code": e.exit_code,
                "oom_killed": e.oom_killed,
            }
            for e in events[:_LISTED]
        ]
        oom = sum(e.oom_killed for e in events)
        return CheckOutcome(
            [
                make_finding(
                    self,
                    ctx,
                    severity=Severity.HIGH,
                    title="The server crashed or hung during the scan",
                    message=(
                        f"The target had to be restarted {len(events)} time(s)"
                        + (f", {oom} after running out of memory" if oom else "")
                        + "."
                    ),
                    case_id="survives-campaign",
                    steps=[],
                    expect={"restarts": 0},
                    observations={"events": listed, "total": len(events)},
                    excerpt=clip(events[0].stderr_tail, 1500) or None,
                )
            ]
        )
