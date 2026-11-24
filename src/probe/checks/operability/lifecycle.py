"""Fresh-instance shutdown and scan startup measurements."""

from probe.checks.base import Applicability, Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.operability._support import metadata, observation
from probe.checks.registry import register
from probe.engine.outcomes import Severity


@register
class CleanShutdown(Check):
    meta = metadata(
        "clean_shutdown",
        "Stdio targets stop without SIGKILL",
        Severity.LOW,
        "post",
        "A server that ignores EOF and SIGTERM leaves processes behind during normal teardown.",
        "Exit after stdin closes or within five seconds of SIGTERM.",
        requires=frozenset({"second_instance"}),
    )

    def applicable(self, ctx: ScanContext) -> Applicability:
        return (
            Applicability.yes()
            if callable(getattr(ctx.runner, "check_shutdown", None))
            else (Applicability.no("runner cannot observe target shutdown"))
        )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        result = await ctx.runner.check_shutdown()
        if result.killed:
            return CheckOutcome(
                [
                    observation(
                        self,
                        ctx,
                        "The process survived stdin EOF (5 s) and SIGTERM (5 s); forced cleanup.",
                        case="shutdown",
                        data={
                            "exit_code": result.exit_code,
                            "terminated": result.terminated,
                            "killed": result.killed,
                        },
                    )
                ]
            )
        return CheckOutcome()


@register
class StartupTime(Check):
    meta = metadata(
        "startup_time",
        "Startup latency is recorded",
        Severity.INFO,
        "passive",
        "Time to the first successful response describes cold-start operability.",
        "Investigate cold starts longer than 30 seconds.",
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        if ctx.startup_ms is None:
            return CheckOutcome.na("startup timing was not recorded")
        message = f"First successful response after {ctx.startup_ms:.1f} ms."
        if ctx.startup_ms > 30_000:
            message += " Startup exceeded 30 s."
        return CheckOutcome(
            [
                observation(
                    self,
                    ctx,
                    message,
                    case="startup",
                    data={"startup_ms": ctx.startup_ms},
                )
            ]
        )
