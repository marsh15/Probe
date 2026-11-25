"""Look for Probe-supplied sensitive values in server logging channels."""

import asyncio
import json

from probe.checks.base import Check, CheckOutcome
from probe.checks.context import ScanContext
from probe.checks.operability._support import arguments, metadata, observation
from probe.checks.registry import register
from probe.checks.support import slug
from probe.engine.budget import BudgetExhausted
from probe.engine.outcomes import Severity
from probe.wire.limits import STDERR_RING_BYTES


@register
class LogsNoSecrets(Check):
    meta = metadata(
        "logs_no_secrets",
        "Logs omit sensitive tool arguments",
        Severity.MEDIUM,
        "active.safe",
        "Logging credentials exposes them to every operator and log consumer.",
        "Redact sensitive arguments from stderr, container logs and logging notifications.",
        requires=frozenset({"tools", "fixtures"}),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        if ctx.fixtures is None:
            return CheckOutcome.na("no fixtures")
        findings = []
        tested = 0
        sentinel: str | None = None
        notification_has_sentinel = False

        async def collect() -> None:
            nonlocal notification_has_sentinel
            async for notification in ctx.client.transport.notifications():
                if sentinel is not None and notification.method == "notifications/message":
                    text = json.dumps(notification.params, ensure_ascii=False)
                    if sentinel in text:
                        notification_has_sentinel = True

        collector = asyncio.create_task(collect())
        try:
            for index, tool in enumerate(ctx.callable_tools()):
                if "sensitive_param" not in tool.flags:
                    continue
                names = [k for k, role in tool.param_roles.items() if role == "sensitive_param"]
                args = await arguments(ctx, tool)
                if not names or args is None:
                    continue
                sentinel = f"probe-sensitive-{ctx.fixtures.token}-{index:08x}"
                notification_has_sentinel = False
                args.update(dict.fromkeys(names, sentinel))
                try:
                    await ctx.call(tool.name, args, case_id=f"secret-log:{slug(tool.name)}")
                except BudgetExhausted:
                    break
                tested += 1
                await asyncio.sleep(0)  # let the notification consumer and stderr reader drain
                sources = []
                if sentinel in ctx.client.transport.stderr_tail(STDERR_RING_BYTES):
                    sources.append("stderr")
                if sentinel in await ctx.runner.logs():
                    sources.append("runner logs")
                if notification_has_sentinel:
                    sources.append("notifications/message")
                if sources:
                    findings.append(
                        observation(
                            self,
                            ctx,
                            "The supplied sensitive sentinel appeared in server logs.",
                            case=f"secret-log:{slug(tool.name)}",
                            tool=tool.name,
                            params={"name": tool.name, "arguments": args},
                            data={"sources": sorted(set(sources))},
                            excerpt=sentinel,
                        )
                    )
        finally:
            collector.cancel()
            await asyncio.gather(collector, return_exceptions=True)
        return (
            CheckOutcome(findings)
            if tested
            else CheckOutcome.na(
                "no callable tool has a sensitive parameter with generated arguments"
            )
        )
