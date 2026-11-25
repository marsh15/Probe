"""behavior.tasks_lifecycle"""

import re
from typing import Any

from probe.checks.base import Check, CheckOutcome
from probe.checks.behavior._campaign import campaign
from probe.checks.behavior._support import clip, input_policy
from probe.checks.context import ScanContext
from probe.checks.registry import register
from probe.checks.support import make_finding, request_step
from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Family,
    Finding,
    Severity,
    ToolInfo,
)
from probe.engine.outcomes import Transport as TransportKind
from probe.wire.errors import RequestTimeout
from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse
from probe.wire.limits import request_timeout
from probe.wire.tasks import (
    CAPABILITIES_META,
    Task,
    cancel_task,
    get_task,
    is_task_result,
    task_from,
    wait_for_terminal,
    with_tasks_capability,
)

_LIKELY = re.compile(r"export|job|task|batch|long|report|async|import|build", re.IGNORECASE)
_TOOLS_TRIED = 6
_SETTLE_S = 5.0  # how long to watch a cancelled task
_SPEC = "2026-07-28/tasks"


class _Run:
    """The calls one run of the check makes, and what it concluded."""

    def __init__(self, check: Check, ctx: ScanContext) -> None:
        self.check, self.ctx = check, ctx
        self.findings: list[Finding] = []
        self.steps: list[dict[str, Any]] = []
        self.meta = {CAPABILITIES_META: with_tasks_capability(ctx.client.client_capabilities)}

    async def send(self, method: str, params: dict[str, Any]) -> Response:
        self.steps.append(request_step(method, params))
        return await self.ctx.request(method, params, meta=self.meta, case_id="tasks")

    def fail(self, case: str, title: str, message: str, tool: str | None = None) -> None:
        self.findings.append(
            make_finding(
                self.check,
                self.ctx,
                severity=Severity.MEDIUM,
                title=title,
                message=clip(message, 400),
                tool=tool,
                case_id=f"tasks:{case}",
                steps=list(self.steps),
                expect={"tasks": "as the Tasks extension specifies"},
                observations={"detail": clip(message, 400)},
            )
        )


@register
class TasksLifecycle(Check):
    meta = CheckMeta(
        id="behavior.tasks_lifecycle",
        family=Family.BEHAVIOR,
        title="Tasks are created durably, reach a terminal state and can be cancelled",
        severity=Severity.MEDIUM,
        eras=frozenset({Era.MODERN}),
        transports=frozenset(TransportKind),
        requires=frozenset({"tools", "tasks_ext"}),
        modes=frozenset({"quick", "standard", "deep"}),
        phase="active.write",
        min_version="2026-07-28",
        spec_refs=[_SPEC],
        disclosure=DisclosureTier.PUBLIC,
        rationale=(
            "A client that is handed a task id expects to poll it at once, see it finish, and "
            "cancel it. A task that cannot be found right after creation, never finishes or "
            "cannot be cancelled leaves the client waiting on work it cannot track."
        ),
        remediation=(
            "Store the task before returning CreateTaskResult, move it to a terminal status, "
            "acknowledge tasks/cancel, and answer an unknown taskId with a JSON-RPC error."
        ),
    )

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        run = _Run(self, ctx)
        try:
            found = await self._find_task_call(ctx, run)
            if found is None:
                return CheckOutcome.na("no tool returned a task when the extension was declared")
            tool, params, task = found
            await self._lifecycle(ctx, run, tool, params, task)
            await self._cancel(ctx, run, tool, params)
            await self._unknown(ctx, run)
        except RequestTimeout:
            return CheckOutcome.error("the server did not answer a tasks request in time")
        return CheckOutcome(run.findings)

    @staticmethod
    def _candidates(ctx: ScanContext) -> list[ToolInfo]:
        tools = ctx.callable_tools()
        likely = [t for t in tools if _LIKELY.search(t.name)]
        rest = [t for t in tools if t not in likely]
        return [*likely, *rest][:_TOOLS_TRIED]

    async def _find_task_call(
        self, ctx: ScanContext, run: _Run
    ) -> tuple[ToolInfo, dict[str, Any], Task] | None:
        book = await campaign(ctx)
        for tool in self._candidates(ctx):
            plan = book.plan_for(tool.name)
            args: Any = next((c.arguments for c in (plan.valid if plan else []) if c.arguments), {})
            params: dict[str, Any] = {
                "name": tool.name,
                "arguments": args if isinstance(args, dict) else {},
            }
            response = await run.send("tools/call", params)
            if not is_task_result(response):
                continue
            task = task_from(response, expect_type="task")
            if task is None:
                run.fail("created", "A task result has no taskId", "resultType is task, no taskId")
                return None
            if task.problems:
                run.fail(
                    "created",
                    f"{tool.name} returned a malformed task",
                    "; ".join(task.problems),
                    tool.name,
                )
            await self._without_extension(ctx, run, tool, params)
            return tool, params, task
        return None

    async def _without_extension(
        self, ctx: ScanContext, run: _Run, tool: ToolInfo, params: dict[str, Any]
    ) -> None:
        """A server must not create a task for a client that did not declare the extension."""
        run.steps.append(
            {"kind": "request", "method": "tools/call", "params": params, "note": "no extension"}
        )
        response = await ctx.request("tools/call", params, case_id="tasks:no-extension")
        if is_task_result(response):
            run.fail(
                "undeclared",
                f"{tool.name} returned a task to a client that did not ask for tasks",
                "resultType task without the io.modelcontextprotocol/tasks capability",
                tool.name,
            )

    async def _lifecycle(
        self, ctx: ScanContext, run: _Run, tool: ToolInfo, params: dict[str, Any], task: Task
    ) -> None:
        right_away = await get_task(run.send, task.task_id)
        if isinstance(right_away, ErrorResponse):
            run.fail(
                "durable",
                "A new task could not be found right after creation",
                f"tasks/get answered error {right_away.error.code} for the task just created: "
                f"{right_away.error.message}",
                tool.name,
            )
            return
        shape = task_from(right_away, expect_type="complete")
        if shape is not None and shape.problems:
            run.fail(
                "get-shape",
                "tasks/get returned a malformed task",
                "; ".join(shape.problems),
                tool.name,
            )
        scale = ctx.config.timeout_scale
        deadline = min(request_timeout(ctx.config.mode, scale) * 4, 30.0 * scale)
        polled = await wait_for_terminal(
            run.send, shape or task, deadline_s=deadline, policy=input_policy(ctx)
        )
        if polled.timed_out:
            run.fail(
                "terminal",
                "A task never reached a terminal status",
                f"still not finished after {deadline:.0f} s",
                tool.name,
            )
        elif (
            polled.task is None
            or polled.last is None
            or not isinstance(polled.last, ResultResponse)
        ):
            run.fail(
                "terminal", "Polling a task failed", "tasks/get did not return a task", tool.name
            )
        elif polled.task.problems:
            run.fail(
                "terminal-shape",
                "The finished task is malformed",
                "; ".join(polled.task.problems),
                tool.name,
            )

    async def _cancel(
        self, ctx: ScanContext, run: _Run, tool: ToolInfo, params: dict[str, Any]
    ) -> None:
        response = await run.send("tools/call", params)
        second = task_from(response, expect_type="task")
        if second is None:
            return  # the server chose not to make a task this time
        ack = await cancel_task(run.send, second.task_id)
        if isinstance(ack, ErrorResponse):
            run.fail(
                "cancel",
                "tasks/cancel was refused",
                f"error {ack.error.code}: {ack.error.message}",
                tool.name,
            )
            return
        polled = await wait_for_terminal(
            run.send, second, deadline_s=_SETTLE_S * ctx.config.timeout_scale
        )
        if polled.task is not None and polled.task.problems:
            run.fail(
                "cancel-shape",
                "A cancelled task is malformed",
                "; ".join(polled.task.problems),
                tool.name,
            )

    async def _unknown(self, ctx: ScanContext, run: _Run) -> None:
        missing = f"probe-unknown-{ctx.fixtures.token if ctx.fixtures else 'task'}"
        response = await get_task(run.send, missing)
        if isinstance(response, ResultResponse):
            run.fail(
                "unknown",
                "tasks/get answered for a task id that does not exist",
                f"result for {missing!r} instead of an error",
            )
