"""The Tasks extension: start a call, follow the task, cancel it.

The server decides whether a ``tools/call`` becomes a task (``resultType: "task"``); the client
only declares the extension. Helpers here parse the task shapes, note what is malformed, and
poll ``tasks/get`` politely. They work through a ``Sender`` so a check can route the requests
through its budget and crash handling.
"""

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse
from probe.wire.mrtr import InputPolicy, Sender

EXTENSION_ID = "io.modelcontextprotocol/tasks"
CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities"
STATUSES = ("working", "input_required", "completed", "failed", "cancelled")
TERMINAL = frozenset({"completed", "failed", "cancelled"})
MIN_POLL_S, MAX_POLL_S = 0.1, 5.0
DEFAULT_POLL_S = 0.5


def with_tasks_capability(capabilities: Mapping[str, Any]) -> dict[str, Any]:
    """Client capabilities that also declare the Tasks extension."""
    merged = dict(capabilities)
    existing = merged.get("extensions")
    extensions = dict(existing) if isinstance(existing, dict) else {}
    merged["extensions"] = {**extensions, EXTENSION_ID: {}}
    return merged


@dataclass(slots=True)
class Task:
    task_id: str
    status: str
    ttl_ms: Any = None
    poll_interval_ms: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL

    @property
    def poll_seconds(self) -> float:
        if self.poll_interval_ms is None:
            return DEFAULT_POLL_S
        return min(max(self.poll_interval_ms / 1000, MIN_POLL_S), MAX_POLL_S)


def parse_task(result: Any, *, expect_type: str | None = None) -> Task | None:
    """A ``Task`` from a result object, or None when there is no task id at all.

    ``problems`` lists what breaks the shape (missing or bad fields); the caller decides how
    much weight each deserves.
    """
    if not isinstance(result, dict):
        return None
    task_id = result.get("taskId")
    if not isinstance(task_id, str) or not task_id:
        return None
    problems: list[str] = []
    status = result.get("status")
    if status not in STATUSES:
        problems.append(f"status {status!r} is not one of {', '.join(STATUSES)}")
    if expect_type is not None and result.get("resultType") != expect_type:
        problems.append(f"resultType is {result.get('resultType')!r}, not {expect_type!r}")
    if "ttlMs" not in result:
        problems.append("ttlMs is missing")
    elif result["ttlMs"] is not None and not _is_count(result["ttlMs"]):
        problems.append("ttlMs is neither null nor a non-negative integer")
    poll = result.get("pollIntervalMs")
    if poll is not None and not _is_count(poll):
        problems.append("pollIntervalMs is not a non-negative integer")
    for name in ("createdAt", "lastUpdatedAt"):
        if not isinstance(result.get(name), str):
            problems.append(f"{name} is missing")
    if status == "completed" and not isinstance(result.get("result"), dict):
        problems.append("a completed task has no result")
    if status == "failed" and not isinstance(result.get("error"), dict):
        problems.append("a failed task has no error")
    if status == "input_required" and not isinstance(result.get("inputRequests"), dict):
        problems.append("an input_required task has no inputRequests")
    return Task(
        task_id,
        str(status),
        result.get("ttlMs"),
        poll if _is_count(poll) else None,
        dict(result),
        problems,
    )


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def result_of(response: Response | None) -> dict[str, Any] | None:
    if isinstance(response, ResultResponse) and isinstance(response.result, dict):
        return response.result
    return None


def task_from(response: Response | None, *, expect_type: str | None = None) -> Task | None:
    return parse_task(result_of(response), expect_type=expect_type)


def is_task_result(response: Response | None) -> bool:
    result = result_of(response)
    return result is not None and result.get("resultType") == "task"


async def get_task(send: Sender, task_id: str) -> Response:
    return await send("tasks/get", {"taskId": task_id})


async def cancel_task(send: Sender, task_id: str) -> Response:
    return await send("tasks/cancel", {"taskId": task_id})


async def update_task(send: Sender, task_id: str, responses: Mapping[str, Any]) -> Response:
    return await send("tasks/update", {"taskId": task_id, "inputResponses": dict(responses)})


@dataclass(slots=True)
class Polled:
    last: Response | None
    task: Task | None
    polls: int
    timed_out: bool = False


async def wait_for_terminal(
    send: Sender,
    task: Task,
    *,
    deadline_s: float,
    policy: InputPolicy | None = None,
) -> Polled:
    """Poll ``tasks/get`` until a terminal status, answering ``input_required`` along the way."""
    loop = asyncio.get_running_loop()
    stop = loop.time() + deadline_s
    polled = Polled(None, task, 0)
    answered: set[str] = set()
    while True:
        response = await get_task(send, task.task_id)
        polled.last, polled.polls = response, polled.polls + 1
        current = task_from(response)
        if current is None:
            return polled
        polled.task = task = current
        if current.terminal:
            return polled
        if current.status == "input_required" and policy is not None:
            requests = current.raw.get("inputRequests")
            fresh = {
                k: policy.answer(k, v)
                for k, v in (requests.items() if isinstance(requests, dict) else ())
                if k not in answered and isinstance(v, dict)
            }
            if fresh:
                answered.update(fresh)
                await update_task(send, task.task_id, fresh)
        if loop.time() + current.poll_seconds > stop:
            polled.timed_out = True
            return polled
        await asyncio.sleep(current.poll_seconds)


def error_code(response: Response | None) -> int | None:
    return response.error.code if isinstance(response, ErrorResponse) else None
