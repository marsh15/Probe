"""Task parsing and polling against a scripted sender."""

from typing import Any

from probe.wire.jsonrpc import ErrorObject, ErrorResponse, Response, ResultResponse
from probe.wire.mrtr import InputPolicy
from probe.wire.tasks import (
    EXTENSION_ID,
    parse_task,
    wait_for_terminal,
    with_tasks_capability,
)


def task(status: str = "working", **extra: Any) -> dict[str, Any]:
    base = {
        "resultType": "complete",
        "taskId": "t1",
        "status": status,
        "createdAt": "2026-07-28T00:00:00Z",
        "lastUpdatedAt": "2026-07-28T00:00:00Z",
        "ttlMs": 60000,
        "pollIntervalMs": 100,
    }
    return {**base, **extra}


class Script:
    def __init__(self, *replies: Response) -> None:
        self.replies = list(replies)
        self.sent: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, method: str, params: dict[str, Any]) -> Response:
        self.sent.append((method, params))
        return self.replies.pop(0)


def test_the_extension_is_added_to_existing_capabilities() -> None:
    merged = with_tasks_capability({"elicitation": {}, "extensions": {"x": {}}})
    assert merged["elicitation"] == {}
    assert set(merged["extensions"]) == {"x", EXTENSION_ID}


def test_a_well_formed_task_has_no_problems() -> None:
    parsed = parse_task({**task(), "resultType": "task"}, expect_type="task")
    assert parsed is not None and parsed.problems == [] and not parsed.terminal


def test_missing_fields_are_listed() -> None:
    parsed = parse_task({"taskId": "t", "status": "bogus"})
    assert parsed is not None
    joined = " ".join(parsed.problems)
    assert "bogus" in joined and "ttlMs" in joined and "createdAt" in joined


def test_terminal_states_need_their_payload() -> None:
    done = parse_task(task("completed"))
    failed = parse_task(task("failed"))
    assert done is not None and any("no result" in p for p in done.problems)
    assert failed is not None and any("no error" in p for p in failed.problems)


def test_no_task_id_means_no_task() -> None:
    assert parse_task({"status": "working"}) is None
    assert parse_task("nope") is None


def test_poll_interval_is_clamped() -> None:
    fast = parse_task(task(pollIntervalMs=1))
    slow = parse_task(task(pollIntervalMs=600_000))
    assert fast is not None and fast.poll_seconds == 0.1
    assert slow is not None and slow.poll_seconds == 5.0


async def test_polling_runs_until_terminal() -> None:
    first = parse_task(task())
    assert first is not None
    send = Script(
        ResultResponse(1, task()),
        ResultResponse(2, task("completed", result={"content": []})),
    )
    polled = await wait_for_terminal(send, first, deadline_s=5)
    assert polled.task is not None and polled.task.status == "completed"
    assert polled.polls == 2 and not polled.timed_out


async def test_polling_gives_up_at_the_deadline() -> None:
    first = parse_task(task())
    assert first is not None
    send = Script(*(ResultResponse(i, task()) for i in range(50)))
    polled = await wait_for_terminal(send, first, deadline_s=0.25)
    assert polled.timed_out


async def test_input_required_is_answered_once() -> None:
    first = parse_task(task())
    assert first is not None
    ask = task(
        "input_required",
        inputRequests={"k": {"method": "roots/list"}},
    )
    send = Script(
        ResultResponse(1, ask),
        ResultResponse(2, {"resultType": "complete"}),
        ResultResponse(3, ask),
        ResultResponse(4, task("completed", result={})),
    )
    polled = await wait_for_terminal(send, first, deadline_s=5, policy=InputPolicy())
    methods = [m for m, _ in send.sent]
    assert methods.count("tasks/update") == 1
    assert polled.task is not None and polled.task.terminal


async def test_an_error_while_polling_stops_it() -> None:
    first = parse_task(task())
    assert first is not None
    send = Script(ErrorResponse(1, ErrorObject(-32602, "unknown task")))
    polled = await wait_for_terminal(send, first, deadline_s=5)
    assert polled.task is first and polled.polls == 1
