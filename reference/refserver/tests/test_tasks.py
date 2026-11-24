"""The Tasks extension layer: the table's clock-driven states, and the requests it answers."""

from __future__ import annotations

from typing import Any

from refserver.tasks_layer import (
    CAPABILITIES_META,
    EXTENSION_ID,
    PROTOCOL_VERSION_META,
    WORK_SECONDS,
    TasksLayer,
    TaskTable,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def table(clock: Clock, *, late: bool = False) -> TaskTable:
    return TaskTable(late_store=late, clock=clock, wall=clock)


def test_a_task_works_then_completes_with_the_export() -> None:
    clock = Clock()
    tasks = table(clock)
    created = tasks.create([1, 2])
    assert created["status"] == "working" and created["ttlMs"] > 0
    first = tasks.get(created["taskId"])
    assert first is not None and first["status"] == "working" and "result" not in first
    clock.now += WORK_SECONDS
    done = tasks.get(created["taskId"])
    assert done is not None and done["status"] == "completed"
    assert done["result"]["isError"] is False
    assert '"exported": 2' in done["result"]["content"][0]["text"]


def test_cancelling_a_working_task_ends_it_cancelled() -> None:
    clock = Clock()
    tasks = table(clock)
    created = tasks.create([1])
    assert tasks.cancel(created["taskId"])
    clock.now += WORK_SECONDS * 2
    view = tasks.get(created["taskId"])
    assert view is not None and view["status"] == "cancelled"


def test_cancelling_a_finished_task_leaves_it_completed() -> None:
    clock = Clock()
    tasks = table(clock)
    created = tasks.create([1])
    clock.now += WORK_SECONDS
    assert tasks.cancel(created["taskId"])
    view = tasks.get(created["taskId"])
    assert view is not None and view["status"] == "completed"


def test_unknown_tasks_are_not_found() -> None:
    tasks = table(Clock())
    assert tasks.get("nope") is None
    assert not tasks.cancel("nope")


def test_a_late_stored_task_cannot_be_found_at_first() -> None:
    clock = Clock()
    tasks = table(clock, late=True)
    created = tasks.create([1])
    assert tasks.get(created["taskId"]) is None
    clock.now += 0.3
    assert tasks.get(created["taskId"]) is not None


def request(method: str, params: dict[str, Any], *, tasks: bool = True) -> dict[str, Any]:
    capabilities = {"extensions": {EXTENSION_ID: {}}} if tasks else {}
    meta = {PROTOCOL_VERSION_META: "2026-07-28", CAPABILITIES_META: capabilities}
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": {**params, "_meta": meta}}


def export_call(*, tasks: bool = True, items: Any = (1, 2)) -> dict[str, Any]:
    arguments = {"items": list(items) if isinstance(items, tuple) else items}
    return request("tools/call", {"name": "long_export", "arguments": arguments}, tasks=tasks)


def test_a_declaring_client_gets_a_task_and_can_follow_it() -> None:
    layer = TasksLayer(frozenset())
    created = layer.answer(export_call())
    assert created is not None and created["id"] == 7
    assert created["result"]["resultType"] == "task"
    task_id = created["result"]["taskId"]
    got = layer.answer(request("tasks/get", {"taskId": task_id}))
    assert got is not None and got["result"]["resultType"] == "complete"
    assert got["result"]["status"] == "working"
    ack = layer.answer(request("tasks/cancel", {"taskId": task_id}))
    assert ack is not None and ack["result"] == {"resultType": "complete"}


def test_a_client_that_did_not_declare_the_extension_is_left_to_the_sdk() -> None:
    assert TasksLayer(frozenset()).answer(export_call(tasks=False)) is None


def test_other_tools_and_legacy_requests_are_left_to_the_sdk() -> None:
    layer = TasksLayer(frozenset())
    assert layer.answer(request("tools/call", {"name": "notes_get", "arguments": {}})) is None
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"taskId": "x"}}
    assert layer.answer(legacy) is None
    assert layer.answer({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_bad_export_arguments_and_unknown_tasks_are_invalid_params() -> None:
    layer = TasksLayer(frozenset())
    bad = layer.answer(export_call(items=[0]))
    assert bad is not None and bad["error"]["code"] == -32602
    for method in ("tasks/get", "tasks/update", "tasks/cancel"):
        reply = layer.answer(request(method, {"taskId": "missing"}))
        assert reply is not None and reply["error"]["code"] == -32602


def test_discover_gets_the_extension_added() -> None:
    reply = {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {"tools": {}}}}
    out = TasksLayer.advertise("server/discover", reply)
    assert out["result"]["capabilities"]["extensions"] == {EXTENSION_ID: {}}
    assert "extensions" not in reply["result"]["capabilities"]  # the original is untouched
    assert TasksLayer.advertise("tools/list", reply) is reply
