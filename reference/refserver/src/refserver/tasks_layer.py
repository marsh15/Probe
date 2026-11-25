"""The Tasks extension (`io.modelcontextprotocol/tasks`), served in front of the SDK.

The SDK has no Tasks support, so the front proxy (stdio) and middleware (HTTP) answer these
requests themselves, using the pure functions here:

* `tools/call long_export` from a client that declared the extension becomes a task;
* `tasks/get`, `tasks/update` and `tasks/cancel` work on the in-memory `TaskTable`;
* `advertise` adds the extension to the `server/discover` capabilities.

A task's status is computed from the clock, so no background thread is needed and a test can
predict it: `working` for `WORK_SECONDS`, then `completed` (or `cancelled` if cancelled first).
A client that did not declare the extension gets the plain synchronous tool from the SDK.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import time
import uuid
from collections.abc import Callable
from typing import Any

EXTENSION_ID = "io.modelcontextprotocol/tasks"
CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities"
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"
EXPORT_TOOL = "long_export"
WORK_SECONDS = 1.0
TTL_MS = 60_000
POLL_INTERVAL_MS = 200
# A task is visible only to the identity that created it (None: unauthenticated or stdio), and an
# identity keeps at most this many; the oldest are dropped first.
MAX_TASKS_PER_OWNER = 100
TASK_METHODS = ("tasks/get", "tasks/update", "tasks/cancel")
# b30: the task is stored this long after CreateTaskResult has been returned.
LATE_STORE_SECONDS = 0.2


def export_result(items: list[int]) -> dict[str, Any]:
    """The tool result of an export; the same for the synchronous tool and a finished task."""
    text = json.dumps({"exported": len(items), "items": items})
    return {"content": [{"type": "text", "text": text}], "isError": False}


def valid_items(value: Any) -> bool:
    return (
        isinstance(value, list)
        and 1 <= len(value) <= 1000
        and all(isinstance(i, int) and not isinstance(i, bool) and i >= 1 for i in value)
    )


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Task:
    def __init__(
        self, items: list[int], now: float, wall: float, store_at: float, owner: str | None
    ) -> None:
        self.id = str(uuid.uuid4())
        self.owner = owner
        self.items = items
        self.created = now
        self.created_wall = wall
        self.store_at = store_at  # not visible to tasks/get before this moment
        self.cancelled_at: float | None = None


class TaskTable:
    def __init__(
        self,
        *,
        late_store: bool = False,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self._tasks: dict[str, _Task] = {}
        self._late_store = late_store
        self._clock, self._wall = clock, wall

    def _expire(self, now: float) -> None:
        """Drop tasks past their advertised ttlMs."""
        for task_id in [t.id for t in self._tasks.values() if now - t.created >= TTL_MS / 1000]:
            del self._tasks[task_id]

    def _find(self, task_id: str, owner: str | None, now: float) -> _Task | None:
        self._expire(now)
        task = self._tasks.get(task_id)
        if task is None or task.owner != owner or now < task.store_at:
            return None
        return task

    def create(self, items: list[int], owner: str | None = None) -> dict[str, Any]:
        now = self._clock()
        self._expire(now)
        task = _Task(
            items,
            now,
            self._wall(),
            now + (LATE_STORE_SECONDS if self._late_store else 0.0),
            owner,
        )
        self._tasks[task.id] = task
        mine = [t.id for t in self._tasks.values() if t.owner == owner]  # oldest first
        for task_id in mine[: max(0, len(mine) - MAX_TASKS_PER_OWNER)]:
            del self._tasks[task_id]
        return self._view(task, now)

    def get(self, task_id: str, owner: str | None = None) -> dict[str, Any] | None:
        now = self._clock()
        task = self._find(task_id, owner, now)
        if task is None:
            return None
        view = self._view(task, now)
        if view["status"] == "completed":
            view["result"] = export_result(task.items)
        return view

    def cancel(self, task_id: str, owner: str | None = None) -> bool:
        now = self._clock()
        task = self._find(task_id, owner, now)
        if task is None:
            return False
        if task.cancelled_at is None and now - task.created < WORK_SECONDS:
            task.cancelled_at = now
        return True

    def _view(self, task: _Task, now: float) -> dict[str, Any]:
        if task.cancelled_at is not None:
            status, updated = "cancelled", task.cancelled_at
        elif now - task.created >= WORK_SECONDS:
            status, updated = "completed", task.created + WORK_SECONDS
        else:
            status, updated = "working", task.created
        offset = self._wall() - now
        return {
            "taskId": task.id,
            "status": status,
            "createdAt": _iso(task.created_wall),
            "lastUpdatedAt": _iso(updated + offset),
            "ttlMs": TTL_MS,
            "pollIntervalMs": POLL_INTERVAL_MS,
        }


def _reply(request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def _error(request: dict[str, Any], code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": code, "message": message}}


def _declares_extension(params: dict[str, Any]) -> bool:
    meta = params.get("_meta")
    caps = meta.get(CAPABILITIES_META) if isinstance(meta, dict) else None
    extensions = caps.get("extensions") if isinstance(caps, dict) else None
    return isinstance(extensions, dict) and EXTENSION_ID in extensions


class TasksLayer:
    def __init__(self, active: frozenset[str]) -> None:
        self.table = TaskTable(late_store="b30" in active)

    def answer(self, message: Any, owner: str | None = None) -> dict[str, Any] | None:
        """The reply to a client request this layer owns, or None to pass it to the SDK.

        ``owner`` is the authenticated identity; a task is visible only to the one that made it.
        """
        if not isinstance(message, dict) or "id" not in message:
            return None
        method, params = message.get("method"), message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
            return None  # not a modern request
        if PROTOCOL_VERSION_META not in params["_meta"]:
            return None
        if method == "tools/call":
            return self._create(message, params, owner)
        if method in TASK_METHODS:
            return self._task_method(message, str(method), params, owner)
        return None

    def _create(
        self, message: dict[str, Any], params: dict[str, Any], owner: str | None
    ) -> dict[str, Any] | None:
        if params.get("name") != EXPORT_TOOL or not _declares_extension(params):
            return None
        arguments = params.get("arguments")
        items = arguments.get("items") if isinstance(arguments, dict) else None
        if not valid_items(items):
            return _error(message, -32602, "Invalid params: items must be 1-1000 note ids")
        return _reply(message, {"resultType": "task", **self.table.create(items, owner)})

    def _task_method(
        self, message: dict[str, Any], method: str, params: dict[str, Any], owner: str | None
    ) -> dict[str, Any]:
        task_id = params.get("taskId")
        if not isinstance(task_id, str):
            return _error(message, -32602, "Invalid params: taskId is required")
        if method == "tasks/get":
            view = self.table.get(task_id, owner)
            if view is None:
                return _error(message, -32602, f"Unknown task: {task_id}")
            return _reply(message, {"resultType": "complete", **view})
        known = (
            self.table.cancel(task_id, owner)
            if method == "tasks/cancel"
            else (self.table.get(task_id, owner) is not None)
        )
        if not known:
            return _error(message, -32602, f"Unknown task: {task_id}")
        return _reply(message, {"resultType": "complete"})

    @staticmethod
    def advertise(method: str | None, message: dict[str, Any]) -> dict[str, Any]:
        """The ``server/discover`` reply with the extension added to the capabilities."""
        result = message.get("result")
        if method != "server/discover" or not isinstance(result, dict):
            return message
        out = copy.deepcopy(message)
        capabilities = out["result"].setdefault("capabilities", {})
        if isinstance(capabilities, dict):
            extensions = capabilities.setdefault("extensions", {})
            if isinstance(extensions, dict):
                extensions[EXTENSION_ID] = {}
        return out
