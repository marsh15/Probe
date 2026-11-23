"""The transport contract shared by stdio and HTTP, plus the bookkeeping both need.

A concrete transport only moves bytes: it implements ``send``, ``close``, ``alive`` and
``stderr_tail``, and hands every incoming line or body to ``_receive``. Correlation, timeouts,
notifications, server-to-client requests, events and recording live here.
"""

import asyncio
import contextlib
import sys
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, ClassVar

from probe.wire.errors import (
    JsonRpcError,
    ProtocolViolation,
    RequestId,
    RequestTimeout,
    TransportClosed,
    UnmatchedResponse,
    WireEvent,
)
from probe.wire.jsonrpc import (
    INTERNAL_ERROR,
    METHOD_NOT_FOUND,
    ErrorObject,
    ErrorResponse,
    Notification,
    ParsedLine,
    Request,
    Response,
    ResultResponse,
    classify,
    encode,
)
from probe.wire.limits import (
    EVENT_EXCERPT_BYTES,
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    MAX_NOTIFICATION_BYTES,
    MAX_QUEUED_NOTIFICATIONS,
    MAX_REQUEST_IDS,
    MAX_SERVER_REQUEST_BYTES,
    MAX_SERVER_REQUESTS,
    MAX_TIMEOUT_HISTORY,
)
from probe.wire.recorder import Direction, HttpMeta, Recorder

# Returns the JSON-RPC result; raise JsonRpcError to answer with an error instead.
ServerRequestHandler = Callable[[Request], Awaitable[Any]]


def _retained_size(value: Any) -> int:
    """Conservatively count decoded objects; short JSON can expand to many Python objects."""
    total = 0
    stack: list[Iterator[Any]] = [iter((value,))]
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        total += sys.getsizeof(item)
        if isinstance(item, dict):
            total += sum(sys.getsizeof(key) for key in item)
            stack.append(iter(item.values()))
        elif isinstance(item, list):
            stack.append(iter(item))
    return total


@dataclass(frozen=True, slots=True)
class CloseResult:
    exit_code: int | None
    terminated: bool = False  # SIGTERM was needed
    killed: bool = False  # SIGKILL was needed (operability.clean_shutdown)


class Transport(ABC):
    name: ClassVar[str]

    def __init__(self, *, recorder: Recorder | None = None) -> None:
        self.recorder = recorder
        self._redact_text = recorder.redact_text if recorder is not None else lambda text: text
        self._pending: dict[RequestId, asyncio.Future[Response]] = {}
        self._used_ids: set[bytes] = set()
        self._timed_out: OrderedDict[bytes, None] = OrderedDict()
        self._notifications: asyncio.Queue[tuple[Notification, int] | None] = asyncio.Queue()
        self._notification_bytes = 0
        self._event_bytes = 0
        self._handler_bytes = 0
        self._events: list[WireEvent] = []
        self._handler: ServerRequestHandler | None = None
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self._closed: TransportClosed | None = None
        self.events_dropped = 0
        self.notifications_dropped = 0
        self.recording_error: str | None = None

    @abstractmethod
    async def send(self, obj: Mapping[str, Any]) -> None:
        """Send one message as-is (no validation) and record it."""

    @abstractmethod
    async def close(self) -> CloseResult:
        """Shut the transport down; idempotent."""

    @abstractmethod
    def alive(self) -> bool: ...

    @abstractmethod
    def stderr_tail(self, n: int = 4096) -> str:
        """The last ``n`` bytes of server stderr, decoded and sanitized for display."""

    # The per-request timeout is part of the contract (it is recorded on RequestTimeout).
    async def request(self, obj: Mapping[str, Any], timeout: float) -> Response:  # noqa: ASYNC109
        """Send a request and wait for the response with the same id.

        On timeout nothing else is sent; a response that arrives later is recorded and dropped.
        """
        request = classify(dict(obj))
        if not isinstance(request, Request):
            raise ValueError("request() needs a JSON-RPC request with an id")
        if self._closed is not None:
            raise TransportClosed(self._closed.exit_code, self._closed.reason)
        if request.id in self._pending:
            raise ValueError(f"request id {request.id!r} is already pending")
        fingerprint = self._id_key(request.id)
        if fingerprint in self._used_ids:
            raise ValueError("request id was already used on this transport")
        if len(self._used_ids) >= MAX_REQUEST_IDS:
            raise ValueError("request id budget exhausted; start a new transport")
        self._used_ids.add(fingerprint)
        future: asyncio.Future[Response] = asyncio.get_running_loop().create_future()
        self._pending[request.id] = future
        try:
            async with asyncio.timeout(timeout):
                await self.send(obj)
                return await future
        except TimeoutError:
            self._timed_out[fingerprint] = None
            if len(self._timed_out) > MAX_TIMEOUT_HISTORY:
                self._timed_out.popitem(last=False)
            raise RequestTimeout(request.id, timeout) from None
        finally:
            self._pending.pop(request.id, None)

    async def notifications(self) -> AsyncIterator[Notification]:
        """Server notifications in arrival order; ends when the transport closes."""
        while True:
            item = await self._notifications.get()
            if item is None:
                self._notifications.put_nowait(None)  # so every other iterator ends too
                return
            notification, size = item
            self._notification_bytes -= size
            yield notification

    def on_server_request(self, handler: ServerRequestHandler | None) -> None:
        """Route server-to-client requests to ``handler``; without one they get -32601."""
        self._handler = handler

    def events(self) -> list[WireEvent]:
        return list(self._events)

    def report_violation(self, rule: str, detail: str) -> None:
        """Let higher layers (session, era logic) add a violation to the event stream."""
        self._emit(ProtocolViolation(rule=rule, detail=detail))

    def _record(self, direction: Direction, body: Any, http: HttpMeta | None = None) -> None:
        if self.recorder is not None:
            try:
                self.recorder.record(direction, self.name, body, http=http)
            except (OSError, ValueError, RuntimeError, TypeError) as exc:
                self._recording_failed(exc)

    def _recording_failed(self, exc: Exception) -> None:
        # Retain explicit evidence, but never let an optional trace sink kill the reader.
        self.recording_error = type(exc).__name__
        self.recorder = None
        self._emit(ProtocolViolation(rule="trace_write_failed", detail=type(exc).__name__))

    @staticmethod
    def _id_key(request_id: RequestId) -> bytes:
        return sha256(encode(request_id)).digest()

    def _emit(self, event: WireEvent) -> None:
        fields = event.model_dump()
        for name, value in fields.items():
            if isinstance(value, str):
                value = self._redact_text(value)
                fields[name] = value.encode("utf-8", "backslashreplace")[
                    :EVENT_EXCERPT_BYTES
                ].decode("utf-8", "ignore")
        event = event.model_copy(update=fields)
        size = len(encode(fields))
        if len(self._events) < MAX_EVENTS and self._event_bytes + size <= MAX_EVENT_BYTES:
            self._events.append(event)
            self._event_bytes += size
        else:
            self.events_dropped += 1
        self._record("event", fields)

    def _receive(self, parsed: ParsedLine, http: HttpMeta | None = None) -> None:
        if parsed.is_json:
            self._record("s2c", parsed.value, http)
        if parsed.event is not None:
            self._emit(parsed.event)
        message = parsed.message
        if isinstance(message, ResultResponse | ErrorResponse):
            self._resolve(message)
        elif isinstance(message, Notification):
            size = _retained_size(message.to_obj())
            if size > MAX_NOTIFICATION_BYTES:
                self.notifications_dropped += 1
                return
            while (
                self._notifications.qsize() >= MAX_QUEUED_NOTIFICATIONS
                or self._notification_bytes + size > MAX_NOTIFICATION_BYTES
            ):
                old = self._notifications.get_nowait()
                if old is not None:
                    self._notification_bytes -= old[1]
                self.notifications_dropped += 1
            self._notifications.put_nowait((message, size))
            self._notification_bytes += size
        elif isinstance(message, Request):
            size = _retained_size(message.to_obj())
            if (
                len(self._handler_tasks) >= MAX_SERVER_REQUESTS
                or self._handler_bytes + size > MAX_SERVER_REQUEST_BYTES
            ):
                self._emit(
                    ProtocolViolation(
                        rule="server_request_limit",
                        detail="server request dropped: budget exceeded",
                    )
                )
                return
            task = asyncio.create_task(self._answer(message))
            self._handler_bytes += size
            self._handler_tasks.add(task)

            def finished(task: asyncio.Task[None]) -> None:
                self._handler_tasks.discard(task)
                self._handler_bytes -= size
                if not task.cancelled() and task.exception() is not None:
                    self.report_violation("client_handler_failed", "server reply task failed")

            task.add_done_callback(finished)

    def _resolve(self, response: Response) -> None:
        late = False
        if response.id is not None:
            future = self._pending.get(response.id)
            if future is not None and not future.done():
                future.set_result(response)
                return
            fingerprint = self._id_key(response.id)
            late = fingerprint in self._timed_out
            self._timed_out.pop(fingerprint, None)
        self._emit(UnmatchedResponse(id=response.id, late=late))

    async def _answer(self, request: Request) -> None:
        reply: Response
        if self._handler is None:
            reply = ErrorResponse(request.id, ErrorObject(METHOD_NOT_FOUND, "Method not found"))
        else:
            try:
                reply = ResultResponse(request.id, await self._handler(request))
            except JsonRpcError as exc:
                reply = ErrorResponse(request.id, ErrorObject(exc.code, exc.message, exc.data))
            except Exception as exc:
                error = ErrorObject(INTERNAL_ERROR, f"client handler failed: {type(exc).__name__}")
                reply = ErrorResponse(request.id, error)
        try:
            encode(reply.to_obj())
        except (TypeError, ValueError, RecursionError):
            self.report_violation(
                "client_handler_result", "handler reply was not JSON serializable"
            )
            reply = ErrorResponse(request.id, ErrorObject(INTERNAL_ERROR, "Invalid client reply"))
        with contextlib.suppress(TransportClosed):
            await self.send(reply.to_obj())

    def _mark_closed(self, error: TransportClosed) -> None:
        """Fail every pending request with ``error`` and end the notification stream."""
        if self._closed is not None:
            return
        self._closed = error
        for future in self._pending.values():
            if not future.done():
                future.set_exception(TransportClosed(error.exit_code, error.reason))
        self._notifications.put_nowait(None)
        for task in self._handler_tasks:
            task.cancel()
