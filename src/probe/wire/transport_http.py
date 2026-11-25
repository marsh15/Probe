"""MCP streamable HTTP: every client message is a POST; the reply is JSON or an SSE stream.

One ``httpx`` client per transport, HTTP/1.1, no redirects, no proxy settings from the
environment, and response bodies are read raw: a server's ``Content-Encoding`` is never
decoded, so a compression bomb is just bytes that hit the size limit.
"""

import asyncio
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from probe.wire.errors import (
    MalformedMessage,
    OversizeMessage,
    RequestId,
    StdoutNoise,
    TransportClosed,
    WireError,
)
from probe.wire.jsonrpc import (
    ErrorResponse,
    ParsedLine,
    Response,
    ResultResponse,
    encode,
    parse_line,
)
from probe.wire.limits import (
    HTTP_CONNECT_TIMEOUT_S,
    HTTP_SEND_TIMEOUT_S,
    MAX_MESSAGE_BYTES,
    MAX_STREAM_BYTES,
    MAX_STREAM_EVENTS,
    TRACE_BODY_MAX_BYTES,
)
from probe.wire.recorder import HttpMeta, Recorder
from probe.wire.sse import SseEvent, SseParser
from probe.wire.transport_base import CloseResult, Transport

_SESSION_ID = re.compile(r"[\x21-\x7e]{1,512}")
_CLOSE_WAIT_S = 2.0


@dataclass(frozen=True, slots=True)
class RawHttpResult:
    """Everything observable about one HTTP exchange, including failed ones."""

    status: int | None  # None when no HTTP response arrived (see ``error``)
    headers: Mapping[str, str]  # lower-cased names
    content_type: str  # media type only, lower-cased; "" when absent
    body: bytes  # up to 64 KiB of the body, with configured secrets redacted in plain bodies
    body_length: int  # raw bytes read before the exchange ended
    responses: tuple[Response, ...]  # JSON-RPC responses that arrived, in order
    elapsed_ms: float
    aborted: str | None = None  # why Probe cut the response short (size or event limit)
    error: str | None = None  # connection-level failure: an exception name or "timeout"


class HttpRequestFailed(WireError):
    """The POST produced no response to the request (HTTP failure, abort or missing reply)."""

    def __init__(self, status: int | None, reason: str, result: RawHttpResult) -> None:
        super().__init__(f"HTTP request failed: {reason} (status {status})")
        self.status = status
        self.reason = reason
        self.result = result


def _merge(*groups: Mapping[str, str]) -> dict[str, str]:
    """Merge header groups case-insensitively; later groups win."""
    merged: dict[str, tuple[str, str]] = {}
    for group in groups:
        for name, value in group.items():
            merged[name.lower()] = (name, value)
    return dict(merged.values())


class _Exchange:
    """Mutable state of one exchange while its response streams in."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.content_type = ""
        self.body = bytearray()
        self.body_length = 0
        self.responses: list[Response] = []
        self.aborted: str | None = None
        self.error: str | None = None


class HttpTransport(Transport):
    name = "http"

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        recorder: Recorder | None = None,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
        max_stream_bytes: int = MAX_STREAM_BYTES,
        max_stream_events: int = MAX_STREAM_EVENTS,
    ) -> None:
        super().__init__(recorder=recorder)
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("an HTTP transport needs an http:// or https:// URL")
        if min(max_message_bytes, max_stream_bytes, max_stream_events) <= 0:
            raise ValueError("size and event limits must be positive")
        self._url = url
        self._headers = dict(headers or {})
        self._max_message_bytes = max_message_bytes
        self._max_stream_bytes = max_stream_bytes
        self._max_stream_events = max_stream_events
        self._redact_prefix = recorder.redact_prefix if recorder is not None else None
        # ``Mcp-Session-Id`` from the server, replayed on later POSTs (legacy era only).
        self.session_id: str | None = None
        # Per-message headers (Mcp-Method and friends) supplied by whoever knows the protocol era.
        self.message_headers: Callable[[Mapping[str, Any]], Mapping[str, str]] | None = None
        self._close_result: CloseResult | None = None
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(connect=HTTP_CONNECT_TIMEOUT_S, read=None, write=30, pool=10),
        )

    @property
    def url(self) -> str:
        """The endpoint this transport posts to."""
        return self._url

    async def send(self, obj: Mapping[str, Any]) -> RawHttpResult:
        """POST one message. A request must get its response back on that same POST."""
        message = dict(obj)
        is_request = "method" in message and "id" in message
        extra = self.message_headers(message) if self.message_headers is not None else None
        result = await self._post(
            message,
            extra,
            None if is_request else HTTP_SEND_TIMEOUT_S,
            stop_after_id=message["id"] if is_request else None,
        )
        if not is_request:
            if result.status is None:
                raise HttpRequestFailed(None, result.error or "no HTTP response", result)
            return result
        if any(response.id == message["id"] for response in result.responses):
            return result
        reason = result.aborted or result.error or "no response with the request id"
        raise HttpRequestFailed(result.status, reason, result)

    def clone(self, headers: Mapping[str, str] | None = None) -> "HttpTransport":
        """A new transport to the same endpoint (own connection, own legacy session), sharing
        the recorder and limits. HTTP servers are stateless per request, so this is as good as a
        fresh instance for probing a different protocol era. ``headers`` replace the configured
        ones of the same name (e.g. to ask as another identity)."""
        return HttpTransport(
            self._url,
            headers=_merge(self._headers, headers or {}),
            recorder=self.recorder,
            max_message_bytes=self._max_message_bytes,
            max_stream_bytes=self._max_stream_bytes,
            max_stream_events=self._max_stream_events,
        )

    def base_headers(self) -> dict[str, str]:
        """The headers every POST carries: content type, accept, configured headers, session id.

        Negative tests start from these, then drop or change the header under test.
        """
        session = {"Mcp-Session-Id": self.session_id} if self.session_id is not None else {}
        return _merge(
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Accept-Encoding": "identity",
            },
            self._headers,
            session,
        )

    async def post(
        self,
        message: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = HTTP_SEND_TIMEOUT_S,  # noqa: ASYNC109 - the exchange deadline
    ) -> RawHttpResult:
        """POST ``message`` with the standard headers and report the whole exchange.

        Responses (including ones carried by a non-2xx status) are routed exactly as for
        ``request()``; nothing raises for an HTTP failure, the result describes it.
        """
        return await self._post(message, headers, timeout)

    async def _post(
        self,
        message: Mapping[str, Any],
        headers: Mapping[str, str] | None,
        timeout: float | None,  # noqa: ASYNC109 - the exchange deadline
        *,
        stop_after_id: RequestId | None = None,
    ) -> RawHttpResult:
        merged = _merge(self.base_headers(), headers or {})
        return await self._exchange(
            "POST",
            merged,
            encode(message)[:-1],
            dict(message),
            timeout,
            track_session=True,
            stop_after_id=stop_after_id,
        )

    async def raw_http(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        method: str = "POST",
        timeout: float | None = HTTP_SEND_TIMEOUT_S,  # noqa: ASYNC109 - the exchange deadline
        url: str | None = None,
    ) -> RawHttpResult:
        """Send exactly ``headers`` and ``body``: no defaults, session or checks; still recorded.
        ``url`` (default: the endpoint) lets a check read a well-known document beside it.

        ``httpx`` still adds Host and Content-Length, and Accept, Accept-Encoding, Connection
        and User-Agent when absent, so a request with no ``Accept`` header cannot be sent.
        """
        text = body.decode("utf-8", errors="replace")
        return await self._exchange(
            method, dict(headers), body, text, timeout, track_session=False, url=url
        )

    def alive(self) -> bool:
        return self._closed is None

    def stderr_tail(self, n: int = 4096) -> str:
        return ""

    async def close(self) -> CloseResult:
        if self._close_result is None:
            self._mark_closed(TransportClosed(None, "closed by client"))
            await self._client.aclose()  # also aborts any response still streaming
            if self._handler_tasks:
                await asyncio.wait(set(self._handler_tasks), timeout=_CLOSE_WAIT_S)
            self._close_result = CloseResult(None)
        return self._close_result

    async def _exchange(
        self,
        method: str,
        headers: dict[str, str],
        body: bytes,
        recorded: Any,
        timeout: float | None,  # noqa: ASYNC109 - the exchange deadline
        *,
        track_session: bool,
        url: str | None = None,
        stop_after_id: RequestId | None = None,
    ) -> RawHttpResult:
        if self._closed is not None:
            raise TransportClosed(self._closed.exit_code, self._closed.reason)
        started = time.monotonic()
        state = _Exchange()
        try:
            async with asyncio.timeout(timeout):
                try:
                    request = self._client.build_request(
                        method, url or self._url, headers=headers, content=body
                    )
                except ValueError as exc:
                    state.error = type(exc).__name__
                else:
                    self._record("c2s", recorded, HttpMeta(None, headers))
                    response = await self._client.send(request, stream=True)
                    try:
                        await self._read(response, state, track_session, stop_after_id)
                    finally:
                        await response.aclose()
        except TimeoutError:
            state.error = "timeout"
        except (httpx.HTTPError, httpx.StreamError, OSError) as exc:
            if self._closed is not None:
                raise TransportClosed(self._closed.exit_code, self._closed.reason) from None
            state.error = type(exc).__name__
        except RuntimeError:
            if self._closed is not None:  # the client was closed under us
                raise TransportClosed(self._closed.exit_code, self._closed.reason) from None
            raise
        return RawHttpResult(
            status=state.status,
            headers=state.headers,
            content_type=state.content_type,
            body=bytes(state.body),
            body_length=state.body_length,
            responses=tuple(state.responses),
            elapsed_ms=(time.monotonic() - started) * 1000,
            aborted=state.aborted,
            error=state.error,
        )

    async def _read(
        self,
        response: httpx.Response,
        state: _Exchange,
        track_session: bool,
        stop_after_id: RequestId | None,
    ) -> None:
        state.status = response.status_code
        state.headers = {name.lower(): value for name, value in response.headers.items()}
        state.content_type = state.headers.get("content-type", "").split(";")[0].strip().lower()
        meta = HttpMeta(state.status, state.headers)
        if track_session and 200 <= state.status < 300:
            self._capture_session(state.headers.get("mcp-session-id"))
        if state.content_type == "text/event-stream":
            await self._read_sse(response, state, meta, stop_after_id)
        else:
            await self._read_body(response, state, meta)

    def _capture_session(self, value: str | None) -> None:
        if value is None:
            return
        if _SESSION_ID.fullmatch(value):
            self.session_id = value
        else:
            self.report_violation("http_session_id_invalid", "Mcp-Session-Id is not visible ASCII")

    async def _read_body(self, response: httpx.Response, state: _Exchange, meta: HttpMeta) -> None:
        buffer = bytearray()
        async for chunk in response.aiter_raw():
            state.body_length += len(chunk)
            if state.body_length > self._max_message_bytes:
                self._abort_oversize(state, self._max_message_bytes, "body")
                self._keep(state, bytes(buffer), complete=False)
                return
            buffer += chunk
        data = bytes(buffer)
        self._keep(state, data)
        if not data:
            self._record("s2c", None, meta)  # e.g. 202 Accepted: keep the status in the trace
        elif state.content_type == "application/json":
            self._deliver(self._parse(data), meta, state)
        else:
            if state.status is not None and 200 <= state.status < 300:
                detail = f"unexpected content type {state.content_type or '(none)'}"
                self.report_violation("http_unexpected_content_type", detail)
            self._record("s2c", data.decode("utf-8", "replace"), meta)

    async def _read_sse(
        self,
        response: httpx.Response,
        state: _Exchange,
        meta: HttpMeta,
        stop_after_id: RequestId | None,
    ) -> None:
        parser = SseParser()
        events = 0
        async for chunk in response.aiter_raw():
            state.body_length += len(chunk)
            if len(state.body) < TRACE_BODY_MAX_BYTES:
                state.body += chunk[: TRACE_BODY_MAX_BYTES - len(state.body)]
            if state.body_length > self._max_stream_bytes:
                self._abort_oversize(state, self._max_stream_bytes, "stream")
                return
            for event in parser.feed(chunk):
                events += 1
                if events > self._max_stream_events:
                    limit = self._max_stream_events
                    state.aborted = f"stream exceeded {limit} events"
                    self.report_violation("sse_event_limit", state.aborted)
                    return
                self._deliver_event(event, meta, state)
                if (
                    stop_after_id is not None
                    and state.responses
                    and state.responses[-1].id == stop_after_id
                ):
                    return
        if parser.finish():
            self.report_violation("sse_truncated_event", "stream ended in the middle of an event")

    def _deliver_event(self, event: SseEvent, meta: HttpMeta, state: _Exchange) -> None:
        if event.event not in (None, "message"):
            self.report_violation("sse_event_type", f"unexpected event type {event.event!r}")
        elif event.data:  # an empty event only primes resumption
            self._deliver(self._parse(event.data.encode("utf-8")), meta, state)

    def _deliver(self, parsed: ParsedLine, meta: HttpMeta, state: _Exchange) -> None:
        self._receive(parsed, meta)
        if isinstance(parsed.message, ResultResponse | ErrorResponse):
            state.responses.append(parsed.message)

    def _parse(self, data: bytes) -> ParsedLine:
        parsed = parse_line(data, max_bytes=self._max_message_bytes, redact_text=self._redact_text)
        if isinstance(parsed.event, StdoutNoise):  # "stdout" means nothing over HTTP
            noise = parsed.event
            malformed = MalformedMessage(
                reason="body is not JSON", excerpt=noise.excerpt, length=noise.length
            )
            return ParsedLine(False, None, None, malformed)
        return parsed

    def _abort_oversize(self, state: _Exchange, limit: int, what: str) -> None:
        state.aborted = f"{what} exceeded {limit} bytes"
        self._emit(OversizeMessage(length=state.body_length, limit=limit, complete=False))

    def _keep(self, state: _Exchange, data: bytes, *, complete: bool = True) -> None:
        if state.content_type != "application/json" and self._redact_prefix is not None:
            text = data.decode("utf-8", "surrogateescape")
            text, _ = self._redact_prefix(text, final=complete)
            data = text.encode("utf-8", "surrogateescape")
        state.body += data[:TRACE_BODY_MAX_BYTES]
