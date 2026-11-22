"""Exceptions raised by the wire layer and the events it reports about server behavior.

Exceptions are for the caller's request failing; events are observations (noise, oversize
lines, protocol violations) that checks read afterwards. Events never stop the stream.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

RequestId = int | str


class WireError(Exception):
    """Base class for wire-layer failures."""


class TransportClosed(WireError):
    def __init__(self, exit_code: int | None, reason: str = "transport closed") -> None:
        super().__init__(f"{reason} (exit code {exit_code})")
        self.exit_code = exit_code
        self.reason = reason


class RequestTimeout(WireError):
    def __init__(self, request_id: RequestId, timeout_s: float) -> None:
        super().__init__(f"no response to request {request_id!r} within {timeout_s} s")
        self.request_id = request_id
        self.timeout_s = timeout_s


class JsonRpcError(WireError):
    """A JSON-RPC error object, raised from a response or by a server-request handler."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class _Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OversizeMessage(_Event):
    """A line longer than the limit; its bytes were discarded up to the next newline."""

    kind: Literal["oversize_message"] = "oversize_message"
    length: int
    limit: int
    # False when the stream ended before the line did.
    complete: bool = True


class StdoutNoise(_Event):
    """A stdout line that is not JSON (feeds protocol.stdout_clean)."""

    kind: Literal["stdout_noise"] = "stdout_noise"
    excerpt: str
    length: int


class MalformedMessage(_Event):
    """JSON that is not a valid JSON-RPC message, or JSON too deeply nested to parse."""

    kind: Literal["malformed_message"] = "malformed_message"
    reason: str
    excerpt: str = ""
    length: int = 0


class UnmatchedResponse(_Event):
    """A response whose id matches no pending request; ``late`` if that request timed out."""

    kind: Literal["unmatched_response"] = "unmatched_response"
    id: RequestId | None
    late: bool


class ProtocolViolation(_Event):
    """Illegal server behavior noticed above the framing layer (e.g. by the session)."""

    kind: Literal["protocol_violation"] = "protocol_violation"
    rule: str
    detail: str


class ProcessExited(_Event):
    kind: Literal["process_exited"] = "process_exited"
    exit_code: int | None


WireEvent = (
    OversizeMessage
    | StdoutNoise
    | MalformedMessage
    | UnmatchedResponse
    | ProtocolViolation
    | ProcessExited
)
