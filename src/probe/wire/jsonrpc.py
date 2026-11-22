"""JSON-RPC 2.0 messages and the strict classification of whatever a server sends."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from probe.wire.errors import (
    JsonRpcError,
    MalformedMessage,
    OversizeMessage,
    RequestId,
    StdoutNoise,
)
from probe.wire.limits import EVENT_EXCERPT_BYTES, MAX_JSON_DEPTH, MAX_MESSAGE_BYTES

Params = dict[str, Any] | list[Any] | None

METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603


@dataclass(frozen=True, slots=True)
class Request:
    id: RequestId
    method: str
    params: Params = None

    def to_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id, "method": self.method}
        if self.params is not None:
            obj["params"] = self.params
        return obj


@dataclass(frozen=True, slots=True)
class Notification:
    method: str
    params: Params = None

    def to_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"jsonrpc": "2.0", "method": self.method}
        if self.params is not None:
            obj["params"] = self.params
        return obj


@dataclass(frozen=True, slots=True)
class ResultResponse:
    id: RequestId
    result: Any

    def unwrap(self) -> Any:
        return self.result

    def to_obj(self) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": self.id, "result": self.result}


@dataclass(frozen=True, slots=True)
class ErrorObject:
    code: int
    message: str
    data: Any = None

    def to_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            obj["data"] = self.data
        return obj


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    # None only for errors about a request whose id could not be read (e.g. parse errors).
    id: RequestId | None
    error: ErrorObject

    def unwrap(self) -> Any:
        raise JsonRpcError(self.error.code, self.error.message, self.error.data)

    def to_obj(self) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": self.id, "error": self.error.to_obj()}


Response = ResultResponse | ErrorResponse
Message = Request | Notification | Response


@dataclass(frozen=True, slots=True)
class ParsedLine:
    """One incoming line: its JSON value (if any), the message it is, or why it is not one."""

    is_json: bool
    value: Any
    message: Message | None
    event: StdoutNoise | MalformedMessage | OversizeMessage | None


def encode(obj: Any) -> bytes:
    """One compact UTF-8 JSON line, as stdio framing requires."""
    return (
        json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8", "backslashreplace"
        )
        + b"\n"
    )


def excerpt(data: bytes, redact_text: Callable[[str], str] | None = None) -> str:
    text = data.decode("utf-8", errors="replace")
    if redact_text is not None:
        text = redact_text(text)
    return text.encode("utf-8", "backslashreplace")[:EVENT_EXCERPT_BYTES].decode(
        "utf-8", errors="ignore"
    )


def _is_id(value: Any) -> bool:
    # bool is an int subclass but never a valid id; fractional ids are not accepted either.
    return isinstance(value, str | int) and not isinstance(value, bool)


def _malformed(reason: str) -> MalformedMessage:
    return MalformedMessage(reason=reason)


def classify(obj: Any) -> Message | MalformedMessage:
    """Classify a decoded JSON value as exactly one JSON-RPC message shape, or say why not."""
    if not isinstance(obj, dict):
        return _malformed("not an object (batches are not supported)")
    if obj.get("jsonrpc") != "2.0":
        return _malformed('jsonrpc must be "2.0"')
    if "method" in obj:
        method, params = obj["method"], obj.get("params")
        if not isinstance(method, str):
            return _malformed("method must be a string")
        if params is not None and not isinstance(params, dict | list):
            return _malformed("params must be an object or array")
        if "id" not in obj:
            return Notification(method, params)
        if not _is_id(obj["id"]):
            return _malformed("request id must be a string or integer")
        return Request(obj["id"], method, params)
    if ("result" in obj) == ("error" in obj):
        return _malformed("response must have exactly one of result and error")
    if "id" not in obj:
        return _malformed("response id is missing")
    response_id = obj["id"]
    if "result" in obj:
        if not _is_id(response_id):
            return _malformed("result response id must be a string or integer")
        return ResultResponse(response_id, obj["result"])
    if response_id is not None and not _is_id(response_id):
        return _malformed("error response id must be a string, integer or null")
    error = obj["error"]
    if (
        not isinstance(error, dict)
        or not isinstance(error.get("code"), int)
        or isinstance(error.get("code"), bool)
        or not isinstance(error.get("message"), str)
    ):
        return _malformed("error must be an object with an integer code and a string message")
    return ErrorResponse(
        response_id, ErrorObject(error["code"], error["message"], error.get("data"))
    )


def _deeper_than(value: Any, limit: int) -> bool:
    # Iterative on purpose: the value may be nested far past the recursion limit.
    stack: list[tuple[Iterator[Any], int]] = [(iter((value,)), 1)]
    while stack:
        children, depth = stack[-1]
        try:
            item = next(children)
        except StopIteration:
            stack.pop()
            continue
        if isinstance(item, dict | list):
            if depth > limit:
                return True
            values = item.values() if isinstance(item, dict) else item
            stack.append((iter(values), depth + 1))
    return False


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def parse_line(
    line: bytes,
    *,
    max_bytes: int = MAX_MESSAGE_BYTES,
    redact_text: Callable[[str], str] | None = None,
) -> ParsedLine:
    """Decode one line (newline optional). Never raises on hostile input."""
    line = line.rstrip(b"\r\n")
    if len(line) > max_bytes:
        event = OversizeMessage(length=len(line), limit=max_bytes)
        return ParsedLine(False, None, None, event)
    try:
        value = json.loads(line, parse_constant=_reject_constant)
    except RecursionError:
        malformed = MalformedMessage(
            reason="JSON nested too deeply to parse",
            excerpt=excerpt(line, redact_text),
            length=len(line),
        )
        return ParsedLine(False, None, None, malformed)
    except ValueError as exc:  # JSONDecodeError, bad UTF-8, NaN/Infinity
        if "non-standard JSON constant" in str(exc):
            malformed = MalformedMessage(
                reason=str(exc), excerpt=excerpt(line, redact_text), length=len(line)
            )
            return ParsedLine(False, None, None, malformed)
        return ParsedLine(
            False, None, None, StdoutNoise(excerpt=excerpt(line, redact_text), length=len(line))
        )
    if _deeper_than(value, MAX_JSON_DEPTH):
        malformed = MalformedMessage(
            reason=f"JSON nested deeper than {MAX_JSON_DEPTH} levels",
            excerpt=excerpt(line, redact_text),
            length=len(line),
        )
        return ParsedLine(False, None, None, malformed)
    result = classify(value)
    if isinstance(result, MalformedMessage):
        malformed = result.model_copy(
            update={"excerpt": excerpt(line, redact_text), "length": len(line)}
        )
        return ParsedLine(True, value, None, malformed)
    return ParsedLine(True, value, result, None)
