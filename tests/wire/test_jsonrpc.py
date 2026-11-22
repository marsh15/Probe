"""JSON-RPC classification: every incoming line is a message or a typed event, never a crash."""

from typing import Any

import pytest

from probe.wire.errors import JsonRpcError, MalformedMessage, OversizeMessage, StdoutNoise
from probe.wire.jsonrpc import (
    ErrorObject,
    ErrorResponse,
    Notification,
    Request,
    ResultResponse,
    classify,
    encode,
    parse_line,
)
from probe.wire.limits import MAX_JSON_DEPTH


def test_request_notification_and_responses_are_classified() -> None:
    assert classify({"jsonrpc": "2.0", "id": 1, "method": "m", "params": {"a": 1}}) == Request(
        1, "m", {"a": 1}
    )
    assert classify({"jsonrpc": "2.0", "method": "n"}) == Notification("n")
    assert classify({"jsonrpc": "2.0", "id": "x", "result": None}) == ResultResponse("x", None)
    assert classify(
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse", "data": 3}}
    ) == ErrorResponse(None, ErrorObject(-32700, "parse", 3))


@pytest.mark.parametrize(
    ("obj", "reason"),
    [
        ([], "not an object"),
        ({"id": 1, "method": "m"}, "jsonrpc"),
        ({"jsonrpc": "1.0", "id": 1, "method": "m"}, "jsonrpc"),
        ({"jsonrpc": "2.0", "id": True, "method": "m"}, "id"),
        ({"jsonrpc": "2.0", "id": 1.5, "method": "m"}, "id"),
        ({"jsonrpc": "2.0", "id": None, "method": "m"}, "id"),
        ({"jsonrpc": "2.0", "id": 1, "method": 7}, "method"),
        ({"jsonrpc": "2.0", "id": 1, "method": "m", "params": "p"}, "params"),
        ({"jsonrpc": "2.0", "id": 1}, "result"),
        ({"jsonrpc": "2.0", "id": 1, "result": 1, "error": {}}, "result"),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": "x", "message": "m"}}, "error"),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": 1}}, "error"),
        ({"jsonrpc": "2.0", "id": None, "result": 1}, "id"),
        ({"jsonrpc": "2.0", "result": 1}, "id"),
    ],
)
def test_invalid_shapes_are_malformed(obj: Any, reason: str) -> None:
    result = classify(obj)
    assert isinstance(result, MalformedMessage)
    assert reason in result.reason


def test_parse_line_returns_value_and_message() -> None:
    parsed = parse_line(b'{"jsonrpc":"2.0","id":1,"result":{"x":1}}\r\n')
    assert parsed.is_json
    assert parsed.value == {"jsonrpc": "2.0", "id": 1, "result": {"x": 1}}
    assert parsed.message == ResultResponse(1, {"x": 1})
    assert parsed.event is None


@pytest.mark.parametrize("line", [b"hello world", b"{not json", b"", b"   ", b"\xff\xfe"])
def test_non_json_lines_are_noise(line: bytes) -> None:
    parsed = parse_line(line)
    assert not parsed.is_json
    assert parsed.message is None
    assert isinstance(parsed.event, StdoutNoise)
    assert parsed.event.length == len(line)


def test_valid_json_with_wrong_shape_is_malformed_but_keeps_value() -> None:
    parsed = parse_line(b'{"jsonrpc":"2.0","id":1}')
    assert parsed.is_json
    assert parsed.value == {"jsonrpc": "2.0", "id": 1}
    assert isinstance(parsed.event, MalformedMessage)


def test_deeply_nested_json_is_malformed_not_a_crash() -> None:
    depth = 200_000
    parsed = parse_line(b"[" * depth + b"]" * depth)
    assert isinstance(parsed.event, MalformedMessage)
    assert "nest" in parsed.event.reason


@pytest.mark.parametrize("depth", [MAX_JSON_DEPTH + 1, 5_000, 100_000])
def test_nesting_past_the_depth_limit_is_malformed_on_every_python(depth: int) -> None:
    # Newer CPython parses 100k levels without RecursionError; later code must not see them.
    line = b'{"jsonrpc":"2.0","id":1,"result":' + b"[" * depth + b"]" * depth + b"}"
    parsed = parse_line(line)
    assert parsed.message is None
    assert isinstance(parsed.event, MalformedMessage)
    assert "nest" in parsed.event.reason


def test_nesting_at_the_depth_limit_is_accepted() -> None:
    depth = MAX_JSON_DEPTH - 1  # the envelope object is one level
    line = b'{"jsonrpc":"2.0","id":1,"result":' + b"[" * depth + b"]" * depth + b"}"
    assert isinstance(parse_line(line).message, ResultResponse)


def test_non_standard_constants_are_malformed() -> None:
    parsed = parse_line(b'{"jsonrpc":"2.0","id":1,"result":NaN}')
    assert isinstance(parsed.event, MalformedMessage)


def test_size_is_checked_before_parsing() -> None:
    parsed = parse_line(b'{"jsonrpc":"2.0","method":"' + b"a" * 100 + b'"}', max_bytes=50)
    assert not parsed.is_json
    assert isinstance(parsed.event, OversizeMessage)
    assert parsed.event.limit == 50


def test_event_excerpts_are_bounded() -> None:
    parsed = parse_line(b"x" * 100_000)
    assert isinstance(parsed.event, StdoutNoise)
    assert len(parsed.event.excerpt) <= 1024
    assert parsed.event.length == 100_000


def test_encode_is_one_compact_line() -> None:
    assert encode(Request(1, "m", {"k": "é"}).to_obj()) == (
        b'{"jsonrpc":"2.0","id":1,"method":"m","params":{"k":"\xc3\xa9"}}\n'
    )
    assert Notification("n").to_obj() == {"jsonrpc": "2.0", "method": "n"}


def test_unwrap_raises_json_rpc_error() -> None:
    assert ResultResponse(1, {"a": 1}).unwrap() == {"a": 1}
    with pytest.raises(JsonRpcError) as info:
        ErrorResponse(1, ErrorObject(-32601, "nope", {"d": 1})).unwrap()
    assert (info.value.code, info.value.message, info.value.data) == (-32601, "nope", {"d": 1})
