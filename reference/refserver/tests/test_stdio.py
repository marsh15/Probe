"""`refserver stdio` as a subprocess, spoken to in raw NDJSON, in both protocol eras."""

from __future__ import annotations

import io
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from refserver import bugs
from refserver.wire_bugs import (
    StdioMutationHook,
    _pump,
    apply_stdio_hooks,
    invalid_message_reply,
)

MODERN = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "refserver-tests", "version": "0"},
}


class StdioSession:
    def __init__(self, data_root: Path, *extra: str) -> None:
        env = {**os.environ, "REFSERVER_DATA": str(data_root), "REFSERVER_SECRET": "fixed"}
        env.pop("PROBE_REF_BUGS", None)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "refserver", "stdio", *extra],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.raw: list[bytes] = []
        self._lines: queue.Queue[bytes] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.raw.append(line)
            self._lines.put(line)

    def send(self, message: dict[str, object]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = 15) -> dict[str, object]:
        return json.loads(self._lines.get(timeout=timeout))

    def request(
        self, rid: int, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        message: dict[str, object] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        while True:
            reply = self.recv()
            if reply.get("id") == rid:
                return reply

    def close(self) -> int:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        code = self.proc.wait(timeout=15)
        assert self.proc.stderr is not None
        self.proc.stderr.close()
        return code


def modern_script(s: StdioSession) -> None:
    discover = s.request(1, "server/discover", {"_meta": META})["result"]
    assert MODERN in discover["supportedVersions"]
    listing = s.request(2, "tools/list", {"_meta": META})["result"]
    assert listing["resultType"] == "complete"
    assert len(listing["tools"]) == 15
    got = s.request(3, "tools/call", {"_meta": META, "name": "notes_get", "arguments": {"id": 1}})[
        "result"
    ]
    assert got["structuredContent"]["id"] == 1
    assert json.loads(got["content"][0]["text"]) == got["structuredContent"]


def legacy_script(s: StdioSession) -> None:
    init = s.request(
        1,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    )["result"]
    assert init["protocolVersion"] == "2025-11-25"
    assert init["serverInfo"]["name"] == "refserver"
    s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert len(s.request(2, "tools/list")["result"]["tools"]) == 15
    got = s.request(3, "tools/call", {"name": "notes_get", "arguments": {"id": 1}})["result"]
    assert got["structuredContent"]["id"] == 1


@pytest.mark.parametrize("script", [modern_script, legacy_script], ids=["modern", "legacy"])
def test_stdio_smoke_both_eras(data_root: Path, script) -> None:
    session = StdioSession(data_root)
    script(session)
    assert session.close() == 0
    for line in session.raw:
        json.loads(line)  # nothing but JSON-RPC on stdout


def _without_tasks(line: bytes) -> object:
    message = json.loads(line)
    result = message.get("result")
    capabilities = result.get("capabilities") if isinstance(result, dict) else None
    extensions = capabilities.get("extensions") if isinstance(capabilities, dict) else None
    if isinstance(extensions, dict):
        extensions.pop("io.modelcontextprotocol/tasks", None)
        if not extensions:
            del capabilities["extensions"]
    return message


@pytest.mark.parametrize("script", [modern_script, legacy_script], ids=["modern", "legacy"])
def test_front_proxy_is_byte_transparent(data_root: Path, script) -> None:
    transcripts = []
    for extra in ((), ("--no-proxy",)):
        session = StdioSession(data_root, *extra)
        script(session)
        session.close()
        transcripts.append(session.raw)
    proxied, direct = transcripts
    # The only thing the proxy adds to a clean server is the Tasks extension in discover.
    assert [_without_tasks(line) for line in proxied] == [_without_tasks(line) for line in direct]
    assert (
        sum(
            proxied_line != direct_line
            for proxied_line, direct_line in zip(proxied, direct, strict=True)
        )
        <= 1
    )


def test_cancellation_and_progress(data_root: Path) -> None:
    s = StdioSession(data_root)
    s.send(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "_meta": {**META, "progressToken": "p1"},
                "name": "slow_report",
                "arguments": {"seconds": 10},
            },
        }
    )
    progress = s.recv()
    assert progress["method"] == "notifications/progress"
    assert progress["params"]["progressToken"] == "p1"
    s.send(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"_meta": META, "requestId": 10},
        }
    )
    # The server stays responsive and never answers the cancelled request.
    assert "tools" in s.request(11, "tools/list", {"_meta": META})["result"]
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        try:
            message = s.recv(timeout=0.2)
        except queue.Empty:
            continue
        assert message.get("id") != 10, "server answered a cancelled request"
        assert message.get("method") != "notifications/progress", "progress continued after cancel"
    assert s.close() == 0


@pytest.mark.anyio
async def test_pump_relays_bytes_unchanged_without_hooks() -> None:
    lines = [
        b'{"jsonrpc":"2.0","id":1}\n',
        b"\xff\xfe not utf-8\r\n",
        "caf\u00e9 \u2028\n".encode(),
        b"no newline",
    ]
    source, sink = io.BytesIO(b"".join(lines)), io.BytesIO()
    await _pump(source, sink, "server_to_client", [], close_sink=False)
    assert sink.getvalue() == b"".join(lines)
    assert all(apply_stdio_hooks("client_to_server", line, []) == [line] for line in lines)


def test_hooks_compose_in_order() -> None:
    def double(direction: str, line: bytes) -> list[bytes]:
        return [line, line]

    def drop_b(direction: str, line: bytes) -> list[bytes]:
        return [] if line == b"b\n" else [line.upper()]

    assert apply_stdio_hooks("server_to_client", b"a\n", [double, drop_b]) == [b"A\n", b"A\n"]
    assert apply_stdio_hooks("server_to_client", b"b\n", [double, drop_b]) == []


@pytest.mark.parametrize(
    ("line", "code", "request_id"),
    [
        (b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"', -32700, None),
        (b"not json at all", -32700, None),
        (b'{"id": 7, "method": "tools/list"}', -32600, 7),
        (b'{"jsonrpc": "1.0", "id": "x", "method": "tools/list"}', -32600, "x"),
        (b'{"jsonrpc": "2.0", "id": 3}', -32600, 3),
        (b'[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]', -32600, None),
        (b'"a string"', -32600, None),
        (b'{"jsonrpc": "2.0", "id": true, "method": 5}', -32600, None),
    ],
)
def test_invalid_lines_get_the_json_rpc_error(line: bytes, code: int, request_id: object) -> None:
    reply = invalid_message_reply(line + b"\n")
    assert reply is not None
    assert json.loads(reply) == {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": "Parse error" if code == -32700 else "Invalid Request"},
    }


@pytest.mark.parametrize(
    "line",
    [
        b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "method": "notifications/initialized"}',
        b'{"jsonrpc": "2.0", "id": "s1", "result": {}}',  # a reply to a server request
        b'{"jsonrpc": "2.0", "id": "s1", "error": {"code": -1, "message": "x"}}',
    ],
)
def test_valid_messages_are_left_to_the_sdk(line: bytes) -> None:
    assert invalid_message_reply(line + b"\n") is None


def test_blank_lines_are_swallowed_silently() -> None:
    assert invalid_message_reply(b"\n") == b""
    assert invalid_message_reply(b"   \r\n") == b""


def test_malformed_input_is_answered_and_the_server_keeps_serving(data_root: Path) -> None:
    s = StdioSession(data_root)
    assert s.proc.stdin is not None
    for garbage, code in [
        (b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"', -32700),
        (b'{"id": 1, "method": "tools/list"}', -32600),
        (b'[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]', -32600),
    ]:
        s.proc.stdin.write(garbage + b"\n")
        s.proc.stdin.flush()
        assert s.recv()["error"]["code"] == code  # type: ignore[index]
    s.proc.stdin.write(b"\n")  # a blank line is ignored without a reply
    s.proc.stdin.flush()
    assert len(s.request(2, "tools/list", {"_meta": META})["result"]["tools"]) == 15  # type: ignore[index]
    assert s.close() == 0


class ShortWriter:
    """A sink that, like a pipe under pressure, accepts only a few bytes per write call."""

    def __init__(self, chunk: int = 3) -> None:
        self.chunk = chunk
        self.data = bytearray()

    def write(self, data: bytes | memoryview) -> int:
        taken = bytes(data[: self.chunk])
        self.data += taken
        return len(taken)

    def flush(self) -> None:
        pass


@pytest.mark.anyio
async def test_pump_writes_every_byte_even_when_the_sink_takes_short_writes() -> None:
    line = b'{"jsonrpc":"2.0","id":1,"result":{"big":"' + b"x" * 100 + b'"}}\n'
    sink = ShortWriter()
    await _pump(io.BytesIO(line), sink, "server_to_client", [], close_sink=False)  # type: ignore[arg-type]
    assert bytes(sink.data) == line


@pytest.mark.anyio
async def test_pump_sends_replies_in_full_when_the_client_stream_takes_short_writes() -> None:
    reply_to = ShortWriter()
    await _pump(
        io.BytesIO(b"not json at all\n"),
        io.BytesIO(),
        "client_to_server",
        [],
        close_sink=False,
        reply_to=reply_to,  # type: ignore[arg-type]
    )
    assert json.loads(bytes(reply_to.data))["error"]["code"] == -32700


def test_the_wire_streams_are_buffered_so_a_line_is_not_read_byte_by_byte() -> None:
    code = (
        "from refserver.wire_bugs import _claim_std_streams;"
        "i, o = _claim_std_streams();"
        "import io, sys;"  # fd 1 now points at stderr, as in the server
        "print(isinstance(i, io.BufferedReader), file=sys.stderr)"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], input=b"", capture_output=True, check=True, timeout=30
    )
    assert done.stderr.strip() == b"True"


@pytest.mark.parametrize(
    "line",
    [
        b'{"jsonrpc": "2.0", "id": true, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": false, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": 1.5, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": {"a": 1}, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": [1], "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": 1.5, "result": {}}',
    ],
)
def test_invalid_id_types_get_invalid_request_with_a_null_id(line: bytes) -> None:
    reply = invalid_message_reply(line + b"\n")
    assert reply is not None
    assert json.loads(reply) == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "Invalid Request"},
    }


@pytest.mark.parametrize("params", ['"x"', "[1, 2]", "5", "true", "null"])
def test_non_object_params_get_invalid_request_keeping_the_id(params: str) -> None:
    line = (
        b'{"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": ' + params.encode() + b"}"
    )
    reply = invalid_message_reply(line + b"\n")
    assert reply is not None
    assert json.loads(reply)["error"]["code"] == -32600
    assert json.loads(reply)["id"] == 4


@pytest.mark.parametrize(
    "line",
    [
        b'{"jsonrpc": "2.0", "id": 0, "method": "tools/list"}',
        b'{"jsonrpc": "2.0", "id": "", "method": "tools/list", "params": {}}',
        b'{"jsonrpc": "2.0", "method": "notifications/initialized", "params": {"a": 1}}',
    ],
)
def test_valid_id_and_params_are_still_left_to_the_sdk(line: bytes) -> None:
    assert invalid_message_reply(line + b"\n") is None


@pytest.mark.anyio
async def test_invalid_ids_are_refused_before_the_tasks_layer_can_answer() -> None:
    meta = {"io.modelcontextprotocol/protocolVersion": MODERN}
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": True,
            "method": "tasks/get",
            "params": {"_meta": meta, "taskId": "x"},
        }
    ).encode()
    out = io.BytesIO()
    hook = StdioMutationHook(frozenset())
    await _pump(
        io.BytesIO(line + b"\n"), io.BytesIO(), "client_to_server", [hook], False, reply_to=out
    )
    reply = json.loads(out.getvalue())
    assert reply["id"] is None and reply["error"]["code"] == -32600


@pytest.mark.anyio
async def test_b08_still_answers_parseable_invalid_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(bugs.ENV_VAR, "b08")
    bugs.load()
    out, sink = io.BytesIO(), io.BytesIO()
    await _pump(
        io.BytesIO(b'{"id": 1, "method": "tools/list"}\n'),
        sink,
        "client_to_server",
        [StdioMutationHook(bugs.active())],
        False,
        reply_to=out,
    )
    assert json.loads(out.getvalue())["error"]["code"] == -32600
    assert sink.getvalue() == b""  # nothing invalid is forwarded to the SDK
