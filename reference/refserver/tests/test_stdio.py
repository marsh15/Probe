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
from refserver.wire_bugs import _pump, apply_stdio_hooks

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


@pytest.mark.parametrize("script", [modern_script, legacy_script], ids=["modern", "legacy"])
def test_front_proxy_is_byte_transparent(data_root: Path, script) -> None:
    transcripts = []
    for extra in ((), ("--no-proxy",)):
        session = StdioSession(data_root, *extra)
        script(session)
        session.close()
        transcripts.append(session.raw)
    proxied, direct = transcripts
    assert proxied == direct


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
