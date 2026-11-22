"""Regressions from the adversarial review of T02."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from probe.wire.errors import RequestTimeout, StdoutNoise, TransportClosed, UnmatchedResponse
from probe.wire.jsonrpc import Request, ResultResponse, parse_line
from probe.wire.recorder import Recorder, read_trace
from probe.wire.transport_base import CloseResult, Transport
from probe.wire.transport_stdio import StdioTransport


class MemoryTransport(Transport):
    name = "test"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.sent: list[dict[str, Any]] = []

    async def send(self, obj: Any) -> None:
        from probe.wire.jsonrpc import encode

        encode(obj)
        self.sent.append(dict(obj))

    async def close(self) -> CloseResult:
        self._mark_closed(TransportClosed(0))
        return CloseResult(0)

    def alive(self) -> bool:
        return self._closed is None

    def stderr_tail(self, n: int = 4096) -> str:
        return ""


def deliver(t: Transport, obj: Any) -> None:
    t._receive(parse_line(json.dumps(obj).encode()))


async def test_timed_out_id_cannot_be_reused() -> None:
    t = MemoryTransport()
    with pytest.raises(RequestTimeout):
        await t.request(Request(1, "old").to_obj(), 0.001)
    with pytest.raises(ValueError, match="used"):
        await t.request(Request(1, "new").to_obj(), 0.001)
    deliver(t, ResultResponse(1, "old").to_obj())
    assert UnmatchedResponse(id=1, late=True) in t.events()


async def test_handler_flood_is_bounded() -> None:
    t = MemoryTransport()
    gate = asyncio.Event()

    async def handler(request: Request) -> None:
        await gate.wait()

    t.on_server_request(handler)
    for i in range(1000):
        deliver(t, Request(i, "slow").to_obj())
    assert len(t._handler_tasks) <= 32
    assert any(getattr(e, "rule", "") == "server_request_limit" for e in t.events())
    await t.close()
    await asyncio.sleep(0)


async def test_large_notifications_and_ids_have_byte_budgets() -> None:
    t = MemoryTransport()
    for _ in range(40):
        deliver(t, {"jsonrpc": "2.0", "method": "n", "params": {"x": "x" * 2**20}})
        deliver(t, ResultResponse("x" * 2**20, None).to_obj())
    assert t._notifications.qsize() <= 16
    assert t.notifications_dropped > 0
    assert max(len(str(e.id)) for e in t.events() if isinstance(e, UnmatchedResponse)) <= 1024
    await t.close()


async def test_bad_handler_result_gets_internal_error_reply() -> None:
    t = MemoryTransport()

    async def handler(request: Request) -> bytes:
        return b"not JSON"

    t.on_server_request(handler)
    deliver(t, Request("\ud800", "call").to_obj())
    await asyncio.sleep(0)
    assert t.sent[0]["error"]["code"] == -32603
    await t.close()


def test_keys_and_noise_are_redacted_before_truncation(tmp_path: Path) -> None:
    secret = "SUPERPRIVATE-SECRETVALUE"
    rec = Recorder(tmp_path / "trace", secrets=[secret])
    rec.record("s2c", "stdio", {"x" * (65536 - 12) + secret: "value"})
    assert secret[:10] not in rec.path.read_text()
    t = MemoryTransport(recorder=rec)
    # The complete secret straddles the parser's excerpt boundary.
    line = b"x" * 1014 + secret.encode() + b"tail"
    t._receive(parse_line(line, redact_text=rec.redact_text))
    records = read_trace(rec.close())
    assert secret[:10] not in json.dumps(records)
    assert "[REDACTED]" in t.events()[0].excerpt


def test_events_obey_body_cap_and_total_trace_is_bounded(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace", scan_max_bytes=100)
    for _ in range(10_000):
        rec.record_event("stdio", StdoutNoise(excerpt="x" * 1024, length=1024))
    assert rec.capped
    assert rec.path.stat().st_size < 100 + 2**20
    records = read_trace(rec.close())
    assert sum("body" in r and r.get("transport") == "stdio" for r in records) == 0


async def test_disk_failure_does_not_prevent_response_dispatch(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace")
    t = MemoryTransport(recorder=rec)
    task = asyncio.create_task(t.request(Request(1, "m").to_obj(), 1))
    await asyncio.sleep(0)
    assert rec._file is not None
    rec._file.close()  # a write to the closed file fails deterministically
    deliver(t, ResultResponse(1, "ok").to_obj())
    assert (await task).unwrap() == "ok"
    assert t.alive()
    assert any(getattr(e, "rule", "") == "trace_write_failed" for e in t.events())
    rec.close()
    await t.close()


async def test_request_history_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import probe.wire.transport_base as base

    monkeypatch.setattr(base, "MAX_REQUEST_IDS", 8, raising=False)
    t = MemoryTransport()
    for i in range(8):
        with pytest.raises(RequestTimeout):
            await t.request(Request(i, "m").to_obj(), 0.001)
    with pytest.raises(ValueError, match="budget"):
        await t.request(Request(9, "m").to_obj(), 0.001)
    assert len(t._timed_out) <= 8
    await t.close()


class HeldPipesProcess:
    """Models Python 3.12 wait() pending after exit while inherited pipes remain open."""

    def __init__(self) -> None:
        self.stdin: Any = self
        self.stdout = asyncio.StreamReader()
        self.stderr = None
        self.returncode: int | None = None
        self.gate = asyncio.Event()

    def close(self) -> None:
        pass

    def write(self, data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass

    async def wait(self) -> int:
        await self.gate.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


async def test_close_is_bounded_with_inherited_pipes_and_shared_between_callers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import probe.wire.transport_stdio as stdio

    monkeypatch.setattr(stdio, "_EXIT_WAIT_S", 0.01)
    t = StdioTransport(HeldPipesProcess())
    async with asyncio.timeout(0.5):
        first, second = await asyncio.gather(
            t.close(grace_s=0.01, kill_after_s=0.01),
            t.close(grace_s=0.1, kill_after_s=0.1),
        )
    assert first is second
    assert first.terminated
    assert first.exit_code == -15
    assert not t.alive()


async def test_reader_exception_fails_pending_requests_immediately() -> None:
    class BrokenReader(asyncio.StreamReader):
        async def read(self, n: int = -1) -> bytes:
            raise OSError("broken reader")

    process = HeldPipesProcess()
    process.stdout = BrokenReader()
    t = StdioTransport(process)
    await asyncio.sleep(0)
    with pytest.raises(TransportClosed, match="stdout reader failed"):
        await t.request(Request(1, "m").to_obj(), 1)
    assert not t.alive()
    process.returncode = 0
    process.gate.set()
    await t.close(grace_s=0.01)


@pytest.mark.parametrize("cut", range(1, 23))
def test_stream_redaction_preserves_secrets_split_at_every_boundary(
    tmp_path: Path, cut: int
) -> None:
    secret = "SUPERPRIVATE-SECRETVALUE"
    rec = Recorder(tmp_path / "trace", secrets=[secret])
    first, pending = rec.redact_prefix("prefix " + secret[:cut])
    second, pending = rec.redact_prefix(pending + secret[cut:] + " suffix")
    third, pending = rec.redact_prefix(pending, final=True)
    assert first + second + third == "prefix [REDACTED] suffix"
    assert pending == ""
    rec.close()


async def test_stderr_artifact_is_redacted_bounded_and_preserves_earlier_output(
    tmp_path: Path,
) -> None:
    secret = "SUPERPRIVATE-SECRETVALUE"
    rec = Recorder(tmp_path / "trace", secrets=[secret])
    code = (
        "import os\n"
        "os.write(2, b'first ' + b'x'*70000)\n"
        f"os.write(2, {secret.encode()!r})\n"
        "os.write(2, b' last')\n"
    )
    t = await StdioTransport.spawn(
        [sys.executable, "-c", code], recorder=rec, stderr_ring_bytes=1024
    )
    await t.close()
    text = (tmp_path / "stderr.log").read_text()
    assert text.startswith("first ")
    assert text.endswith("[REDACTED] last")
    assert secret not in text
    assert len(t.stderr_tail(100000)) <= 1024
    rec.close()


def test_cap_notes_redact_context_too(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace", secrets=["real-secret"], scan_max_bytes=0)
    rec.set_context(check_id="real-secret")
    rec.record("s2c", "stdio", {"a": 1})
    assert "real-secret" not in json.dumps(read_trace(rec.close()))


def test_overlapping_repeated_secrets_do_not_grow_stream_buffer(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace", secrets=["aaaa"])
    text, pending = rec.redact_prefix("a" * 4096)
    assert len(pending) <= 4
    assert text and "aaaa" not in text
    rec.close()


async def test_stderr_artifact_open_failure_is_contained(tmp_path: Path) -> None:
    process = HeldPipesProcess()
    # Opening a directory as a file fails, but this optional sink must not abort construction.
    t = StdioTransport(process, stderr_path=tmp_path)
    assert any(getattr(e, "rule", "") == "stderr_log_failed" for e in t.events())
    process.returncode = 0
    process.gate.set()
    process.stdout.feed_eof()
    await t.close()


async def test_spawn_cleans_up_if_construction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    original = asyncio.create_subprocess_exec
    processes: list[asyncio.subprocess.Process] = []

    async def capture(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        process = await original(*args, **kwargs)
        processes.append(process)
        return process

    def fail(self: StdioTransport, *args: Any, **kwargs: Any) -> None:
        raise ValueError("construction failed")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    monkeypatch.setattr(StdioTransport, "__init__", fail)
    try:
        with pytest.raises(ValueError, match="construction failed"):
            await StdioTransport.spawn([sys.executable, "-c", "import time; time.sleep(60)"])
        assert processes[0].returncode is not None
    finally:
        for process in processes:
            if process.returncode is None:
                process.kill()
            await asyncio.wait_for(process.wait(), 2)


async def test_parent_exit_fails_requests_even_while_inherited_pipes_stay_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import probe.wire.transport_stdio as stdio

    monkeypatch.setattr(stdio, "_EXIT_WAIT_S", 0.01)
    process = HeldPipesProcess()
    t = StdioTransport(process)
    request = asyncio.create_task(t.request(Request(1, "m").to_obj(), 1))
    await asyncio.sleep(0)
    process.returncode = 7
    try:
        with pytest.raises(TransportClosed) as info:
            await request
        assert info.value.exit_code == 7
    finally:
        process.gate.set()
        await t.close(grace_s=0.01)
