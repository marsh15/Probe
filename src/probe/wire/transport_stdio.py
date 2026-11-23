"""Newline-delimited JSON-RPC over a child process's stdin/stdout."""

import asyncio
import codecs
import contextlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO, Protocol, Self

from probe.util.sanitize_console import sanitize_console
from probe.wire.errors import OversizeMessage, ProcessExited, TransportClosed
from probe.wire.jsonrpc import encode, parse_line
from probe.wire.limits import (
    MAX_MESSAGE_BYTES,
    SHUTDOWN_GRACE_S,
    SHUTDOWN_KILL_AFTER_S,
    STDERR_RING_BYTES,
    TRACE_SCAN_MAX_BYTES,
)
from probe.wire.recorder import Recorder
from probe.wire.transport_base import CloseResult, Transport

_CHUNK_BYTES = 64 * 1024
# After stdout ends, how long to wait for the exit code and the rest of stderr.
_EXIT_WAIT_S = 2.0


class ProcessLike(Protocol):
    """What the transport needs from a process: an asyncio subprocess or a ``docker run -i``."""

    @property
    def stdin(self) -> asyncio.StreamWriter | None: ...
    @property
    def stdout(self) -> asyncio.StreamReader | None: ...
    @property
    def stderr(self) -> asyncio.StreamReader | None: ...
    @property
    def returncode(self) -> int | None: ...
    async def wait(self) -> int: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


class StdioTransport(Transport):
    """Reads stdout with a bounded line reader and drains stderr into a ring buffer.

    Must be constructed inside a running event loop: the readers start immediately.
    """

    name = "stdio"

    def __init__(
        self,
        process: ProcessLike,
        *,
        recorder: Recorder | None = None,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
        stderr_ring_bytes: int = STDERR_RING_BYTES,
        stderr_path: Path | None = None,
        stderr_max_bytes: int = TRACE_SCAN_MAX_BYTES,
    ) -> None:
        super().__init__(recorder=recorder)
        if max_message_bytes <= 0 or min(stderr_ring_bytes, stderr_max_bytes) < 0:
            raise ValueError("message limit must be positive and stderr limit nonnegative")
        if process.stdin is None or process.stdout is None:
            raise ValueError("the process needs piped stdin and stdout")
        self._process = process
        self._stdin = process.stdin
        self._max_message_bytes = max_message_bytes
        self._stderr = bytearray()
        self._stderr_ring_bytes = stderr_ring_bytes
        self._stderr_path = stderr_path
        if self._stderr_path is None and recorder is not None:
            self._stderr_path = recorder.path.parent / "stderr.log"
        self._stderr_file: BinaryIO | None = None
        if self._stderr_path is not None:
            try:
                self._stderr_file = self._stderr_path.open("wb")
            except OSError as exc:
                self.report_violation("stderr_log_failed", type(exc).__name__)
        self._stderr_written = 0
        self._stderr_max_bytes = stderr_max_bytes
        self._stderr_pending = ""
        self._stderr_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._redact_prefix = recorder.redact_prefix if recorder is not None else None
        self._write_lock = asyncio.Lock()
        self._close_result: CloseResult | None = None
        self._close_task: asyncio.Task[CloseResult] | None = None
        self._stderr_task = (
            asyncio.create_task(self._drain_stderr(process.stderr)) if process.stderr else None
        )
        self._stdout_task = asyncio.create_task(self._read_stdout(process.stdout))
        self._watch_task = asyncio.create_task(self._watch_exit())

    @classmethod
    async def spawn(
        cls,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        recorder: Recorder | None = None,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
        stderr_ring_bytes: int = STDERR_RING_BYTES,
        stderr_path: Path | None = None,
        stderr_max_bytes: int = TRACE_SCAN_MAX_BYTES,
    ) -> Self:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=None if env is None else dict(env),
            cwd=cwd,
        )
        try:
            return cls(
                process,
                recorder=recorder,
                max_message_bytes=max_message_bytes,
                stderr_ring_bytes=stderr_ring_bytes,
                stderr_path=stderr_path,
                stderr_max_bytes=stderr_max_bytes,
            )
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            process_transport = getattr(process, "_transport", None)
            if isinstance(process_transport, asyncio.SubprocessTransport):
                process_transport.close()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), _EXIT_WAIT_S)
            raise

    async def send(self, obj: Mapping[str, Any]) -> None:
        await self._write(encode(obj), obj)

    async def raw_stdio_line(self, data: bytes) -> None:
        """Write ``data`` exactly as given (no framing, no validation); still recorded."""
        await self._write(data, data.decode("utf-8", errors="replace"))

    def alive(self) -> bool:
        return self._closed is None and self._process.returncode is None

    @property
    def returncode(self) -> int | None:
        """The process exit code, or None while it is still running."""
        return self._process.returncode

    def stderr_tail(self, n: int = 4096) -> str:
        tail = bytes(self._stderr[-n:]) if n > 0 else b""
        return sanitize_console(tail.decode("utf-8", errors="replace"))

    async def close(
        self, *, grace_s: float = SHUTDOWN_GRACE_S, kill_after_s: float = SHUTDOWN_KILL_AFTER_S
    ) -> CloseResult:
        """Close stdin, wait ``grace_s``, then SIGTERM, then SIGKILL after ``kill_after_s``."""
        if self._close_result is not None:
            return self._close_result
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close(grace_s, kill_after_s))
        return await asyncio.shield(self._close_task)

    async def _close(self, grace_s: float, kill_after_s: float) -> CloseResult:
        terminated = killed = False
        self._stdin.close()
        if not await self._wait_exit(grace_s):
            terminated = True
            with contextlib.suppress(ProcessLookupError):
                self._process.terminate()
            if not await self._wait_exit(kill_after_s):
                killed = True
                with contextlib.suppress(ProcessLookupError):
                    self._process.kill()
                await self._wait_exit(_EXIT_WAIT_S)
        exit_code = self._process.returncode
        # A grandchild holding the pipes open must not keep the readers alive forever.
        readers = {
            t for t in (self._stdout_task, self._stderr_task, self._watch_task) if t is not None
        }
        _, stuck = await asyncio.wait(readers, timeout=_EXIT_WAIT_S)
        for task in stuck:
            task.cancel()
        self._mark_closed(TransportClosed(exit_code, "closed by client"))
        tasks = stuck | self._handler_tasks
        if tasks:
            await asyncio.wait(tasks, timeout=_EXIT_WAIT_S)
        if isinstance(self._process, asyncio.subprocess.Process):
            # Process has no public pipe-close method. Closing the asyncio transport releases
            # inherited pipes too, before the event loop shuts down (not in __del__).
            process_transport = getattr(self._process, "_transport", None)
            if isinstance(process_transport, asyncio.SubprocessTransport):
                process_transport.close()
                await asyncio.sleep(0)
        if self._stderr_file is not None:
            self._write_stderr_log("", final=True)
            if self._stderr_file is not None:
                self._stderr_file.close()
                self._stderr_file = None
        self._close_result = CloseResult(exit_code, terminated, killed)
        return self._close_result

    async def _wait_exit(self, seconds: float) -> bool:
        deadline = asyncio.get_running_loop().time() + seconds
        while self._process.returncode is None:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            try:
                # On 3.12 wait() also waits for inherited pipes, even after returncode is set.
                await asyncio.wait_for(self._process.wait(), min(remaining, 0.05))
                return True
            except TimeoutError:
                continue
        return True

    async def _write(self, data: bytes, body: Any) -> None:
        if self._closed is not None:
            raise TransportClosed(self._closed.exit_code, self._closed.reason)
        async with self._write_lock:
            try:
                self._stdin.write(data)
                self._record("c2s", body)
                await self._stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise TransportClosed(self._process.returncode, "server stdin closed") from exc

    async def _read_stdout(self, stdout: asyncio.StreamReader) -> None:
        try:
            await self._read_lines(stdout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            reason = f"stdout reader failed: {type(exc).__name__}"
            self.report_violation("stdout_reader_failed", reason)
            self._mark_closed(TransportClosed(self._process.returncode, reason))

    async def _read_lines(self, stdout: asyncio.StreamReader) -> None:
        """Split stdout into lines without ever holding more than one line's limit in memory.

        A line over the limit is dropped as soon as it crosses the limit; its remaining bytes
        are counted and discarded until the next newline, so the stream stays usable.
        """
        line = bytearray()
        oversize_length: int | None = None  # set while discarding an oversize line
        while chunk := await stdout.read(_CHUNK_BYTES):
            start = 0
            while True:
                newline = chunk.find(b"\n", start)
                end = len(chunk) if newline == -1 else newline
                if oversize_length is not None:
                    oversize_length += end - start
                elif len(line) + end - start > self._max_message_bytes:
                    oversize_length = len(line) + end - start
                    line = bytearray()
                else:
                    line += chunk[start:end]
                if newline == -1:
                    break
                if oversize_length is not None:
                    limit = self._max_message_bytes
                    self._emit(OversizeMessage(length=oversize_length, limit=limit))
                    oversize_length = None
                else:
                    self._receive(
                        parse_line(
                            bytes(line),
                            max_bytes=self._max_message_bytes,
                            redact_text=self._redact_text,
                        )
                    )
                    line = bytearray()
                start = newline + 1
        if oversize_length is not None:
            limit = self._max_message_bytes
            self._emit(OversizeMessage(length=oversize_length, limit=limit, complete=False))
        elif line:
            self._receive(
                parse_line(
                    bytes(line), max_bytes=self._max_message_bytes, redact_text=self._redact_text
                )
            )
        await self._on_stdout_closed()

    async def _on_stdout_closed(self) -> None:
        exited = await self._wait_exit(_EXIT_WAIT_S)
        if self._stderr_task is not None:
            # Let stderr catch up so stderr_tail() explains the crash to whoever sees it next.
            await asyncio.wait({self._stderr_task}, timeout=_EXIT_WAIT_S)
        exit_code = self._process.returncode
        if exited:
            self._emit(ProcessExited(exit_code=exit_code))
        reason = "server exited" if exited else "server closed stdout"
        self._mark_closed(TransportClosed(exit_code, reason))

    async def _watch_exit(self) -> None:
        # EOF is not proof of exit, and an inherited pipe can delay EOF indefinitely.
        while self._closed is None:
            if await self._wait_exit(0.1):
                break
        if self._closed is not None or self._process.returncode is None:
            return
        await asyncio.wait({self._stdout_task}, timeout=_EXIT_WAIT_S)
        if self._closed is None:
            exit_code = self._process.returncode
            self._emit(ProcessExited(exit_code=exit_code))
            self._mark_closed(TransportClosed(exit_code, "server exited"))

    async def _drain_stderr(self, stderr: asyncio.StreamReader) -> None:
        try:
            while chunk := await stderr.read(_CHUNK_BYTES):
                self._stderr += chunk
                if len(self._stderr) > self._stderr_ring_bytes:
                    del self._stderr[: len(self._stderr) - self._stderr_ring_bytes]
                self._write_stderr_log(self._stderr_decoder.decode(chunk))
        finally:
            self._write_stderr_log(self._stderr_decoder.decode(b"", final=True), final=True)

    def _write_stderr_log(self, text: str, *, final: bool = False) -> None:
        if self._stderr_file is None:
            return
        file = self._stderr_file
        self._stderr_pending += text
        if self._redact_prefix is not None:
            text, self._stderr_pending = self._redact_prefix(self._stderr_pending, final=final)
        else:
            text, self._stderr_pending = self._stderr_pending, ""
        data = text.encode("utf-8", "backslashreplace")
        remaining = self._stderr_max_bytes - self._stderr_written
        try:
            file.write(data[:remaining])
            file.flush()
            self._stderr_written += min(len(data), remaining)
            if len(data) > remaining:
                self.report_violation("stderr_log_capped", "stderr artifact reached its byte limit")
                file.close()
                self._stderr_file = None
        except OSError as exc:
            with contextlib.suppress(OSError):
                file.close()
            self._stderr_file = None
            self.report_violation("stderr_log_failed", type(exc).__name__)
