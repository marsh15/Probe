"""Append-only trace of everything sent, received and noticed during a scan (trace.jsonl)."""

import gzip
import json
import re
import shutil
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Literal

from probe.util.redact import Redactor, redact_headers
from probe.wire.errors import WireEvent
from probe.wire.limits import TRACE_BODY_MAX_BYTES, TRACE_METADATA_BYTES, TRACE_SCAN_MAX_BYTES

Direction = Literal["c2s", "s2c", "event"]


@dataclass(frozen=True, slots=True)
class HttpMeta:
    status: int | None
    headers: Mapping[str, str]


def _encode(value: Any) -> bytes:
    # A hostile server can send lone surrogates; backslashreplace turns them back into the
    # \udXXX escapes they arrived as, which keeps the line valid JSON.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8", "backslashreplace")


class Recorder:
    """Writes one JSON record per line; redacts real secrets before anything touches disk.

    Bodies over ``body_max_bytes`` are cut and carry their sha256 and full length. Once
    ``scan_max_bytes`` of body bytes have been written, later records keep metadata only.
    """

    def __init__(
        self,
        path: Path,
        *,
        secrets: Iterable[str] = (),
        body_max_bytes: int = TRACE_BODY_MAX_BYTES,
        scan_max_bytes: int = TRACE_SCAN_MAX_BYTES,
    ) -> None:
        self.path = path
        if body_max_bytes < 0 or scan_max_bytes < 0:
            raise ValueError("trace budgets must be nonnegative")
        self._secrets = tuple(s for s in secrets if len(s) >= 4)
        self._redactor = Redactor(self._secrets)
        self._secret_pattern = (
            re.compile(
                "|".join(re.escape(s) for s in sorted(set(self._secrets), key=len, reverse=True))
            )
            if self._secrets
            else None
        )
        self._body_max = body_max_bytes
        self._scan_max = scan_max_bytes
        self._body_bytes = 0
        self._written_bytes = 0
        self._disk_capped = False
        self.records_dropped = 0
        self._seq = 0
        self._context: dict[str, Any] = {"check_id": None, "case_id": None, "round": None}
        self._file: BinaryIO | None = path.open("ab")
        self.capped = False

    def set_context(
        self, *, check_id: str | None = None, case_id: str | None = None, round: int | None = None
    ) -> None:
        """Tag every following record (including server traffic) until changed."""
        self._context = {"check_id": check_id, "case_id": case_id, "round": round}

    @contextmanager
    def context(
        self, *, check_id: str | None = None, case_id: str | None = None, round: int | None = None
    ) -> Iterator[None]:
        previous = self._context
        self.set_context(check_id=check_id, case_id=case_id, round=round)
        try:
            yield
        finally:
            self._context = previous

    def record(
        self, direction: Direction, transport: str, body: Any, *, http: HttpMeta | None = None
    ) -> int:
        """Append one record and return its sequence number."""
        if self._file is None:
            raise RuntimeError("recorder is closed")
        if self._disk_capped:
            self.records_dropped += 1
            return -1
        # Body first: crossing the scan cap writes a note record before this one.
        try:
            body_fields = self._body_fields(self._redact_body(body))
        except RecursionError:
            body_fields = {"body_omitted": True, "body_note": "body nested too deeply to record"}
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts_ms": time.time_ns() // 1_000_000,
            "dir": direction,
            "transport": transport,
        }
        if http is not None:
            headers = {
                name: self._redactor.redact_text(value)
                for name, value in redact_headers(http.headers).items()
            }
            record["http"] = {"status": http.status, "headers": headers}
        record.update(body_fields)
        record.update(self._context)
        # Context and header names can contain credentials too.
        return self._write(record)

    def redact_text(self, text: str) -> str:
        """Redact a complete string before callers truncate their event excerpts."""
        return self._redactor.redact_text(text)

    def redact_prefix(self, text: str, *, final: bool = False) -> tuple[str, str]:
        """Redact a stream prefix, retaining enough input to recognize split secrets."""
        cut = len(text) if final else max(0, len(text) - max(map(len, self._secrets), default=0))
        # Finish a match across the boundary rather than retaining overlapping matches forever.
        if not final and self._secret_pattern is not None:
            for match in self._secret_pattern.finditer(text):
                if match.start() >= cut:
                    break
                cut = max(cut, match.end())
        return self.redact_text(text[:cut]), text[cut:]

    def _redact_body(self, body: Any) -> Any:
        if isinstance(body, dict):
            return {
                self.redact_text(key) if isinstance(key, str) else key: self._redact_body(value)
                for key, value in body.items()
            }
        if isinstance(body, list):
            return [self._redact_body(value) for value in body]
        return self.redact_text(body) if isinstance(body, str) else body

    def record_event(self, transport: str, event: WireEvent) -> int:
        return self.record("event", transport, event.model_dump(mode="json"))

    def _body_fields(self, body: Any) -> dict[str, Any]:
        encoded = _encode(body)
        over_cap = self._body_bytes + min(len(encoded), self._body_max) > self._scan_max
        if self.capped or over_cap:
            if not self.capped:
                self.capped = True
                self._write_cap_note()
            return {
                "body_omitted": True,
                "body_length": len(encoded),
                "body_sha256": sha256(encoded).hexdigest(),
            }
        if len(encoded) <= self._body_max:
            self._body_bytes += len(encoded)
            return {"body": body}
        self._body_bytes += self._body_max
        return {
            "body": encoded[: self._body_max].decode("utf-8", errors="ignore"),
            "body_truncated": True,
            "body_length": len(encoded),
            "body_sha256": sha256(encoded).hexdigest(),
        }

    def _write_cap_note(self) -> None:
        note = {"kind": "trace_cap_reached", "limit": self._scan_max}
        self._write(
            {
                "seq": self._seq,
                "ts_ms": time.time_ns() // 1_000_000,
                "dir": "event",
                "transport": "recorder",
                "body": note,
                **self._context,
            }
        )

    def _write(self, record: dict[str, Any]) -> int:
        if self._file is None:
            raise RuntimeError("recorder is closed")
        encoded = _encode(self._redact_body(record)) + b"\n"
        # Metadata continues after the body cap, within a separate fixed disk allowance.
        if self._written_bytes + len(encoded) > self._scan_max + TRACE_METADATA_BYTES - 1024:
            self._disk_capped = self.capped = True
            self.records_dropped += 1
            encoded = (
                _encode(
                    {
                        "seq": self._seq,
                        "ts_ms": time.time_ns() // 1_000_000,
                        "dir": "event",
                        "transport": "recorder",
                        "body": {"kind": "trace_metadata_cap_reached"},
                    }
                )
                + b"\n"
            )
        self._file.write(encoded)
        self._file.flush()
        self._written_bytes += len(encoded)
        self._seq += 1
        return self._seq - 1

    def close(self) -> Path:
        """Gzip the trace, delete the plain file, and return the ``.gz`` path. Idempotent."""
        gz_path = self.path.with_name(self.path.name + ".gz")
        if self._file is not None:
            self._file.close()
            self._file = None
            with self.path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            self.path.unlink()
        return gz_path


def read_trace(path: Path) -> list[dict[str, Any]]:
    """Read a trace back (plain or gzipped), one dict per record."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        return [json.loads(line) for line in fh]
