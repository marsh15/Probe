"""The trace recorder: append-only, redacted, bounded, gzipped on close."""

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from probe.util.redact import REDACTED
from probe.wire.errors import StdoutNoise
from probe.wire.recorder import HttpMeta, Recorder, read_trace


def test_records_are_sequenced_and_tagged_with_context(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl")
    rec.record("c2s", "stdio", {"id": 1})
    with rec.context(check_id="protocol.x", case_id="c1", round=2):
        rec.record("s2c", "stdio", {"id": 1})
    rec.set_context(check_id="schema.y")
    rec.record_event("stdio", StdoutNoise(excerpt="hi", length=2))
    records = read_trace(rec.close())

    assert [r["seq"] for r in records] == [0, 1, 2]
    assert [r["dir"] for r in records] == ["c2s", "s2c", "event"]
    assert all(r["transport"] == "stdio" and isinstance(r["ts_ms"], int) for r in records)
    assert (records[0]["check_id"], records[0]["case_id"], records[0]["round"]) == (
        None,
        None,
        None,
    )
    assert (records[1]["check_id"], records[1]["case_id"], records[1]["round"]) == (
        "protocol.x",
        "c1",
        2,
    )
    assert records[2]["check_id"] == "schema.y"
    assert records[2]["case_id"] is None
    assert records[2]["body"] == {"kind": "stdout_noise", "excerpt": "hi", "length": 2}
    assert "http" not in records[0]


def test_close_gzips_and_removes_the_plain_file(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    rec = Recorder(path)
    rec.record("c2s", "stdio", {"a": 1})
    gz = rec.close()
    assert gz == tmp_path / "trace.jsonl.gz"
    assert not path.exists()
    with gzip.open(gz, "rt", encoding="utf-8") as fh:
        assert json.loads(fh.readline())["body"] == {"a": 1}
    assert rec.close() == gz  # idempotent
    with pytest.raises(RuntimeError):
        rec.record("c2s", "stdio", {})


def test_auth_headers_and_passed_secrets_are_redacted(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl", secrets=["real-token-123"])
    rec.record(
        "c2s",
        "http",
        {"params": {"key": "real-token-123", "fixture": "sk-fake-fixture-secret"}},
        http=HttpMeta(
            status=200,
            headers={"Authorization": "Bearer x", "Cookie": "a=b", "X-Echo": "real-token-123"},
        ),
    )
    rec.record_event("stdio", StdoutNoise(excerpt="leaked real-token-123", length=21))
    records = read_trace(rec.close())

    assert records[0]["body"] == {"params": {"key": REDACTED, "fixture": "sk-fake-fixture-secret"}}
    assert records[0]["http"] == {
        "status": 200,
        "headers": {"Authorization": REDACTED, "Cookie": REDACTED, "X-Echo": REDACTED},
    }
    assert records[1]["body"]["excerpt"] == f"leaked {REDACTED}"


def test_large_bodies_are_truncated_with_hash_and_length(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl", body_max_bytes=100)
    body = {"data": "x" * 500}
    rec.record("s2c", "stdio", body)
    rec.record("s2c", "stdio", {"small": True})
    records = read_trace(rec.close())

    full = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    big = records[0]
    assert big["body_truncated"] is True
    assert big["body_length"] == len(full.encode())
    assert big["body_sha256"] == hashlib.sha256(full.encode()).hexdigest()
    assert big["body"] == full[:100]
    assert records[1]["body"] == {"small": True}
    assert "body_truncated" not in records[1]


def test_scan_cap_stops_body_capture_and_notes_it_once(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl", scan_max_bytes=50)
    rec.record("c2s", "stdio", {"a": "x" * 20})  # 28 bytes, under the cap
    rec.record("c2s", "stdio", {"b": "y" * 20})  # would exceed it
    rec.record("c2s", "stdio", {"c": 1})
    assert rec.capped
    records = read_trace(rec.close())

    assert records[0]["body"] == {"a": "x" * 20}
    note = [r for r in records if r["dir"] == "event"]
    assert len(note) == 1
    assert note[0]["body"]["kind"] == "trace_cap_reached"
    metadata_only = [r for r in records if r["dir"] == "c2s"][1:]
    assert len(metadata_only) == 2
    for record in metadata_only:
        assert "body" not in record
        assert record["body_omitted"] is True
        assert record["body_length"] > 0
        assert len(record["body_sha256"]) == 64


def test_body_too_deep_to_encode_is_recorded_as_metadata(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl")
    deep: list[object] = []
    for _ in range(10_000):
        deep = [deep]
    rec.record("c2s", "stdio", deep)
    [record] = read_trace(rec.close())
    assert "body" not in record
    assert record["body_omitted"] is True
    assert "nested" in record["body_note"]


def test_read_trace_reads_the_plain_file_while_open(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "trace.jsonl")
    rec.record("c2s", "stdio", {"a": 1})
    assert [r["body"] for r in read_trace(rec.path)] == [{"a": 1}]
    rec.close()
