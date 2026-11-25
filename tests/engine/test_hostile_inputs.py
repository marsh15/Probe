"""Hostile payloads must not prevent a complete report from being written."""

import json
from importlib import import_module

import pytest

from probe.checks.normalize_volatile import normalize_volatile
from probe.checks.schema.output import _mirrors
from probe.engine.outcomes import Status
from probe.engine.runscan import RunConfig, run_scan
from probe.report.json_out import write_report
from tests.checks.protocol.harness import ToolsServer
from tests.engine.fakes import FakeRunner


@pytest.mark.parametrize("bad_id", [[], {}])
async def test_unhashable_id_scan_writes_report(tmp_path, monkeypatch, bad_id):
    def runner(cfg, resolved, recorder, *args):
        recorder.record("s2c", "stdio", {"jsonrpc": "2.0", "id": bad_id, "result": {}})
        return FakeRunner(ToolsServer, recorder=recorder)

    monkeypatch.setattr(import_module("probe.engine.runscan"), "_make_runner", runner)
    report = await run_scan(RunConfig(out_dir=tmp_path, only=["schema.cache_fields_present"]))
    assert report.scan.status == "completed"
    assert write_report(report, tmp_path).is_file()
    assert (
        next(r for r in report.results if r.check_id == "schema.cache_fields_present").status
        is Status.PASS
    )


async def test_huge_ttl_scan_records_finding_and_writes_report(tmp_path, monkeypatch):
    huge = 10**400

    def runner(cfg, resolved, recorder, *args):
        return FakeRunner(lambda: ToolsServer(list_extra={"ttlMs": huge}), recorder=recorder)

    monkeypatch.setattr(import_module("probe.engine.runscan"), "_make_runner", runner)
    report = await run_scan(RunConfig(out_dir=tmp_path, only=["schema.cache_ttl_sane"]))
    result = next(r for r in report.results if r.check_id == "schema.cache_ttl_sane")
    assert result.status is Status.FAIL
    assert str(huge) in report.findings[0].title
    assert write_report(report, tmp_path).is_file()


def test_huge_compared_integer_is_preserved():
    assert normalize_volatile({"value": 10**400}) == {"value": 10**400}


@pytest.mark.parametrize("decoder", ["default", "python"])
def test_deep_json_text_does_not_abort_mirror_check(monkeypatch, decoder):
    text = "[" * 20000 + "0" + "]" * 20000
    if decoder == "python":
        # Exercise the recursive stdlib decoder even on Python builds with an iterative C one.
        recursive = json.JSONDecoder()
        recursive.scan_once = json.scanner.py_make_scanner(recursive)
        monkeypatch.setattr(json, "_default_decoder", recursive)
    assert not _mirrors({"structuredContent": {}, "content": [{"text": text}]})


def test_oversize_json_text_is_not_parsed(monkeypatch):
    from probe.wire.limits import MAX_MESSAGE_BYTES

    def loads(*args, **kwargs):
        pytest.fail("oversize mirror text must not be decoded")

    monkeypatch.setattr(json, "loads", loads)
    text = '"' + "x" * MAX_MESSAGE_BYTES + '"'
    assert not _mirrors({"structuredContent": {}, "content": [{"text": text}]})


@pytest.mark.parametrize("secret", ["2026", "http", "1.0", "completed", "schema", "modern", "dual"])
async def test_short_secrets_do_not_corrupt_report_metadata(tmp_path, secret):
    from tests.checks.protocol.harness import mini_argv

    report = await run_scan(
        RunConfig(
            out_dir=tmp_path,
            command=mini_argv(),
            only=["schema.tools_list_valid"],
            target_env={"SECRET": secret, "PROBE_TOOL_NAME": secret},
            secret_env=["SECRET"],
        )
    )
    assert report.scan.status == "completed"
    assert report.tools[0].name == ("[REDACTED]" if len(secret) >= 4 else secret)
    assert write_report(report, tmp_path).is_file()


async def test_runner_creation_failure_closes_recorder(tmp_path, monkeypatch):
    module = import_module("probe.engine.runscan")
    recorders = []
    original = module.Recorder

    def recorder(*args, **kwargs):
        result = original(*args, **kwargs)
        recorders.append(result)
        return result

    monkeypatch.setattr(module, "Recorder", recorder)
    with pytest.raises(module.UsageError):
        await run_scan(RunConfig(out_dir=tmp_path))
    assert recorders[0]._file is None


async def test_http_transport_survives_a_secret_named_http(tmp_path, monkeypatch):
    from probe.engine.outcomes import Transport

    def runner(cfg, resolved, recorder, *args):
        return FakeRunner(ToolsServer, kind=Transport.HTTP, recorder=recorder)

    monkeypatch.setattr(import_module("probe.engine.runscan"), "_make_runner", runner)
    report = await run_scan(
        RunConfig(
            out_dir=tmp_path,
            only=["schema.cache_fields_present"],
            target_env={"SECRET": "http"},
            secret_env=["SECRET"],
        )
    )
    assert report.target.transport is Transport.HTTP
    assert write_report(report, tmp_path).is_file()


async def test_secret_matching_a_tool_flag_preserves_typed_flag(tmp_path, monkeypatch):
    def runner(cfg, resolved, recorder, *args):
        return FakeRunner(
            lambda: ToolsServer(
                tools=[
                    {
                        "name": "url_param",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}},
                        },
                    }
                ]
            ),
            recorder=recorder,
        )

    monkeypatch.setattr(import_module("probe.engine.runscan"), "_make_runner", runner)
    report = await run_scan(
        RunConfig(
            out_dir=tmp_path,
            only=["schema.tools_list_valid"],
            target_env={"SECRET": "url_param"},
            secret_env=["SECRET"],
        )
    )
    assert report.tools[0].name == "[REDACTED]"
    assert report.tools[0].flags == ["url_param"]
    assert write_report(report, tmp_path).is_file()


async def test_deep_server_text_scan_writes_report(tmp_path, monkeypatch):
    from tests.wire.fake_eras import result

    class DeepTextServer(ToolsServer):
        def __init__(self):
            super().__init__(
                tools=[
                    {
                        "name": "read_it",
                        "inputSchema": {"type": "object"},
                        "outputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ]
            )

        def handle(self, msg, headers):
            if msg.get("method") == "tools/call":
                return result(
                    msg["id"],
                    {
                        "resultType": "complete",
                        "structuredContent": {},
                        "content": [{"type": "text", "text": "[" * 20000 + "0" + "]" * 20000}],
                    },
                )
            return super().handle(msg, headers)

    def runner(cfg, resolved, recorder, *args):
        return FakeRunner(DeepTextServer, recorder=recorder)

    recursive = json.JSONDecoder()
    recursive.scan_once = json.scanner.py_make_scanner(recursive)
    monkeypatch.setattr(json, "_default_decoder", recursive)
    monkeypatch.setattr(import_module("probe.engine.runscan"), "_make_runner", runner)
    report = await run_scan(RunConfig(out_dir=tmp_path, only=["schema.structured_text_mirror"]))
    assert report.scan.status == "completed"
    check = next(r for r in report.results if r.check_id == "schema.structured_text_mirror")
    assert check.status is Status.FAIL
    assert write_report(report, tmp_path).is_file()
