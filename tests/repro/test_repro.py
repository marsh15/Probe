"""Repro bundles, ``probe repro`` and ``--export-script``, end to end on the local refserver."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from probe.cli.app import app
from probe.repro.bundle import ReproBundle, load_bundle
from probe.repro.export_script import export_script

runner = CliRunner()


def scan(tmp_path: Path, stdio_command: Any, bugs: str = "b03") -> dict[str, Any]:
    argv, env = stdio_command
    flags = [
        a
        for k, v in env.items()
        if k in ("PYTHONPATH", "REFSERVER_DATA")
        for a in ("--target-env", f"{k}={v}")
    ]
    result = runner.invoke(
        app,
        [
            "run", "--out", str(tmp_path / "out"), "--fail-on", "none", *flags,
            "--target-env", f"PROBE_REF_BUGS={bugs}", "--only", "protocol.result_type_present",
            "--", *argv,
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    return json.loads((tmp_path / "out" / "report.json").read_text())


def first_finding(report: dict[str, Any]) -> dict[str, Any]:
    assert report["findings"], "the injected bug should have produced a finding"
    return report["findings"][0]


def test_every_finding_gets_a_bundle_and_a_one_line_command(
    tmp_path: Path, stdio_command: Any
) -> None:
    report = scan(tmp_path, stdio_command)
    finding = first_finding(report)
    fid = finding["finding_id"]
    assert finding["repro"]["command"] == f"probe repro report.json --finding {fid}"
    bundle = load_bundle(tmp_path / "out" / "report.json", fid)
    assert bundle.finding_id == fid and bundle.check_id == finding["check_id"]
    assert bundle.target.command is not None and bundle.run.target_env["PROBE_REF_BUGS"] == "b03"
    assert bundle.steps == finding["repro"]["steps"]


def test_bundle_keeps_secret_names_but_never_their_values(
    tmp_path: Path, stdio_command: Any
) -> None:
    argv, env = stdio_command
    result = runner.invoke(
        app,
        [
            "run", "--out", str(tmp_path / "out"), "--fail-on", "none",
            "--target-env", f"PYTHONPATH={env['PYTHONPATH']}",
            "--target-env", f"REFSERVER_DATA={env['REFSERVER_DATA']}",
            "--target-env", "PROBE_REF_BUGS=b03", "--target-env", "MY_TOKEN=hunter2-secret",
            "--secret-env", "MY_TOKEN", "--only", "protocol.result_type_present", "--", *argv,
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    text = "".join(p.read_text() for p in (tmp_path / "out" / "repro").rglob("repro.json"))
    assert text and "hunter2-secret" not in text and "MY_TOKEN" in text


def test_repro_reports_reproduced_when_the_bug_is_still_there(
    tmp_path: Path, stdio_command: Any
) -> None:
    fid = first_finding(scan(tmp_path, stdio_command))["finding_id"]
    result = runner.invoke(app, ["repro", str(tmp_path / "out" / "report.json"), "--finding", fid])
    assert result.exit_code == 0, result.output
    assert "REPRODUCED" in result.output and "NOT REPRODUCED" not in result.output


def test_repro_reports_not_reproduced_against_a_fixed_target(
    tmp_path: Path, stdio_command: Any
) -> None:
    fid = first_finding(scan(tmp_path, stdio_command))["finding_id"]
    result = runner.invoke(
        app,
        [
            "repro", str(tmp_path / "out" / "report.json"), "--finding", fid,
            "--target-env", "PROBE_REF_BUGS=",
        ],
    )  # fmt: skip
    assert result.exit_code == 1, result.output
    assert "NOT REPRODUCED" in result.output


def test_repro_refuses_an_unknown_finding_and_a_missing_report(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["repro", str(tmp_path / "nope.json"), "--finding", "abc"])
    assert missing.exit_code == 2 and "report" in missing.output.lower()


def test_unknown_finding_lists_the_ones_that_exist(tmp_path: Path, stdio_command: Any) -> None:
    fid = first_finding(scan(tmp_path, stdio_command))["finding_id"]
    result = runner.invoke(
        app, ["repro", str(tmp_path / "out" / "report.json"), "--finding", "0" * 16]
    )
    assert result.exit_code == 2 and fid in result.output


# --- the standalone script ---------------------------------------------------------------


def bundle_with(**overrides: Any) -> ReproBundle:
    base: dict[str, Any] = {
        "finding_id": "f" * 16,
        "check_id": "demo.check",
        "tool": "echo",
        "case_id": "demo:case",
        "severity": "high",
        "title": "demo",
        "probe_version": "0",
        "catalog_version": "0",
        "target": {"name": "t", "transport": "stdio", "command": ["cat"]},
        "run": {"mode": "standard", "seed": 0, "era": "modern", "negotiated_version": "2026-07-28"},
        "profile": {"version": 1},
        "steps": [
            {"kind": "request", "method": "tools/call", "params": {"name": "echo", "arguments": {}}}
        ],
        "expect": {"x": "y"},
    }
    return ReproBundle.model_validate({**base, **overrides})


def test_stdio_script_feeds_modern_requests_with_meta_and_runs() -> None:
    script = export_script(bundle_with())
    assert script.startswith("#!/bin/sh") and "demo.check" in script
    out = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=30, check=True
    ).stdout  # `cat` is the target, so the requests come straight back
    line = json.loads(out.strip().splitlines()[0])
    assert line["method"] == "tools/call" and line["params"]["name"] == "echo"
    assert "_meta" in line["params"] and line["id"] == 1


def test_legacy_stdio_script_handshakes_first() -> None:
    legacy = {"mode": "standard", "seed": 0, "era": "legacy", "negotiated_version": "2025-06-18"}
    script = export_script(bundle_with(run=legacy))
    out = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=30, check=True
    ).stdout.splitlines()
    methods = [json.loads(line)["method"] for line in out if line.strip()]
    assert methods[:2] == ["initialize", "notifications/initialized"] and "tools/call" in methods


def test_sandboxed_script_uses_docker_and_http_script_uses_curl() -> None:
    docker = export_script(
        bundle_with(target={"name": "t", "transport": "stdio", "image": "img:1", "image_digest": "sha256:ab", "command": None})  # noqa: E501
    )  # fmt: skip
    assert "docker run -i --rm" in docker and "img" in docker
    http = export_script(
        bundle_with(target={"name": "t", "transport": "http", "url": "http://127.0.0.1:9/mcp"})
    )  # fmt: skip
    assert "curl" in http and "Mcp-Method: tools/call" in http and "http://127.0.0.1:9/mcp" in http


def test_script_is_honest_when_the_finding_has_no_recorded_steps() -> None:
    script = export_script(bundle_with(steps=[]))
    assert "no wire requests were recorded" in script.lower()


def test_hostile_values_are_quoted_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    evil = f"'; touch {marker}; echo '"
    script = export_script(
        bundle_with(steps=[{"kind": "request", "method": "tools/call", "params": {"name": evil}}])
    )
    subprocess.run(["/bin/sh", "-c", script], capture_output=True, timeout=30, check=True)  # noqa: S603
    assert not marker.exists()


def test_export_script_option_writes_an_executable_file(tmp_path: Path, stdio_command: Any) -> None:
    fid = first_finding(scan(tmp_path, stdio_command))["finding_id"]
    target = tmp_path / "repro.sh"
    result = runner.invoke(
        app,
        ["repro", str(tmp_path / "out" / "report.json"), "--finding", fid,
         "--export-script", str(target), "--no-run"],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert target.stat().st_mode & 0o100 and target.read_text().startswith("#!/bin/sh")


@pytest.mark.parametrize("flag", ["--no-run"])
def test_no_run_skips_the_replay(tmp_path: Path, stdio_command: Any, flag: str) -> None:
    fid = first_finding(scan(tmp_path, stdio_command))["finding_id"]
    result = runner.invoke(
        app,
        ["repro", str(tmp_path / "out" / "report.json"), "--finding", fid, flag,
         "--export-script", str(tmp_path / "r.sh")],
    )  # fmt: skip
    assert result.exit_code == 0 and "REPRODUCED" not in result.output


@pytest.mark.parametrize("version", ["2026-07-28", "2025-06-18"])
def test_http_script_talks_to_a_real_server_in_both_eras(seeded_data: Path, version: str) -> None:
    from tests.conftest import launch_http

    with launch_http(seeded_data) as url:
        bundle = bundle_with(
            target={"name": "t", "transport": "http", "url": url},
            run={"mode": "standard", "seed": 0, "era": "auto", "negotiated_version": version},
            steps=[{"kind": "request", "method": "tools/list", "params": {}}],
        )
        out = subprocess.run(  # noqa: S603
            ["/bin/sh", "-c", export_script(bundle)],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout  # fmt: skip
    assert "HTTP/" in out and '"tools"' in out and "notes_get" in out


def test_stdio_script_shows_the_bug_on_the_real_refserver(stdio_command: Any) -> None:
    argv, env = stdio_command

    def answer(bugs: str) -> str:
        bundle = bundle_with(
            target={"name": "t", "transport": "stdio", "command": argv},
            run={
                "mode": "standard", "seed": 0, "era": "auto", "negotiated_version": "2026-07-28",
                "target_env": {**env, "PROBE_REF_BUGS": bugs},
            },
            steps=[{"kind": "request", "method": "tools/list", "params": {}}],
        )  # fmt: skip
        return subprocess.run(  # noqa: S603
            ["/bin/sh", "-c", export_script(bundle)],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout  # fmt: skip

    assert "resultType" in answer("") and "notes_get" in answer("")
    buggy = answer("b03")
    assert "notes_get" in buggy and "resultType" not in buggy


def test_bundle_redacts_secrets_in_command_url_env_and_export(tmp_path: Path) -> None:
    from probe.config.profile import parse_profile
    from probe.engine.runscan import RunConfig
    from probe.report.models import ScanReport
    from probe.repro.bundle import bundle_for
    from tests.report.test_formats import load

    secret = "fake-private-token-0123456789"
    cfg = RunConfig(
        out_dir=tmp_path,
        command=["server", secret],
        url=f"http://localhost/?key={secret}",
        secret_env=["TOKEN"],
        target_env={"TOKEN": secret, "OTHER": secret},
        profile=parse_profile(
            "version: 1\ntarget:\n  secrets:\n    KEY: {value: " + secret + ", real: true}\n"
        ),
    )
    scan_report = load("buggy")
    assert isinstance(scan_report, ScanReport)
    bundle = bundle_for(scan_report.findings[0], scan_report, cfg)
    assert secret not in bundle.model_dump_json()
    assert secret not in export_script(bundle)


def test_export_io_error_is_usage_error(tmp_path, monkeypatch):
    from importlib import import_module

    monkeypatch.setattr(import_module("probe.cli.repro"), "load_bundle", lambda *a: bundle_with())
    result = runner.invoke(
        app,
        [
            "repro",
            str(tmp_path / "report.json"),
            "--finding",
            "f" * 16,
            "--export-script",
            str(tmp_path / "missing" / "out.sh"),
            "--no-run",
        ],
    )
    assert result.exit_code == 2, result.output
    assert "script" in result.output.lower()


def test_export_disk_failure_is_internal_error(tmp_path, monkeypatch):
    from importlib import import_module

    module = import_module("probe.cli.repro")
    monkeypatch.setattr(module, "load_bundle", lambda *a: bundle_with())

    def failed_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", failed_write)
    result = runner.invoke(
        app,
        [
            "repro",
            str(tmp_path / "report.json"),
            "--finding",
            "f" * 16,
            "--export-script",
            str(tmp_path / "out.sh"),
            "--no-run",
        ],
    )
    assert result.exit_code == 4
    assert "disk full" in result.output
