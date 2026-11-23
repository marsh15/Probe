"""The sandbox CLI reports prerequisites and limits collection to requested owned scans."""

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from probe.cli.app import app
from probe.cli.sandbox import sandbox_api
from probe.sandbox.gc import GCResult

runner = CliRunner()


def test_doctor_reports_available_prerequisites_and_optional_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sandbox_api,
        "doctor",
        lambda: {
            "docker_cli": True,
            "daemon": True,
            "linux": True,
            "architecture": "aarch64",
            "runsc": False,
            "public_pool": True,
        },
    )
    result = runner.invoke(app, ["sandbox", "doctor"])
    assert result.exit_code == 0, result.output
    assert "Docker daemon: reachable" in result.output
    assert "aarch64" in result.output
    assert "gVisor (optional): not installed" in result.output


def test_doctor_returns_failure_and_sanitizes_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox_api, "doctor", lambda: {"docker_cli": True, "error": "\x1b[31mdaemon offline"}
    )
    result = runner.invoke(app, ["sandbox", "doctor"])
    assert result.exit_code == 1
    assert "Docker daemon: unreachable" in result.output
    assert "daemon offline" in result.output
    assert "\x1b" not in result.output


def test_gc_passes_scope_age_and_cache_directory_to_owned_collection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def collect(**kwargs: Any) -> GCResult:
        seen.update(kwargs)
        return GCResult(removed=["probe-pub-example"], leases=["example"])

    monkeypatch.setattr(sandbox_api, "collect", collect)
    result = runner.invoke(
        app,
        [
            "sandbox",
            "gc",
            "--scan-id",
            "example",
            "--older-than",
            "7200",
            "--cache-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == {"scan_id": "example", "age_s": 7200.0, "cache_dir": tmp_path}
    assert "Removed 1 sandbox resource(s); released 1 subnet lease(s)." in result.output


@pytest.mark.parametrize("args", [["--older-than", "3599"], ["--scan-id", "../other"]])
def test_gc_rejects_unsafe_inputs_before_calling_docker(
    monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    def forbidden(**kwargs: Any) -> GCResult:
        pytest.fail("invalid arguments reached Docker collection")

    monkeypatch.setattr(sandbox_api, "collect", forbidden)
    assert runner.invoke(app, ["sandbox", "gc", *args]).exit_code == 2


def test_gc_reports_partial_cleanup_as_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox_api, "collect", lambda **kwargs: GCResult(errors=["volume still in use"])
    )
    result = runner.invoke(app, ["sandbox", "gc"])
    assert result.exit_code == 1
    assert "volume still in use" in result.output


def test_gc_reports_daemon_failure_without_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    def collect(**kwargs: Any) -> GCResult:
        raise OSError("daemon offline")

    monkeypatch.setattr(sandbox_api, "collect", collect)
    result = runner.invoke(app, ["sandbox", "gc"])
    assert result.exit_code == 1
    assert "daemon offline" in result.output
    assert "Traceback" not in result.output
