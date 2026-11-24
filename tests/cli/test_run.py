"""`probe run` end to end through the command line."""

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from probe.cli.app import app
from tests.checks.protocol.harness import mini_argv

runner = CliRunner()
REPORT_SCHEMA = json.loads(
    (Path(__file__).parents[2] / "schemas" / "report.schema.json").read_text()
)


def run(tmp_path: Path, *args: str, target: list[str] | None = None) -> Any:
    argv = ["run", "--out", str(tmp_path / "out"), *args, "--", *(target or mini_argv())]
    return runner.invoke(app, argv)


def report(tmp_path: Path) -> dict[str, Any]:
    data = json.loads((tmp_path / "out" / "report.json").read_text())
    jsonschema.validate(data, REPORT_SCHEMA)
    return data


def test_findings_at_the_threshold_exit_1_and_are_listed(tmp_path: Path) -> None:
    result = run(tmp_path)  # the mini server publishes no cache fields: a high finding
    assert result.exit_code == 1
    assert "schema.tools_list_valid" in result.output
    assert "report:" in result.output
    assert any(r["status"] == "fail" for r in report(tmp_path)["results"])


@pytest.mark.parametrize(
    ("fail_on", "code"), [("none", 0), ("critical", 0), ("high", 1), ("medium", 1), ("low", 1)]
)
def test_fail_on_sets_the_threshold(tmp_path: Path, fail_on: str, code: int) -> None:
    assert run(tmp_path, "--fail-on", fail_on).exit_code == code


def test_skipping_the_failing_checks_makes_the_run_pass(tmp_path: Path) -> None:
    result = run(tmp_path, "--skip", "schema.*", "--skip", "protocol.era_parity")
    assert result.exit_code == 0, result.output
    # info findings (such as the measured startup time) are notes, not failures
    assert [f for f in report(tmp_path)["findings"] if f["severity"] != "info"] == []


def test_an_unavailable_target_exits_3_with_a_report(tmp_path: Path) -> None:
    result = run(tmp_path, target=["/no/such/binary"])
    assert result.exit_code == 3
    assert "target unavailable" in result.output
    assert report(tmp_path)["scan"]["status"] == "target_unavailable"


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["--mode", "warp"], "unknown mode"),
        (["--era", "ancient"], "unknown era"),
        (["--fail-on", "sometimes"], "--fail-on"),
        (["--format", "xml"], "unknown"),
        (["--format", ""], "unknown"),
        (["--target-env", "NOEQUALS"], "KEY=VALUE"),
        (["--profile", "/no/such.yaml"], "cannot read profile"),
        (["--secret-env", "NO_SUCH_VAR_FOR_PROBE"], "unset variables"),
        (["--url", "https://8.8.8.8/mcp"], "either --url or"),  # both a URL and a command
    ],
)
def test_usage_errors_exit_2_with_a_message(tmp_path: Path, args: list[str], fragment: str) -> None:
    result = run(tmp_path, *args)
    assert result.exit_code == 2
    assert fragment in result.output


def test_a_non_local_url_needs_permission(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["run", "--out", str(tmp_path / "o"), "--url", "https://8.8.8.8/mcp"]
    )
    assert result.exit_code == 2
    assert "--i-have-permission" in result.output


def test_no_target_at_all_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--out", str(tmp_path / "o")])
    assert result.exit_code == 2


def test_hostile_server_output_cannot_drive_the_terminal(tmp_path: Path) -> None:
    result = run(tmp_path, "--fail-on", "none", target=mini_argv("--ansi-noise"))
    assert "protocol.stdout_clean" in result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    # The offending text is kept as evidence, with the control codes stripped.
    stdout_finding = next(
        f for f in report(tmp_path)["findings"] if f["check_id"] == "protocol.stdout_clean"
    )
    excerpt = stdout_finding["evidence"]["excerpt"]
    assert "FAKE OUTPUT" in excerpt and "\x1b" not in excerpt and "\x07" not in excerpt


def test_quiet_hides_findings_and_verbose_lists_every_check(tmp_path: Path) -> None:
    quiet = run(tmp_path, "-q")
    assert "schema.tools_list_valid" not in quiet.output and "family" in quiet.output
    verbose = run(tmp_path / "v", "-v")
    assert "protocol.discover_implemented" in verbose.output and "pass" in verbose.output


def test_target_env_and_profile_reach_the_server(tmp_path: Path) -> None:
    profile = tmp_path / "p.yaml"
    profile.write_text("name: from-profile\n")
    result = run(tmp_path, "--profile", str(profile), "--fail-on", "none")
    assert result.exit_code == 0
    assert report(tmp_path)["target"]["name"] == "from-profile"


# --- the reference server (the plan's acceptance scenarios) ------------------------------


def refserver_args(stdio_command: Any, *extra: str) -> list[str]:
    argv, env = stdio_command
    pairs = [f"{k}={v}" for k, v in env.items() if k in ("PYTHONPATH", "REFSERVER_DATA")]
    flags = [a for pair in pairs for a in ("--target-env", pair)]
    return [*flags, *extra, "--", *argv]


def test_the_clean_reference_server_passes(tmp_path: Path, stdio_command: Any) -> None:
    result = runner.invoke(
        app, ["run", "--out", str(tmp_path / "out"), *refserver_args(stdio_command)]
    )
    assert result.exit_code == 0, result.output
    data = report(tmp_path)
    assert data["target"]["era"]["negotiated_version"] == "2026-07-28"
    assert "Grade A" in result.output
    assert data["score"]["overall"] == 100.0
    assert 0 < data["score"]["coverage"] < 100
    assert data["scoring_profile"] == "full"
    assert not [r for r in data["results"] if r["status"] in ("fail", "error")]


def test_an_injected_bug_is_reported_and_fails_the_run(tmp_path: Path, stdio_command: Any) -> None:
    args = refserver_args(
        stdio_command, "--fail-on", "medium", "--target-env", "PROBE_REF_BUGS=b03"
    )
    result = runner.invoke(app, ["run", "--out", str(tmp_path / "out"), *args])
    assert result.exit_code == 1, result.output
    failed = {r["check_id"] for r in report(tmp_path)["results"] if r["status"] == "fail"}
    assert "protocol.result_type_present" in failed
    assert os.path.exists(tmp_path / "out" / "trace.jsonl.gz")


def test_server_text_cannot_inject_terminal_hyperlinks_or_markup(tmp_path: Path) -> None:
    import asyncio
    import io

    from rich.console import Console

    from probe.cli.summary import render_summary
    from probe.engine.runscan import RunConfig, run_scan

    hostile = "[link=https://evil.test]click[/link] [bold red]ALERT[/bold red]"
    cfg = RunConfig(
        out_dir=tmp_path / "out", command=mini_argv(), target_env={"PROBE_TOOL_NAME": hostile}
    )
    scanned = asyncio.run(run_scan(cfg))
    out = io.StringIO()
    render_summary(scanned, Console(file=out, force_terminal=True, width=200), verbose=1)
    text = out.getvalue()
    assert "\x1b]8;" not in text  # no OSC 8 hyperlink was created
    assert "[link=https://evil.test]" in text  # the markup is shown literally instead


@pytest.mark.parametrize("value", ["-1", "101", "nan", "NaN", "inf", "-inf"])
def test_min_score_requires_a_finite_percentage_before_launch(tmp_path: Path, value: str) -> None:
    result = run(tmp_path, "--min-score", value, target=["/no/such/binary"])
    assert result.exit_code == 2
    assert "--min-score" in result.output and "finite" in result.output
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    ("minimum", "fail_on", "code"), [("0", "none", 0), ("100", "none", 1), ("0", "high", 1)]
)
def test_min_score_and_fail_on_both_apply(
    tmp_path: Path, minimum: str, fail_on: str, code: int
) -> None:
    result = run(tmp_path, "--min-score", minimum, "--fail-on", fail_on)
    assert result.exit_code == code, result.output
    score = report(tmp_path)["score"]
    assert 0 < score["overall"] < 100
    assert f"Grade {score['grade']}" in result.output
    assert "coverage" in result.output and "caps" in result.output


def test_null_score_fails_even_a_zero_threshold_but_unavailable_keeps_exit_3(
    tmp_path: Path,
) -> None:
    empty = run(tmp_path, "--only", "nothing.*", "--min-score", "0", "--fail-on", "none")
    assert empty.exit_code == 1, empty.output
    assert report(tmp_path)["score"]["overall"] is None
    assert "ungraded" in empty.output and "coverage 0.0%" in empty.output
    unavailable = run(tmp_path / "u", "--min-score", "100", target=["/no/such/binary"])
    assert unavailable.exit_code == 3, unavailable.output
    assert report(tmp_path / "u")["score"]["grade"] is None


def test_null_score_without_a_threshold_is_ok(tmp_path: Path) -> None:
    result = run(tmp_path, "--only", "nothing.*", "--fail-on", "none")
    assert result.exit_code == 0
    assert report(tmp_path)["score"]["coverage"] == 0


@pytest.mark.parametrize("kind,code", [("sandbox", 5), ("internal", 4), ("usage", 2)])
def test_min_score_keeps_error_exit_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, code: int
) -> None:
    from importlib import import_module

    from probe.engine.runscan import SandboxUnavailable, UsageError

    async def broken_scan(config: Any) -> Any:
        errors = {"sandbox": SandboxUnavailable, "internal": RuntimeError, "usage": UsageError}
        raise errors[kind]("test error")

    monkeypatch.setattr(import_module("probe.cli.run"), "run_scan", broken_scan)
    result = run(tmp_path, "--min-score", "100")
    assert result.exit_code == code


def test_html_report_is_written_by_default_and_json_only_skips_it(tmp_path: Path) -> None:
    run(tmp_path, "--fail-on", "none")
    page = (tmp_path / "out" / "report.html").read_text()
    assert "<h1>" in page and "report.json" in page
    only_json = tmp_path / "j"
    run(only_json, "--fail-on", "none", "--format", "json")
    assert (only_json / "out" / "report.json").exists()
    assert not (only_json / "out" / "report.html").exists()


def test_every_format_can_be_written_in_one_run(tmp_path: Path) -> None:
    run(
        tmp_path,
        "--fail-on",
        "none",
        "--format",
        "json,html,sarif,md,badge",
        "--sarif-anchor",
        "x.md",
    )
    out = tmp_path / "out"
    for name in ("report.json", "report.html", "report.sarif", "summary.md", "badge.json"):
        assert (out / name).read_text(), name
    assert json.loads((out / "report.sarif").read_text())["version"] == "2.1.0"
    assert json.loads((out / "badge.json").read_text())["label"] == "probe"


def test_llm_flag_without_a_key_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = run(tmp_path, "--llm")
    assert result.exit_code == 2 and "ANTHROPIC_API_KEY" in result.output
