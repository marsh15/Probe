"""probe selfval: reading expectations, judging results, and a real fast run."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from probe.cli.app import app
from probe.selfval.expected import ExpectedError, load_expected
from probe.selfval.report import judge, render_markdown
from probe.selfval.runner import Job, JobResult

REPO = Path(__file__).parents[2]
EXPECTED = REPO / "tests" / "selfval" / "expected.yaml"

YAML = """
clean: {transports: [stdio], primary: []}
b01: {transports: [stdio], primary: [protocol.a], allowed_collateral: [schema.b]}
b02: {transports: [stdio, http], primary: [schema.c], allowed_collateral: []}
"""


def expectations(tmp_path: Path, text: str = YAML) -> dict:
    path = tmp_path / "expected.yaml"
    path.write_text(text)
    return load_expected(path)


def done(bug: str, transport: str, seed: int, *failed: str) -> JobResult:
    return JobResult(Job(bug, transport, seed), "completed", failed)


def test_the_real_expectations_load() -> None:
    wanted = load_expected(EXPECTED)
    assert "clean" in wanted and len(wanted) > 30
    assert wanted["b20"].collateral == ("behavior.survives_campaign",)
    assert wanted["b14"].transports == ("http",)


@pytest.mark.parametrize(
    "text",
    [
        "b01: {transports: [stdio], primary: [protocol.a]}",  # no clean entry
        "clean: {transports: [stdio], primary: []}\nb01: {transports: [ftp], primary: [a.b]}",
        "clean: {transports: [stdio], primary: []}\nb01: {transports: [stdio], primary: []}",
        "clean: {transports: [stdio], primary: []}\nb01: {transports: [stdio], primary: [NOPE]}",
        "[]",
    ],
)
def test_bad_expectations_are_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(ExpectedError):
        expectations(tmp_path, text)


def test_detected_means_the_primary_check_failed_on_every_scan(tmp_path: Path) -> None:
    wanted = expectations(tmp_path)
    results = [
        done("clean", "stdio", 1),
        done("b01", "stdio", 1, "protocol.a"),
        done("b01", "stdio", 2, "protocol.a", "schema.b"),  # allowed collateral
        done("b02", "stdio", 1, "schema.c"),
        done("b02", "http", 1),  # missed on one transport
    ]
    summary = judge(wanted, results)
    rows = {r.bug: r for r in summary.rows}
    assert rows["b01"].detected and not rows["b01"].unexpected
    assert not rows["b02"].detected and rows["b02"].detected_jobs == 1
    assert (summary.implemented, summary.detected) == (2, 1)
    assert not summary.passed


def test_unexpected_failures_and_false_positives_are_reported(tmp_path: Path) -> None:
    wanted = expectations(tmp_path)
    results = [
        done("clean", "stdio", 1, "schema.z"),
        done("b01", "stdio", 1, "protocol.a", "operability.q"),
        done("b02", "stdio", 1, "schema.c"),
        done("b02", "http", 1, "schema.c"),
    ]
    summary = judge(wanted, results)
    assert summary.false_positives == ["schema.z"]
    assert summary.unexpected == {"b01": ["operability.q"]}
    assert summary.detected == 2 and not summary.passed


def test_a_scan_that_did_not_complete_is_not_a_detection(tmp_path: Path) -> None:
    wanted = expectations(tmp_path)
    broken = JobResult(Job("b01", "stdio", 1), "target_unavailable", ("protocol.a",))
    summary = judge(wanted, [done("clean", "stdio", 1), broken])
    [row] = summary.rows
    assert not row.detected and row.problems


def test_everything_detected_and_nothing_else_failing_passes(tmp_path: Path) -> None:
    wanted = expectations(tmp_path)
    results = [
        done("clean", "stdio", 1),
        done("b01", "stdio", 1, "protocol.a"),
        done("b02", "stdio", 1, "schema.c"),
        done("b02", "http", 1, "schema.c"),
    ]
    summary = judge(wanted, results)
    assert summary.passed
    text = render_markdown(summary, mode="deep", seeds=[1], backend="local")
    assert "Detected 2 of 2" in text and "| b01 | protocol |" in text
    assert summary.by_family == {"protocol": (1, 1), "schema": (1, 1)}


def test_unknown_bug_ids_are_a_usage_error() -> None:
    result = CliRunner().invoke(app, ["selfval", "--bugs", "b99", "--expected", str(EXPECTED)])
    assert result.exit_code == 2


def test_a_real_local_run_detects_a_bug_and_keeps_the_clean_server_clean(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "selfval",
            "--local",
            "--bugs",
            "b10",
            "--seeds",
            "1",
            "--mode",
            "quick",
            "--transports",
            "stdio",
            "--workers",
            "2",
            "--out",
            str(tmp_path),
            "--expected",
            str(EXPECTED),
            "--profiles",
            str(REPO / "profiles"),
            "--refserver-src",
            str(REPO / "reference" / "refserver" / "src"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Detected 1 of 1" in result.output
    assert (tmp_path / "selfval" / "report.json").is_file()
    assert (tmp_path / "selfval" / "report.md").is_file()
