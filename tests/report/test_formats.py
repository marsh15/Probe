"""SARIF, badge, markdown summary and ``probe diff``."""

import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from syrupy.assertion import SnapshotAssertion
from typer.testing import CliRunner

from probe.cli.app import app
from probe.report.badge import badge_json
from probe.report.diff import diff_reports, render_diff_md
from probe.report.markdown import summary_md
from probe.report.models import ScanReport
from probe.report.sarif import to_sarif

DATA = Path(__file__).parent / "data"
runner = CliRunner()
SARIF_SCHEMA = json.loads((DATA / "sarif-2.1.0.schema.json").read_text())


def load(name: str) -> ScanReport:
    return ScanReport.model_validate_json((DATA / f"{name}.json").read_text())


def edit(name: str, change: Any) -> ScanReport:
    data = json.loads((DATA / f"{name}.json").read_text())
    change(data)
    return ScanReport.model_validate(data)


# --- SARIF -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["clean", "buggy"])
def test_sarif_validates_against_the_official_schema(name: str) -> None:
    jsonschema.validate(to_sarif(load(name)), SARIF_SCHEMA)


def test_sarif_has_one_run_with_every_check_as_a_rule() -> None:
    from probe.checks.registry import REGISTRY

    sarif = to_sarif(load("buggy"))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "probe"
    ids = [r["id"] for r in driver["rules"]]
    assert ids == sorted(c.meta.id for c in REGISTRY)
    rule = next(r for r in driver["rules"] if r["id"] == "protocol.result_type_present")
    assert rule["helpUri"] == "https://probe-mcp.github.io/checks/protocol.result_type_present/"
    assert rule["properties"]["security-severity"] == "5.5"
    assert rule["help"]["markdown"] and rule["fullDescription"]["text"]


def test_sarif_results_are_failures_only_with_levels_anchor_and_fingerprint() -> None:
    report = load("buggy")
    results = to_sarif(report, anchor="docs/mcp.md")["runs"][0]["results"]
    failing = [f for f in report.findings if f.severity.value != "info"]
    assert len(results) == len(failing) > 0  # info observations are not alerts
    by_id = {r["partialFingerprints"]["probeFindingId"]: r for r in results}
    for finding in failing:
        result = by_id[finding.finding_id]
        assert result["ruleId"] == finding.check_id
        assert (
            result["level"]
            == {"high": "error", "critical": "error", "medium": "warning", "low": "note"}[
                finding.severity.value
            ]
        )
        assert (
            f"probe repro report.json --finding {finding.finding_id}" in result["message"]["text"]
        )
        location = result["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "docs/mcp.md"
        assert location["physicalLocation"]["region"]["startLine"] == 1
        if finding.tool:
            assert location["logicalLocations"] == [{"name": finding.tool, "kind": "function"}]


def test_clean_report_has_no_sarif_results() -> None:
    assert to_sarif(load("clean"))["runs"][0]["results"] == []


# --- badge -------------------------------------------------------------------------------


def test_badge_shows_grade_and_score_with_the_grade_colour() -> None:
    assert badge_json(load("buggy")) == {
        "schemaVersion": 1, "label": "probe", "message": "B · 84.9", "color": "green",
    }  # fmt: skip
    assert badge_json(load("clean"))["color"] == "brightgreen"


def test_badge_coverage_style_and_ungraded() -> None:
    cov = badge_json(load("buggy"), style="coverage")
    assert cov["label"] == "probe coverage" and cov["message"] == "54.2%"

    def ungraded(data: dict[str, Any]) -> None:
        data["score"].update(overall=None, grade=None, coverage=0)
        for fam in data["score"]["families"].values():
            fam.update(score=None, applicable_weight=0, failed_weight=0)

    assert badge_json(edit("clean", ungraded))["message"] == "not graded"


@pytest.mark.parametrize(
    ("grade", "colour"),
    [("A", "brightgreen"), ("B", "green"), ("C", "yellow"), ("D", "orange"), ("F", "red")],
)
def test_badge_colours(grade: str, colour: str) -> None:
    def change(data: dict[str, Any]) -> None:
        data["score"]["grade"] = grade

    assert badge_json(edit("buggy", change))["color"] == colour


# --- markdown ----------------------------------------------------------------------------


def test_summary_markdown_snapshot(snapshot: SnapshotAssertion) -> None:
    assert summary_md(load("buggy")) == snapshot(name="buggy")
    assert summary_md(load("clean")) == snapshot(name="clean")


def test_markdown_neutralises_hostile_text() -> None:
    hostile = "<img src=x onerror=alert(1)>|[x](javascript:alert(1))\n# heading"

    def change(data: dict[str, Any]) -> None:
        data["findings"][0]["title"] = hostile
        data["findings"][0]["tool"] = hostile
        data["target"]["name"] = hostile

    text = summary_md(edit("buggy", change))
    other = render_diff_md(diff_reports(load("clean"), edit("buggy", change)))
    for out in (text, other):
        assert not re.search(r"(?<!\\)[<>]", out.replace("<=", ""))  # every angle bracket escaped
        assert not re.search(r"(?<!\\)\]\(", out)  # no live link syntax
        assert "\n# " not in out  # the hostile text cannot start a heading


def test_summary_lists_at_most_ten_findings() -> None:
    def change(data: dict[str, Any]) -> None:
        base = data["findings"][0]
        data["findings"] = [{**base, "finding_id": f"{i:016x}"} for i in range(25)]

    text = summary_md(edit("buggy", change))
    assert text.count("probe repro") <= 10 and "15 more" in text


# --- diff --------------------------------------------------------------------------------


def test_diff_between_clean_and_buggy(snapshot: SnapshotAssertion) -> None:
    diff = diff_reports(load("clean"), load("buggy"))
    assert diff["score"]["overall"] == {"base": 100.0, "head": 84.9, "delta": -15.1}
    assert diff["grade"] == {"base": "A", "head": "B"}
    assert len(diff["new"]) == 5 and diff["fixed"] == []
    assert render_diff_md(diff) == snapshot(name="clean_to_buggy")


def test_diff_back_shows_fixed_findings_and_no_new_ones() -> None:
    diff = diff_reports(load("buggy"), load("clean"))
    assert diff["new"] == [] and len(diff["fixed"]) == 5
    assert diff["score"]["overall"]["delta"] == 15.1


def test_diff_of_a_report_with_itself_is_empty() -> None:
    diff = diff_reports(load("buggy"), load("buggy"))
    assert diff["new"] == diff["fixed"] == [] and diff["score"]["overall"]["delta"] == 0


def test_findings_match_across_targets_by_check_tool_and_case() -> None:
    def change(data: dict[str, Any]) -> None:
        for f in data["findings"]:
            f["finding_id"] = "0" * 16  # a rebuilt image has a different identity

    diff = diff_reports(load("buggy"), edit("buggy", change))
    assert diff["new"] == diff["fixed"] == []


# --- command line ------------------------------------------------------------------------


def test_report_command_writes_each_format(tmp_path: Path) -> None:
    source = DATA / "buggy.json"
    for fmt, name in (
        ("sarif", "r.sarif"),
        ("md", "r.md"),
        ("badge", "r.json"),
        ("html", "r.html"),
    ):
        out = tmp_path / name
        result = runner.invoke(app, ["report", str(source), "--format", fmt, "--out", str(out)])
        assert result.exit_code == 0, result.output
        assert out.read_text()
    jsonschema.validate(json.loads((tmp_path / "r.sarif").read_text()), SARIF_SCHEMA)


def test_report_command_rejects_a_bad_input(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", str(tmp_path / "none.json"), "--format", "md"])
    assert result.exit_code == 2
    (tmp_path / "bad.json").write_text("{}")
    assert (
        runner.invoke(app, ["report", str(tmp_path / "bad.json"), "--format", "md"]).exit_code == 2
    )


def test_diff_command_prints_markdown_or_json() -> None:
    base, head = str(DATA / "clean.json"), str(DATA / "buggy.json")
    md = runner.invoke(app, ["diff", base, head])
    assert md.exit_code == 0 and "84.9" in md.output
    js = runner.invoke(app, ["diff", base, head, "--format", "json"])
    assert json.loads(js.output)["grade"] == {"base": "A", "head": "B"}
    assert runner.invoke(app, ["diff", base, "missing.json"]).exit_code == 2
