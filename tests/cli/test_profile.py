"""`probe profile validate` and `probe profile init`."""

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from probe.cli.app import app
from probe.config.profile import parse_profile
from probe.engine.runscan import RunConfig, run_scan
from tests.checks.protocol.harness import mini_argv

runner = CliRunner()
PROFILES = Path(__file__).parents[2] / "profiles"


def test_validate_accepts_the_shipped_profiles() -> None:
    paths = [str(p) for p in sorted(PROFILES.glob("*.yaml"))]
    result = runner.invoke(app, ["profile", "validate", *paths])
    assert result.exit_code == 0, result.output
    assert result.output.count("ok ") == len(paths) >= 3
    assert "2 identities" in result.output


def test_validate_reports_every_problem_and_exits_2(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text("name: ok\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("targt: {}\nauth: {type: bearer}\n")
    result = runner.invoke(app, ["profile", "validate", str(good), str(bad), "/no/such.yaml"])
    assert result.exit_code == 2
    assert f"ok {good}" in result.output
    assert "targt" in result.output and "at least one identity" in result.output
    assert "cannot read profile" in result.output


def test_init_prints_a_valid_blank_profile() -> None:
    result = runner.invoke(app, ["profile", "init"])
    assert result.exit_code == 0
    profile = parse_profile(result.output)
    assert profile.name == "my-server" and profile.tools == {}


def test_init_writes_a_file_and_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    target = tmp_path / "p.yaml"
    assert runner.invoke(app, ["profile", "init", "--out", str(target)]).exit_code == 0
    assert parse_profile(target.read_text()).version == 1
    again = runner.invoke(app, ["profile", "init", "--out", str(target)])
    assert again.exit_code == 2 and "--force" in again.output
    assert runner.invoke(app, ["profile", "init", "--out", str(target), "--force"]).exit_code == 0


async def test_init_from_a_report_lists_every_tool_with_its_inferred_kind(tmp_path: Path) -> None:
    import asyncio

    report = await run_scan(
        RunConfig(
            out_dir=tmp_path / "out",
            command=mini_argv(),
            target_env={"PROBE_TOOL_NAME": "delete_everything"},
        )
    )
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json())
    result = await asyncio.to_thread(
        runner.invoke, app, ["profile", "init", "--from-report", str(path)]
    )
    assert result.exit_code == 0, result.output
    profile = parse_profile(result.output)
    assert profile.tools["delete_everything"].kind == "destructive"
    assert "heuristic" in result.output  # the evidence for the guess is shown as a comment


async def test_a_hostile_tool_name_cannot_break_out_of_the_generated_yaml(tmp_path: Path) -> None:
    import asyncio

    hostile = 'evil": {kind: exec}\nauth: {type: bearer}\n#'
    report = await run_scan(
        RunConfig(
            out_dir=tmp_path / "out", command=mini_argv(), target_env={"PROBE_TOOL_NAME": hostile}
        )
    )
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json())
    result = await asyncio.to_thread(
        runner.invoke, app, ["profile", "init", "--from-report", str(path)]
    )
    assert result.exit_code == 0, result.output
    data = yaml.safe_load(result.output)
    assert "auth" not in data  # the name stayed a quoted key; it did not add a section
    assert list(data["tools"]) == [hostile]
    assert data["tools"][hostile] == {"kind": "exec"}


def test_init_from_an_unreadable_report_exits_2(tmp_path: Path) -> None:
    broken = tmp_path / "r.json"
    broken.write_text(json.dumps({"not": "a report"}))
    assert runner.invoke(app, ["profile", "init", "--from-report", str(broken)]).exit_code == 2
    assert runner.invoke(app, ["profile", "init", "--from-report", "/no/such"]).exit_code == 2
