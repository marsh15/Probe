"""`probe checks list|show` and the generated catalog document."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from probe.checks.docs import builtin_checks, render_markdown
from probe.cli.app import app

runner = CliRunner()
CATALOG = Path(__file__).parents[2] / "docs" / "checks.md"


def test_docs_checks_md_is_not_stale() -> None:
    """Regenerate with: uv run probe checks list --format md > docs/checks.md"""
    assert CATALOG.read_text() == render_markdown()


def test_the_cli_md_output_is_the_document() -> None:
    result = runner.invoke(app, ["checks", "list", "--format", "md"])
    assert result.exit_code == 0
    assert result.output == CATALOG.read_text()


def test_every_check_is_documented_once() -> None:
    text = render_markdown()
    for check in builtin_checks():
        assert text.count(f"### {check.meta.id}\n") == 1
        assert f"(#{check.meta.id.replace('.', '')})" in text
    assert f"Probe ships {len(builtin_checks())} checks" in text


def test_every_check_explains_itself() -> None:
    for check in builtin_checks():
        meta = check.meta
        assert len(meta.rationale) > 40 and len(meta.remediation) > 20, meta.id
        assert meta.title and meta.spec_refs, meta.id


def test_modes_are_listed_in_natural_order() -> None:
    assert "| quick, standard, deep |" in render_markdown()
    assert "| deep |" in render_markdown()  # era_parity runs only in deep mode


def test_list_table_shows_every_id_in_full() -> None:
    result = runner.invoke(app, ["checks", "list"], env={"COLUMNS": "60"})
    assert result.exit_code == 0
    for check in builtin_checks():
        assert check.meta.id in result.output  # never truncated, even on a narrow terminal


def test_list_json_is_machine_readable_and_filters_by_family() -> None:
    everything = json.loads(runner.invoke(app, ["checks", "list", "--format", "json"]).output)
    schema = json.loads(
        runner.invoke(app, ["checks", "list", "--format", "json", "--family", "schema"]).output
    )
    assert len(everything) == len(builtin_checks())
    assert {c["family"] for c in schema} == {"schema"} and len(schema) == 11
    assert all(
        {"id", "severity", "phase", "rationale", "remediation"} <= set(c) for c in everything
    )


def test_show_describes_one_check() -> None:
    result = runner.invoke(app, ["checks", "show", "protocol.origin_validated"])
    assert result.exit_code == 0
    assert "### protocol.origin_validated" in result.output
    assert "Why it matters" in result.output and "How to fix" in result.output


def test_show_an_unknown_check_suggests_the_nearest() -> None:
    result = runner.invoke(app, ["checks", "show", "protocol.origin_valid"])
    assert result.exit_code == 2
    assert "protocol.origin_validated" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["list", "--format", "xml"],
        ["list", "--family", "nope"],
        ["list", "--format", "md", "--family", "schema"],
    ],
)
def test_bad_arguments_exit_2(args: list[str]) -> None:
    assert runner.invoke(app, ["checks", *args]).exit_code == 2
