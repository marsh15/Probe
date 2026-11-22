"""Tests for the version command."""

from typer.testing import CliRunner

from probe.cli.app import app

runner = CliRunner()


def test_version() -> None:
    """Test that the version command outputs the correct version."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "probe-mcp 0.1.0.dev0" in result.stdout
