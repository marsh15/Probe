"""Select this independent suite when uv --project leaves cwd at the repo root."""

from pathlib import Path


def pytest_configure(config):
    project = Path(__file__).resolve().parents[2]
    if (project / "tests").is_dir() and config.args_source == config.ArgsSource.TESTPATHS:
        config.args[:] = [str(project / "tests")]
