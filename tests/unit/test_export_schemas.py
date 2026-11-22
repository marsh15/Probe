"""The committed JSON schemas must match the models (CI runs the same check)."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "export_schemas.py"


def test_report_schema_is_up_to_date() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_check_fails_when_the_schema_is_stale(tmp_path: Path) -> None:
    (tmp_path / "report.schema.json").write_text("{}\n")
    result = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [sys.executable, str(SCRIPT), "--check", "--out-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 1
    assert "stale" in result.stdout
