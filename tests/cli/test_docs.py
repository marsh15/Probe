"""Every command and option is documented, and the documentation's links resolve."""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location(
    "check_cli_docs", ROOT / "scripts" / "check_cli_docs.py"
)
assert spec is not None and spec.loader is not None
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_every_command_and_option_is_documented() -> None:
    assert check.missing(check.documentation()) == []


def test_the_checker_notices_what_is_missing() -> None:
    problems = check.missing("probe run --url")
    assert any("--llm-budget-usd" in p for p in problems)
    assert any("probe repro" in p for p in problems)


def test_relative_links_in_the_documentation_resolve() -> None:
    broken = []
    for page in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        if page.name == "plan.md":
            continue
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", page.read_text()):
            if "://" in target or target.startswith("mailto:"):
                continue
            if not (page.parent / target).exists():
                broken.append(f"{page.name}: {target}")
    assert broken == []
