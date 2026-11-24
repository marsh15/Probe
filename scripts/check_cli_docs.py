"""Fail if a `probe` command or option is not mentioned in the documentation.

Walks the Typer app, so a new command or flag cannot ship undocumented. Documentation is
README.md plus everything under docs/ except the private plan. Commands must appear as
`probe <command>`; every long option must appear as written (for example `--llm-budget-usd`).
"""

import sys
from pathlib import Path
from typing import Any

import typer.main

ROOT = Path(__file__).resolve().parents[1]
IGNORED_OPTIONS = {"--help", "--install-completion", "--show-completion"}


def documentation(root: Path = ROOT) -> str:
    files = [root / "README.md", *sorted((root / "docs").glob("*.md"))]
    return "\n".join(p.read_text(encoding="utf-8") for p in files if p.name != "plan.md")


def walk(command: Any, path: tuple[str, ...]) -> list[tuple[tuple[str, ...], Any]]:
    found = [(path, command)]
    subcommands = getattr(command, "commands", None)
    if subcommands:
        for name, sub in sorted(subcommands.items()):
            found += walk(sub, (*path, name))
    return found


def missing(text: str) -> list[str]:
    from probe.cli.app import app

    root = typer.main.get_command(app)
    problems: list[str] = []
    for path, command in walk(root, ("probe",)):
        if len(path) > 1 and " ".join(path) not in text:
            problems.append(f"command `{' '.join(path)}` is not documented")
        for param in command.params:
            for option in getattr(param, "opts", []):
                if option.startswith("--") and option not in IGNORED_OPTIONS and option not in text:
                    problems.append(f"option {option} of `{' '.join(path)}` is not documented")
    return problems


def main() -> int:
    problems = missing(documentation())
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
