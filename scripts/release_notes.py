"""Release helper: print the CHANGELOG section for a version, or check that a tag matches.

release_notes.py notes 0.9.0     # the text under "## [0.9.0]"
release_notes.py check v0.9.0    # the tag must equal the version in pyproject.toml
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def section(changelog: str, version: str) -> str:
    """The text under ``## [version]``, up to the next ``## `` heading (ValueError if none)."""
    heading = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.M)
    match = heading.search(changelog)
    if match is None:
        raise ValueError(f"CHANGELOG.md has no section for {version}")
    rest = changelog[match.end() :]
    following = re.search(r"^## ", rest, re.M)
    body = (rest[: following.start()] if following else rest).strip()
    if not body:
        raise ValueError(f"the CHANGELOG section for {version} is empty")
    return body + "\n"


def project_version(root: Path = ROOT) -> str:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def check_tag(tag: str, version: str) -> None:
    if tag.removeprefix("v") != version:
        raise ValueError(f"tag {tag} does not match the package version {version}")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("notes", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        if argv[1] == "notes":
            sys.stdout.write(section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), argv[2]))
        else:
            check_tag(argv[2], project_version())
    except ValueError as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
