"""Deterministic seed for the reference server.

    python -m refserver.seed.make_seed --seed 1 --out /data

Layout written under --out (the sentinel layout of plan section 7.3 plus the
server's own state):

    allowed/            readme.md, notes/a.txt, big.log (5 MiB), link_out -> ../secret
    allowed_evil/       evil.txt (sibling sharing the "allowed" prefix)
    secret/SENTINEL     "PROBE-SENTINEL-<token>"
    probe-canary/       empty
    db/notes.db         10,000 notes with ~200-byte bodies
    repo/               small git repository (fixed authors and dates)

The same seed (and token) always produces byte-identical files and the same
git commit ids.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
from pathlib import Path

NOTE_COUNT = 10_000
BODY_BYTES = 200
BIG_LOG_BYTES = 5 * 1024 * 1024
_EPOCH = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)

# Plain ASCII vocabulary so body length in characters equals length in bytes.
WORDS = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
    "meeting",
    "budget",
    "roadmap",
    "launch",
    "review",
    "draft",
    "release",
    "backlog",
    "sprint",
    "retro",
    "customer",
    "invoice",
    "report",
    "server",
    "cache",
    "index",
    "query",
    "schema",
    "migration",
    "rollout",
    "incident",
    "postmortem",
    "metric",
    "alert",
    "deploy",
    "design",
    "sketch",
    "prototype",
    "feedback",
    "survey",
    "interview",
    "summary",
    "decision",
    "action",
    "owner",
    "deadline",
]
TAGS = ("work", "personal", "ideas", "todo", "archive", "urgent", "reading", "travel")

SCHEMA = """
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX notes_created_at ON notes(created_at);
"""


def default_token(seed: int) -> str:
    return hashlib.sha256(f"refserver-seed-{seed}".encode()).hexdigest()[:16]


def _iso(ts: dt.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _body(rng: random.Random) -> str:
    words: list[str] = []
    while len(" ".join(words)) < BODY_BYTES:
        words.append(rng.choice(WORDS))
    return " ".join(words)[:BODY_BYTES].rstrip() + "."


def make_notes_db(path: Path, seed: int) -> None:
    rng = random.Random(seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        rows = []
        ts = _EPOCH
        for i in range(1, NOTE_COUNT + 1):
            ts += dt.timedelta(minutes=rng.randint(30, 150))
            title = f"Note {i}: " + " ".join(rng.choice(WORDS) for _ in range(3))
            tags = sorted(rng.sample(TAGS, rng.randint(0, 3)))
            rows.append((i, title, _body(rng), json.dumps(tags), _iso(ts), _iso(ts)))
        with conn:
            conn.executemany("INSERT INTO notes VALUES (?, ?, ?, ?, ?, ?)", rows)
    finally:
        conn.close()


def make_fs_tree(root: Path, token: str) -> None:
    allowed = root / "allowed"
    (allowed / "notes").mkdir(parents=True)
    (allowed / "readme.md").write_text("# Allowed area\n\nFiles here are readable by read_file.\n")
    (allowed / "notes" / "a.txt").write_text("note a: the quick brown fox\n")
    line_no = 0
    with (allowed / "big.log").open("wb") as fh:
        written = 0
        while written < BIG_LOG_BYTES:
            line = f"2026-01-01T00:00:00Z INFO refserver line={line_no:08d} status=ok\n".encode()
            line = line[: BIG_LOG_BYTES - written]
            fh.write(line)
            written += len(line)
            line_no += 1
    os.symlink("../secret", allowed / "link_out")
    (root / "allowed_evil").mkdir()
    (root / "allowed_evil" / "evil.txt").write_text("outside the allowed root (prefix sibling)\n")
    (root / "secret").mkdir()
    (root / "secret" / "SENTINEL").write_text(f"PROBE-SENTINEL-{token}")
    (root / "probe-canary").mkdir()


def _git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Ref Author",
        "GIT_AUTHOR_EMAIL": "author@refserver.test",
        "GIT_COMMITTER_NAME": "Ref Author",
        "GIT_COMMITTER_EMAIL": "author@refserver.test",
        "TZ": "UTC",
    }
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, capture_output=True)


def make_git_repo(repo: Path) -> None:
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    commits = [
        ("README.md", "# demo\n", "Initial commit"),
        ("src/app.py", "print('hello')\n", "Add app"),
        ("src/app.py", "print('hello, world')\n", "Greet the world"),
        ("CHANGELOG.md", "## 1.0\n- first release\n", "Release 1.0"),
        ("docs/usage.md", "Run app.py\n", "Document usage"),
    ]
    for n, (name, content, message) in enumerate(commits):
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        date = f"2026-01-0{n + 1}T12:00:00+00:00"
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", message, date=date)
        if message == "Release 1.0":
            _git(repo, "tag", "v1.0")
    _git(repo, "branch", "feature/notes", "v1.0")


def make_seed(out: Path, seed: int = 1, token: str | None = None) -> Path:
    """Write the full seed under `out`, which must be absent or empty."""
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty; seed into a fresh directory")
    out.mkdir(parents=True, exist_ok=True)
    make_fs_tree(out, token or default_token(seed))
    make_notes_db(out / "db" / "notes.db", seed)
    make_git_repo(out / "repo")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--token", default=None, help="sentinel token (default: derived from --seed)"
    )
    args = parser.parse_args(argv)
    try:
        make_seed(args.out, args.seed, args.token)
    except FileExistsError as exc:
        print(f"make_seed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
