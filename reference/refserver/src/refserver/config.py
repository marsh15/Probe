"""Runtime configuration, read from the environment once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DATA = Path("/data")
# Signs cursors and requestState. Fixed, so two instances of the clean server agree on every
# token they issue; REFSERVER_SECRET overrides it.
DEFAULT_SECRET = b"refserver-default-secret-v1"


def parse_tokens(spec: str) -> dict[str, str]:
    """Parse REFSERVER_TOKENS="alice:<tok>,bob:<tok>" into {token: identity}."""
    tokens: dict[str, str] = {}
    for entry in filter(None, (part.strip() for part in spec.split(","))):
        identity, sep, token = entry.partition(":")
        if not sep or not identity or not token:
            raise ValueError("REFSERVER_TOKENS entries must look like 'name:token'")
        tokens[token] = identity
    return tokens


@dataclass(frozen=True)
class Config:
    data_root: Path
    allowed_root: Path
    db_path: Path
    repo_path: Path
    secret: bytes = field(repr=False)
    backend_url: str = "http://fakehttp"
    backend_token: str | None = field(default=None, repr=False)
    tokens: dict[str, str] = field(default_factory=dict, repr=False)
    issuer_url: str = "http://auth.probe.test"

    @classmethod
    def for_data_root(cls, data_root: Path, **overrides: object) -> Config:
        base: dict[str, object] = {
            "data_root": data_root,
            "allowed_root": data_root / "allowed",
            "db_path": data_root / "db" / "notes.db",
            "repo_path": data_root / "repo",
            "secret": DEFAULT_SECRET,
        }
        base.update(overrides)
        return cls(**base)  # type: ignore[arg-type]

    @classmethod
    def from_env(cls, data_root: Path | None = None) -> Config:
        env = os.environ
        root = data_root or Path(env.get("REFSERVER_DATA", str(DEFAULT_DATA)))
        overrides: dict[str, object] = {}
        if "REFSERVER_ALLOWED_ROOT" in env:
            overrides["allowed_root"] = Path(env["REFSERVER_ALLOWED_ROOT"])
        if "REFSERVER_DB" in env:
            overrides["db_path"] = Path(env["REFSERVER_DB"])
        if "REFSERVER_REPO" in env:
            overrides["repo_path"] = Path(env["REFSERVER_REPO"])
        if env.get("REFSERVER_SECRET"):
            overrides["secret"] = env["REFSERVER_SECRET"].encode()
        if env.get("REFSERVER_BACKEND_URL"):
            overrides["backend_url"] = env["REFSERVER_BACKEND_URL"].rstrip("/")
        if env.get("REFSERVER_BACKEND_TOKEN"):
            overrides["backend_token"] = env["REFSERVER_BACKEND_TOKEN"]
        if env.get("REFSERVER_TOKENS"):
            overrides["tokens"] = parse_tokens(env["REFSERVER_TOKENS"])
        if env.get("REFSERVER_ISSUER"):
            overrides["issuer_url"] = env["REFSERVER_ISSUER"]
        return cls.for_data_root(root, **overrides)
