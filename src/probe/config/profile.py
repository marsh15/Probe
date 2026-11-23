"""A scan profile: what the operator knows about the target that Probe cannot discover.

The shape follows the design (section 7.4). Unknown keys are errors so a typo never silently does
nothing, and every ``skip`` needs a written reason. ``{token}`` and ``{secret:NAME}`` placeholders
are resolved once per scan by ``resolve_profile``; the profile on disk is never rewritten.
"""

import fnmatch
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from probe.util.hashing import canonical_hash

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PLACEHOLDER = re.compile(r"\{(token|secret:([A-Za-z_][A-Za-z0-9_]*))\}")


class ProfileError(ValueError):
    """The profile cannot be read, is not valid, or cannot be resolved."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HttpTarget(_Strict):
    port: int = Field(default=3000, ge=1, le=65535)
    path: str = "/mcp"

    @field_validator("path")
    @classmethod
    def _absolute(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("must start with /")
        return value


class SecretValue(_Strict):
    value: str
    # Real secrets are redacted from every artifact; fake ones are evidence and stay visible.
    real: bool = False


class TargetSection(_Strict):
    transport: Literal["stdio", "http"] = "stdio"
    image: str | None = None  # sandbox mode: the image holding the server
    command: list[str] | None = None  # inside the image, or the local command
    http: HttpTarget | None = None
    env: dict[str, str] = Field(default_factory=dict)
    secrets: dict[str, SecretValue] = Field(default_factory=dict)  # injected as env variables
    startup_timeout_s: float = Field(default=30.0, gt=0)

    @field_validator("secrets")
    @classmethod
    def _env_names(cls, value: dict[str, SecretValue]) -> dict[str, SecretValue]:
        bad = [name for name in value if not _ENV_NAME.fullmatch(name)]
        if bad:
            raise ValueError(f"not environment variable names: {', '.join(bad)}")
        return value

    @model_validator(mode="after")
    def _http_defaults(self) -> "TargetSection":
        if self.transport == "http" and self.http is None:
            self.http = HttpTarget()
        if self.transport == "stdio" and self.http is not None:
            raise ValueError("http settings need transport: http")
        return self


class FsFixture(_Strict):
    seed_dir: str
    allowed_roots: list[str] = Field(default_factory=list)
    sentinel: bool = True


class HttpFixture(_Strict):
    routes: str | None = None
    aliases: list[str] = Field(default_factory=list)
    env_base_urls: dict[str, str] = Field(default_factory=dict)


class SqliteFixture(_Strict):
    path: str
    seed_sql: str | None = None


class GitFixture(_Strict):
    path: str
    seed_bundle: str | None = None


class FixturesSection(_Strict):
    fs: FsFixture | None = None
    http: HttpFixture | None = None
    sqlite: SqliteFixture | None = None
    git: GitFixture | None = None


class ToolOverride(_Strict):
    kind: Literal["read", "write", "destructive", "exec", "unknown"] | None = None
    idempotent: bool | None = None
    intended_exec: bool | None = None
    allow_private_network: bool | None = None


class ElicitationMatch(_Strict):
    key: str | None = None
    message_regex: str | None = None

    @model_validator(mode="after")
    def _one_condition(self) -> "ElicitationMatch":
        if self.key is None and self.message_regex is None:
            raise ValueError("needs key or message_regex")
        if self.message_regex is not None:
            try:
                re.compile(self.message_regex)
            except re.error as exc:
                raise ValueError(f"message_regex is not a valid regex: {exc}") from exc
        return self


class ElicitationResponse(_Strict):
    action: Literal["accept", "decline", "cancel"]
    content: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _content_only_when_accepting(self) -> "ElicitationResponse":
        if self.content is not None and self.action != "accept":
            raise ValueError("content is only allowed with action: accept")
        return self


class ElicitationAnswer(_Strict):
    match: ElicitationMatch
    response: ElicitationResponse


class Identity(_Strict):
    name: str = Field(min_length=1)
    token: str = Field(min_length=1)


class AuthSection(_Strict):
    type: Literal["none", "bearer"] = "none"
    identities: list[Identity] = Field(
        default_factory=list
    )  # two or more enable cache-scope checks

    @model_validator(mode="after")
    def _consistent(self) -> "AuthSection":
        names = [i.name for i in self.identities]
        if len(names) != len(set(names)):
            raise ValueError("identity names must be unique")
        if self.type == "bearer" and not self.identities:
            raise ValueError("type: bearer needs at least one identity")
        if self.type == "none" and self.identities:
            raise ValueError("identities need type: bearer")
        return self


class ChecksSection(_Strict):
    # check id (or glob) -> why it is skipped; a skip with no reason is refused
    skip: dict[str, str] = Field(default_factory=dict)

    @field_validator("skip")
    @classmethod
    def _reasons(cls, value: dict[str, str]) -> dict[str, str]:
        unexplained = [pattern for pattern, reason in value.items() if not reason.strip()]
        if unexplained:
            raise ValueError(f"skips need a reason: {', '.join(unexplained)}")
        return value


class Profile(_Strict):
    version: Literal[1] = 1
    name: str | None = None
    target: TargetSection = Field(default_factory=TargetSection)
    fixtures: FixturesSection = Field(default_factory=FixturesSection)
    tools: dict[str, ToolOverride] = Field(default_factory=dict)  # keys may be globs
    inputs: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)  # known-good arguments
    elicitation_answers: list[ElicitationAnswer] = Field(default_factory=list)
    auth: AuthSection = Field(default_factory=AuthSection)
    checks: ChecksSection = Field(default_factory=ChecksSection)
    notes: str | None = None

    @property
    def hash(self) -> str:
        """Content hash for scan keys and reports; equal profiles hash equal."""
        return canonical_hash(self.model_dump(mode="json"))

    def override_for(self, tool: str) -> ToolOverride | None:
        """The override for ``tool``: an exact key wins, then the first matching glob."""
        if tool in self.tools:
            return self.tools[tool]
        for pattern, override in self.tools.items():
            if fnmatch.fnmatchcase(tool, pattern):
                return override
        return None

    def classifier_view(self, tool_names: Sequence[str] = ()) -> Mapping[str, Any]:
        """The mapping ``classify_tool`` reads (exact ``tools.<name>.kind``), globs expanded
        against the tools the server actually has."""
        view: dict[str, Any] = {}
        for name in tool_names:
            override = self.override_for(name)
            if override is not None and override.kind is not None:
                view[name] = {"kind": override.kind}
        return {"tools": view}


@dataclass(frozen=True, slots=True)
class ResolvedProfile:
    profile: Profile  # placeholders replaced
    secrets: tuple[str, ...]  # values that must never appear in an artifact

    @property
    def env(self) -> dict[str, str]:
        """The environment the server is started with: ``target.env`` plus ``target.secrets``."""
        env = dict(self.profile.target.env)
        env.update({name: s.value for name, s in self.profile.target.secrets.items()})
        return env


def scan_token(seed: int, profile_hash: str) -> str:
    """The per-scan token: stable for one (seed, profile), different across them."""
    digest = hashlib.sha256(f"probe-token:{seed}:{profile_hash}".encode()).hexdigest()
    return digest[:12]


def _interpolate(
    text: str, token: str, environ: Mapping[str, str], found: list[str], where: str
) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group(1) == "token":
            return token
        name = match.group(2)
        if name not in environ:
            raise ProfileError(f"{where}: secret {name!r} is not set in the environment")
        found.append(environ[name])
        return environ[name]

    return _PLACEHOLDER.sub(replace, text)


def resolve_profile(profile: Profile, *, token: str, environ: Mapping[str, str]) -> ResolvedProfile:
    """Replace ``{token}`` and ``{secret:NAME}`` in the target and auth sections.

    The same token goes everywhere, so the server's configuration and Probe's credentials agree.
    Values taken from the host environment, and secrets marked ``real``, are returned for
    redaction.
    """
    secrets: list[str] = []

    def fill(text: str, where: str) -> str:
        return _interpolate(text, token, environ, secrets, where)

    data = profile.model_dump(mode="json")
    target = data["target"]
    if target["command"] is not None:
        target["command"] = [fill(a, "target.command") for a in target["command"]]
    target["env"] = {k: fill(v, f"target.env.{k}") for k, v in target["env"].items()}
    for name, secret in target["secrets"].items():
        secret["value"] = fill(secret["value"], f"target.secrets.{name}")
        if secret["real"]:
            secrets.append(secret["value"])
    for identity in data["auth"]["identities"]:
        identity["token"] = fill(identity["token"], f"auth.identities.{identity['name']}")
    return ResolvedProfile(
        Profile.model_validate(data), tuple(dict.fromkeys(s for s in secrets if s))
    )


def parse_profile(text: str, source: str = "profile") -> Profile:
    try:
        data = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as exc:
        raise ProfileError(f"{source}: not valid YAML: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ProfileError(f"{source}: the top level must be a mapping")
    try:
        return Profile.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}" for e in exc.errors()
        )
        raise ProfileError(f"{source}: {problems}") from exc


def load_profile(path: Path) -> Profile:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc.strerror}") from exc
    return parse_profile(text, str(path))
