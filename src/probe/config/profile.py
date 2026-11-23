"""A scan profile: what the operator knows about the target that Probe cannot discover.

This is the minimal v1 shape: the target's name and environment, checks to skip, and tool kind
overrides for the classifier. Unknown keys are errors, so a typo never silently does nothing.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from probe.util.hashing import canonical_hash


class ProfileError(ValueError):
    """The profile cannot be read or is not valid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetSection(_Strict):
    name: str | None = None
    env: dict[str, str] = Field(default_factory=dict)  # added to the server's environment


class ChecksSection(_Strict):
    skip: list[str] = Field(default_factory=list)  # check id globs, e.g. "safety.*"


class ToolOverride(_Strict):
    kind: Literal["read", "write", "destructive", "exec", "unknown"]


class Profile(_Strict):
    target: TargetSection = Field(default_factory=TargetSection)
    checks: ChecksSection = Field(default_factory=ChecksSection)
    tools: dict[str, ToolOverride] = Field(default_factory=dict)

    @property
    def hash(self) -> str:
        """Content hash for scan keys and reports; equal profiles hash equal."""
        return canonical_hash(self.model_dump(mode="json"))

    def classifier_view(self) -> Mapping[str, Any]:
        """The mapping ``classify_tool`` reads (``tools.<name>.kind``)."""
        return {"tools": {name: {"kind": o.kind} for name, o in self.tools.items()}}


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
