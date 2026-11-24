"""What each injected bug must make Probe report (tests/selfval/expected.yaml)."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CLEAN = "clean"
_CHECK_ID = re.compile(r"[a-z]+\.[a-z0-9_.]+")
TRANSPORTS = ("stdio", "http")


class ExpectedError(ValueError):
    """The expectations file is malformed."""


@dataclass(frozen=True, slots=True)
class Expectation:
    name: str  # "clean" or a bug id
    transports: tuple[str, ...]
    primary: tuple[str, ...]  # checks that must FAIL
    collateral: tuple[str, ...] = ()  # other checks allowed to FAIL

    @property
    def family(self) -> str:
        return self.primary[0].split(".", 1)[0] if self.primary else "-"

    @property
    def allowed(self) -> frozenset[str]:
        return frozenset({*self.primary, *self.collateral})


def _checks(entry: dict[str, Any], key: str, name: str) -> tuple[str, ...]:
    values = entry.get(key) or []
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ExpectedError(f"{name}: {key} must be a list of check ids")
    bad = [v for v in values if not _CHECK_ID.fullmatch(v)]
    if bad:
        raise ExpectedError(f"{name}: not a check id: {', '.join(bad)}")
    return tuple(values)


def load_expected(path: Path) -> dict[str, Expectation]:
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ExpectedError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or CLEAN not in raw:
        raise ExpectedError(f"{path} must be a mapping with a '{CLEAN}' entry")
    found: dict[str, Expectation] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ExpectedError(f"{name}: entry must be a mapping")
        transports = tuple(entry.get("transports") or ())
        if not transports or not set(transports) <= set(TRANSPORTS):
            raise ExpectedError(f"{name}: transports must be a non-empty subset of stdio, http")
        primary = _checks(entry, "primary", name)
        if name != CLEAN and not primary:
            raise ExpectedError(f"{name}: a bug needs at least one primary check")
        found[str(name)] = Expectation(
            str(name), transports, primary, _checks(entry, "allowed_collateral", name)
        )
    return found
