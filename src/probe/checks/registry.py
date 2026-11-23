"""All known checks, in the order the engine runs them."""

import re
from collections.abc import Iterator
from importlib.metadata import entry_points
from typing import get_args

from probe.checks.base import Check
from probe.engine.outcomes import Phase

ENTRY_POINT_GROUP = "probe.checks"
PHASE_ORDER: tuple[str, ...] = get_args(Phase)
_ID = re.compile(r"[a-z]+\.[a-z0-9_]+(\.[a-z0-9_]+)*")


class RegistryError(ValueError):
    """A check cannot be registered (bad id, duplicate, missing meta)."""


class Registry:
    def __init__(self) -> None:
        self._checks: dict[str, type[Check]] = {}
        self.plugin_errors: list[tuple[str, str]] = []  # (entry point name, what went wrong)

    def register[T: type[Check]](self, cls: T) -> T:
        meta = getattr(cls, "meta", None)
        if meta is None:
            raise RegistryError(f"{cls.__name__} has no meta")
        if not _ID.fullmatch(meta.id) or meta.id.split(".", 1)[0] != meta.family.value:
            raise RegistryError(f"check id {meta.id!r} must look like '<family>.<name>'")
        existing = self._checks.get(meta.id)
        if existing is not None and existing is not cls:
            raise RegistryError(
                f"check id {meta.id!r} is already registered by {existing.__name__}"
            )
        self._checks[meta.id] = cls
        return cls

    def get(self, check_id: str) -> type[Check]:
        try:
            return self._checks[check_id]
        except KeyError:
            raise KeyError(f"no check {check_id!r}") from None

    def __contains__(self, check_id: str) -> bool:
        return check_id in self._checks

    def __len__(self) -> int:
        return len(self._checks)

    def __iter__(self) -> Iterator[type[Check]]:
        """Checks in run order: by phase, then by id, so every scan sees the same order."""
        return iter(
            sorted(
                self._checks.values(),
                key=lambda c: (PHASE_ORDER.index(c.meta.phase), c.meta.id),
            )
        )

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> None:
        """Register checks from installed packages.

        An entry point may name a Check subclass, or a module whose import registers checks.
        One that fails to load is recorded in ``plugin_errors`` and skipped, so a broken
        plugin cannot stop a scan.
        """
        for entry in entry_points(group=group):
            try:
                loaded = entry.load()
                if isinstance(loaded, type) and issubclass(loaded, Check):
                    self.register(loaded)
            except Exception as exc:
                self.plugin_errors.append((entry.name, f"{type(exc).__name__}: {exc}"))


REGISTRY = Registry()
register = REGISTRY.register
