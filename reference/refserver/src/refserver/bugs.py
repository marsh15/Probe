"""Registry of injectable bugs, switched on with `PROBE_REF_BUGS=b17,b31`.

Tool code branches on `is_on("bNN")`. The catalog has 58 ids (b01-b58); a bug
can only be enabled once its branch exists (listed in `IMPLEMENTED`), so a
selfval run never silently scans a clean server while believing a bug is on.
"""

from __future__ import annotations

import os
import re

ENV_VAR = "PROBE_REF_BUGS"
KNOWN: frozenset[str] = frozenset(f"b{n:02d}" for n in range(1, 59))
# Grows as bugs are implemented (T11 and later).
IMPLEMENTED: frozenset[str] = frozenset(
    f"b{n:02d}"
    for n in (*range(1, 31), *range(50, 59))  # b01-b30 and b50-b58
)

_ID = re.compile(r"^b\d{2}$")


class BugConfigError(ValueError):
    """PROBE_REF_BUGS names an unknown or not-yet-implemented bug."""


def parse(spec: str) -> frozenset[str]:
    """Parse a comma list such as "b03, b17"; empty entries are ignored."""
    ids = [part.strip().lower() for part in spec.split(",") if part.strip()]
    unknown = sorted(i for i in ids if not _ID.match(i) or i not in KNOWN)
    if unknown:
        raise BugConfigError(
            f"{ENV_VAR}: unknown bug id(s) {', '.join(unknown)}; valid ids are b01-b58"
        )
    missing = sorted(set(ids) - IMPLEMENTED)
    if missing:
        raise BugConfigError(
            f"{ENV_VAR}: bug(s) {', '.join(missing)} are not implemented in this refserver build"
        )
    return frozenset(ids)


_active: frozenset[str] | None = None


def load(environ: dict[str, str] | None = None) -> frozenset[str]:
    """(Re)read the active set from the environment; raises BugConfigError on bad ids."""
    global _active
    env = os.environ if environ is None else environ
    _active = parse(env.get(ENV_VAR, ""))
    return _active


def active() -> frozenset[str]:
    return load() if _active is None else _active


def is_on(bug_id: str) -> bool:
    """True when `bug_id` is enabled. A typo in tool code fails loudly instead of reading as off."""
    if bug_id not in KNOWN:
        raise KeyError(f"unknown bug id {bug_id!r}")
    return bug_id in active()
