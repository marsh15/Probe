"""Make text from the scanned server safe to put in Markdown (summaries, PR comments)."""

import re

_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~<>&])")
_SPACE = re.compile(r"\s+")


def md_text(value: object, limit: int = 200) -> str:
    """One line of plain text: whitespace collapsed, every Markdown and HTML character escaped."""
    flat = _SPACE.sub(" ", str(value)).strip()
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return _SPECIAL.sub(r"\\\1", flat)
