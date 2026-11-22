"""Make server-provided strings safe to print: no escape sequences, no terminal control."""

import re

# Order matters: the specific forms come before the generic two-character escape.
_ESCAPE_SEQUENCES = re.compile(
    r"\x1b\][^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?"  # OSC (titles, hyperlinks)
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"  # CSI (colors, cursor movement, erase)
    r"|\x1b[PX^_][^\x1b\x9c]*(?:\x1b\\|\x9c)?"  # DCS, SOS, PM, APC strings
    r"|\x1b[ -/]*[0-~]"  # other two-character escapes
)
# C0 and C1 controls except tab (\x09) and newline (\x0a); this includes \r and ESC.
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Bidirectional overrides can make text render differently from what it says.
_BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def sanitize_console(text: str, *, single_line: bool = False, max_len: int | None = None) -> str:
    """Strip ANSI/OSC sequences, control characters and bidi overrides from ``text``.

    Newline and tab survive unless ``single_line`` is set. ``max_len`` truncates the cleaned text
    (with an ellipsis) so a huge server string cannot flood the console.
    """
    if max_len is not None and max_len < 1:
        raise ValueError("max_len must be at least 1")
    cleaned = _ESCAPE_SEQUENCES.sub("", text)
    cleaned = _CONTROLS.sub("", cleaned)
    cleaned = _BIDI.sub("", cleaned)
    if single_line:
        cleaned = cleaned.replace("\n", " ").replace("\t", " ")
    if max_len is not None and len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned
