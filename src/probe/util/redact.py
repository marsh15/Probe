"""Keep real credentials out of traces and reports.

Fixture fake secrets are deliberately *not* redacted: they are evidence. Only values the user
marks as real (profile ``secrets``, ``--secret-env``) are passed to a :class:`Redactor`.
"""

from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
)
# Shorter values would shred ordinary text ("ab" appears everywhere); real secrets are longer.
_MIN_SECRET_LEN = 4


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: REDACTED if name.lower() in _SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


class Redactor:
    def __init__(self, secrets: Iterable[str]) -> None:
        # Longest first so a secret that contains another is replaced as a whole.
        unique = {s for s in secrets if len(s) >= _MIN_SECRET_LEN}
        self._secrets = sorted(unique, key=len, reverse=True)

    def redact_text(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def redact_json(self, value: Any) -> Any:
        """Return a copy of ``value`` with secrets replaced in every string and key."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {self.redact_text(key): self.redact_json(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_json(item) for item in value]
        return value
