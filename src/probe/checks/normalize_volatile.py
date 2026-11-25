"""Make two results of the same call comparable by masking values that change every time."""

import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ULID = re.compile(r"\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b")
_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_DURATION = re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s)\b")
_KEY = re.compile(r"(.*_at|(.*_)?(timestamp|time|date|elapsed|duration|request_id|trace_id))")
_ONE_DAY_MS = 86_400_000
# Applied in this order: a UUID contains hex runs and a timestamp contains digits+units.
_TEXT_RULES = (
    (_UUID, "<uuid>"),
    (_ISO, "<timestamp>"),
    (_ULID, "<ulid>"),
    (_HEX, "<hex-id>"),
    (_DURATION, "<duration>"),
)


def normalize_volatile(value: Any, *, now: float | None = None) -> Any:
    """A copy of ``value`` with timestamps, ids, durations and epoch times masked.

    Strings are scanned for the patterns; numbers within a day of ``now`` (epoch
    milliseconds) are masked; any value stored under a key that names a time, duration or
    request id is replaced whole.
    """
    now_ms = (time.time() if now is None else now) * 1000
    return _walk(value, now_ms)


def _walk(value: Any, now_ms: float) -> Any:
    if isinstance(value, dict):
        return {
            key: "<volatile>" if _KEY.fullmatch(str(key).lower()) else _walk(item, now_ms)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_walk(item, now_ms) for item in value]
    if isinstance(value, str):
        for pattern, placeholder in _TEXT_RULES:
            value = pattern.sub(placeholder, value)
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        return "<epoch-ms>" if now_ms - _ONE_DAY_MS <= value <= now_ms + _ONE_DAY_MS else value
    return value


async def stable_equal(
    produce: Callable[[], Awaitable[tuple[Any, Any]]], *, now: float | None = None
) -> bool:
    """True if ``produce()``'s two values match once normalized, on either of two attempts.

    A comparison that mismatches is run once more; only a second mismatch counts, which keeps
    flaky servers from producing false findings.
    """
    for _ in range(2):
        actual, expected = await produce()
        if normalize_volatile(actual, now=now) == normalize_volatile(expected, now=now):
            return True
    return False
