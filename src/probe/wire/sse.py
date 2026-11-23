"""Incremental Server-Sent Events parser (WHATWG framing) for MCP's streamable HTTP.

It only frames events; size and count limits belong to the caller, which sees every byte
before the parser does. Work per ``feed`` is linear in the chunk, so a hostile stream of
tiny lines costs time proportional to the bytes the caller allows.
"""

import codecs
import re
from dataclasses import dataclass

_LINE_END = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True, slots=True)
class SseEvent:
    """One dispatched event; ``id`` and ``retry`` are only those set within this event."""

    event: str | None
    data: str
    id: str | None = None
    retry: int | None = None


class SseParser:
    def __init__(self) -> None:
        self.comments = 0
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._line: list[str] = []
        self._skip_lf = False  # the last chunk ended in CR, so a leading LF belongs to it
        self._at_start = True
        self._reset_event()

    def _reset_event(self) -> None:
        self._data: list[str] = []
        self._has_data = False
        self._event: str | None = None
        self._id: str | None = None
        self._retry: int | None = None

    def feed(self, chunk: bytes) -> list[SseEvent]:
        text = self._decoder.decode(chunk)
        if not text:
            return []
        if self._at_start:
            self._at_start = False
            text = text.removeprefix("\ufeff")
        if self._skip_lf:
            self._skip_lf = False
            text = text.removeprefix("\n")
        events: list[SseEvent] = []
        position = 0
        for match in _LINE_END.finditer(text):
            piece = text[position : match.start()]
            if self._line:
                self._line.append(piece)
                piece = "".join(self._line)
                self._line.clear()
            self._handle_line(piece, events)
            position = match.end()
            if match.end() == len(text) and match.group() == "\r":
                self._skip_lf = True
        if position < len(text):
            self._line.append(text[position:])
        return events

    def finish(self) -> bool:
        """End of stream: True if an event was cut off (and is discarded, as the spec says)."""
        tail = self._decoder.decode(b"", final=True)
        if tail:
            self._line.append(tail)
        return bool(self._line) or self._has_data

    def _handle_line(self, line: str, events: list[SseEvent]) -> None:
        if not line:
            if self._has_data:
                data = "\n".join(self._data)
                events.append(SseEvent(self._event, data, self._id, self._retry))
            self._reset_event()
            return
        if line.startswith(":"):
            self.comments += 1
            return
        name, colon, value = line.partition(":")
        if colon:
            value = value.removeprefix(" ")
        if name == "data":
            self._data.append(value)
            self._has_data = True
        elif name == "event":
            self._event = value
        elif name == "id":
            if "\x00" not in value:
                self._id = value
        elif name == "retry" and value.isascii() and value.isdigit():
            self._retry = int(value)
