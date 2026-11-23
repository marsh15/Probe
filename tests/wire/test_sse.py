"""The SSE parser, fed directly: framing rules, split chunks and hostile input."""

import pytest

from probe.wire.sse import SseEvent, SseParser


def parse(*chunks: bytes) -> tuple[list[SseEvent], SseParser]:
    parser = SseParser()
    events: list[SseEvent] = []
    for chunk in chunks:
        events += parser.feed(chunk)
    return events, parser


def test_single_event() -> None:
    events, _ = parse(b"event: message\nid: 7\ndata: {}\n\n")
    assert events == [SseEvent(event="message", data="{}", id="7")]


def test_multiline_data_is_joined_with_newlines() -> None:
    events, _ = parse(b"data: a\ndata: b\ndata:\ndata: c\n\n")
    assert [e.data for e in events] == ["a\nb\n\nc"]


@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r"])
def test_every_line_ending_is_accepted(eol: bytes) -> None:
    events, _ = parse(b"data: one" + eol + eol + b"data: two" + eol + eol)
    assert [e.data for e in events] == ["one", "two"]


def test_crlf_split_across_chunks_is_one_line_ending() -> None:
    events, _ = parse(b"data: a\r", b"\n\r", b"\ndata: b\r\n\r\n")
    assert [e.data for e in events] == ["a", "b"]


def test_comments_are_counted_and_never_delivered() -> None:
    events, parser = parse(b": keep-alive\ndata: x\n: another\n\n")
    assert [e.data for e in events] == ["x"]
    assert parser.comments == 2


def test_only_one_leading_space_is_stripped() -> None:
    events, _ = parse(b"data:  two\ndata:none\n\n")
    assert events[0].data == " two\nnone"


def test_line_without_colon_is_a_field_with_empty_value() -> None:
    events, _ = parse(b"data\ndata\n\n")
    assert events[0].data == "\n"


def test_empty_data_still_dispatches() -> None:
    events, _ = parse(b"id: 1\ndata:\n\n")
    assert events == [SseEvent(event=None, data="", id="1")]


def test_block_without_data_is_not_dispatched() -> None:
    events, _ = parse(b"event: ping\nid: 3\n\ndata: x\n\n")
    assert events == [SseEvent(event=None, data="x", id=None)]


def test_fields_do_not_leak_into_the_next_event() -> None:
    events, _ = parse(b"event: a\nid: 1\nretry: 50\ndata: x\n\ndata: y\n\n")
    assert events[1] == SseEvent(event=None, data="y", id=None, retry=None)
    assert events[0].retry == 50


def test_bad_retry_and_nul_id_are_ignored() -> None:
    events, _ = parse(b"retry: 1x\nid: a\x00b\ndata: x\n\n")
    assert events == [SseEvent(event=None, data="x", id=None, retry=None)]


def test_unknown_fields_are_ignored() -> None:
    events, _ = parse(b"bogus: 1\ndata: x\n\n")
    assert [e.data for e in events] == ["x"]


def test_leading_bom_is_dropped() -> None:
    events, _ = parse(b"\xef\xbb\xbfdata: x\n\n")
    assert [e.data for e in events] == ["x"]


def test_multibyte_character_split_across_chunks() -> None:
    raw = "data: héllo €\n\n".encode()
    events, _ = parse(raw[:8], raw[8:])
    assert events[0].data == "héllo €"


def test_invalid_utf8_is_replaced() -> None:
    events, _ = parse(b"data: a\xffb\n\n")
    assert events[0].data == "a�b"


def test_byte_at_a_time_matches_whole_feed() -> None:
    raw = b": hi\r\nevent: message\r\ndata: a\r\ndata: b\r\n\r\ndata: c\n\r\ndata: d\r\r"
    whole, _ = parse(raw)
    pieces, _ = parse(*(raw[i : i + 1] for i in range(len(raw))))
    assert whole == pieces
    assert [e.data for e in whole] == ["a\nb", "c", "d"]


def test_finish_reports_a_cut_off_event() -> None:
    events, parser = parse(b"data: whole\n\ndata: cut")
    assert [e.data for e in events] == ["whole"]
    assert parser.finish() is True


def test_finish_is_clean_after_a_complete_event() -> None:
    _, parser = parse(b"data: x\n\n")
    assert parser.finish() is False


def test_finish_treats_a_trailing_cr_as_a_line_ending() -> None:
    events, parser = parse(b"data: x\r\r")
    assert [e.data for e in events] == ["x"]
    assert parser.finish() is False
