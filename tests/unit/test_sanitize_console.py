"""A hostile server must not be able to drive the user's terminal through its strings."""

import pytest

from probe.util.sanitize_console import sanitize_console


def test_plain_text_is_unchanged() -> None:
    assert sanitize_console("hello wörld ✓") == "hello wörld ✓"


def test_ansi_color_codes_are_stripped() -> None:
    assert sanitize_console("\x1b[31mred\x1b[0m text") == "red text"


def test_csi_cursor_and_erase_sequences_are_stripped() -> None:
    assert sanitize_console("a\x1b[2J\x1b[Hb\x1b[10;20Hc") == "abc"


def test_osc_title_with_bel_terminator_is_stripped() -> None:
    assert sanitize_console("\x1b]0;evil title\x07hi") == "hi"


def test_osc_hyperlink_with_string_terminator_keeps_only_the_label() -> None:
    link = "\x1b]8;;http://evil.example\x1b\\click\x1b]8;;\x1b\\"
    assert sanitize_console(link) == "click"


def test_unterminated_osc_does_not_swallow_following_escape_free_text_forever() -> None:
    assert sanitize_console("ok\x1b]0;never ends") == "ok"


def test_single_char_c1_csi_is_stripped_like_the_two_char_form() -> None:
    assert sanitize_console("\x9b31mX") == "X"


def test_dcs_and_apc_strings_are_stripped() -> None:
    assert sanitize_console("a\x1bPpayload\x1b\\b\x1b_apc\x1b\\c") == "abc"


def test_control_characters_are_removed() -> None:
    assert sanitize_console("a\x00b\x07c\x7fd\x85e\x9ff") == "abcdef"


def test_carriage_return_is_removed_so_lines_cannot_be_overwritten() -> None:
    assert sanitize_console("real\rfake") == "realfake"
    assert sanitize_console("one\r\ntwo") == "one\ntwo"


def test_newline_and_tab_are_kept_by_default() -> None:
    assert sanitize_console("a\n\tb") == "a\n\tb"


def test_single_line_mode_flattens_newlines_and_tabs() -> None:
    assert sanitize_console("a\n\tb", single_line=True) == "a  b"


def test_bidi_override_characters_are_removed() -> None:
    assert sanitize_console("safe\u202eegap\u2066x\u2069") == "safeegapx"


def test_lone_escape_is_removed() -> None:
    assert sanitize_console("a\x1b") == "a"


def test_max_len_truncates_with_an_ellipsis() -> None:
    assert sanitize_console("abcdefghij", max_len=5) == "abcd…"
    assert sanitize_console("abc", max_len=5) == "abc"


def test_max_len_applies_after_stripping() -> None:
    assert sanitize_console("\x1b[31mabc\x1b[0m", max_len=3) == "abc"


@pytest.mark.parametrize("bad", [0, -1])
def test_max_len_must_be_positive(bad: int) -> None:
    with pytest.raises(ValueError, match="max_len"):
        sanitize_console("x", max_len=bad)
