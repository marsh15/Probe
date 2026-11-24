from __future__ import annotations

import pytest
from refserver import bugs
from refserver.__main__ import main


def test_empty_spec_means_clean() -> None:
    assert bugs.parse("") == frozenset()
    assert bugs.parse(" , ,") == frozenset()
    assert bugs.load({}) == frozenset()
    assert not bugs.is_on("b17")


def test_catalog_has_58_ids() -> None:
    assert len(bugs.KNOWN) == 58
    assert {"b01", "b58"} <= bugs.KNOWN
    assert "b59" not in bugs.KNOWN


@pytest.mark.parametrize("spec", ["b99", "b00", "x1", "b1", "b017", "b03,nope"])
def test_unknown_ids_rejected(spec: str) -> None:
    with pytest.raises(bugs.BugConfigError, match="unknown bug id"):
        bugs.parse(spec)


def test_known_but_unimplemented_rejected() -> None:
    assert "b31" not in bugs.IMPLEMENTED
    with pytest.raises(bugs.BugConfigError, match="not implemented"):
        bugs.parse("b31")


def test_the_implemented_bugs_are_the_expected_set() -> None:
    expected = {f"b{n:02d}" for n in (*range(1, 31), *range(50, 59))}
    assert expected == bugs.IMPLEMENTED
    assert bugs.parse("b01, b56") == {"b01", "b56"}


def test_implemented_bug_is_switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bugs, "IMPLEMENTED", frozenset({"b03", "b17"}))
    assert bugs.load({bugs.ENV_VAR: "B03, b17"}) == {"b03", "b17"}
    assert bugs.is_on("b03")
    assert bugs.is_on("b17")
    assert not bugs.is_on("b31")


def test_is_on_rejects_typos_in_tool_code() -> None:
    with pytest.raises(KeyError):
        bugs.is_on("b99")


def test_cli_refuses_to_start_with_bad_bug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(bugs.ENV_VAR, "b99")
    assert main(["stdio"]) == 2
    assert "unknown bug id(s) b99" in capsys.readouterr().err
