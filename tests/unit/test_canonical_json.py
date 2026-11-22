"""Canonical JSON must be byte-stable: hashes and content addresses depend on it."""

import pytest

from probe.util.canonical_json import canonical_bytes, canonical_json


def test_keys_are_sorted_and_no_whitespace() -> None:
    encoded = canonical_json({"b": 1, "a": [1, 2, {"d": 4, "c": 3}]})
    assert encoded == '{"a":[1,2,{"c":3,"d":4}],"b":1}'


def test_insertion_order_does_not_matter() -> None:
    first = {"x": 1, "y": {"p": 1, "q": 2}}
    second = {"y": {"q": 2, "p": 1}, "x": 1}
    assert canonical_json(first) == canonical_json(second)


def test_list_order_is_preserved() -> None:
    assert canonical_json([3, 1, 2]) == "[3,1,2]"


def test_non_ascii_is_kept_as_utf8_not_escaped() -> None:
    assert canonical_json({"k": "é✓"}) == '{"k":"é✓"}'
    assert canonical_bytes({"k": "é"}) == '{"k":"é"}'.encode()


def test_floats_use_repr() -> None:
    assert canonical_json([1.0, 0.1, 1e22]) == "[1.0,0.1,1e+22]"


def test_scalars() -> None:
    assert canonical_json([True, False, None, 0]) == "[true,false,null,0]"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_are_rejected(bad: float) -> None:
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json({"v": bad})


def test_non_json_types_are_rejected() -> None:
    with pytest.raises(TypeError):
        canonical_json({"v": {1, 2}})


def test_lone_surrogates_from_hostile_servers_do_not_crash_encoding() -> None:
    # A server can send "\ud800" in JSON; hashing it must stay deterministic.
    assert canonical_bytes({"v": "\ud800"}) == canonical_bytes({"v": "\ud800"})
