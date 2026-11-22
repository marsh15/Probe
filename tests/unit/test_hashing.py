"""Hashing helpers: finding ids and scan keys must be stable and sensitive to every input."""

import re

from probe.util.hashing import canonical_hash, finding_id, scan_key, sha256_hex

IDENTITY = {
    "ecosystem": "pypi",
    "package": "demo",
    "version": "1.0",
    "image_digest": "sha256:abc",
    "platform": "linux/arm64",
}


def test_sha256_known_vector() -> None:
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex("abc") == expected
    assert sha256_hex(b"abc") == expected


def test_canonical_hash_ignores_key_order() -> None:
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})


def test_finding_id_is_16_hex_chars_and_deterministic() -> None:
    first = finding_id("safety.ssrf_blocked", "fetch", "ssrf:fetch:url:decimal-ip", IDENTITY)
    again = finding_id("safety.ssrf_blocked", "fetch", "ssrf:fetch:url:decimal-ip", IDENTITY)
    assert first == again
    assert re.fullmatch(r"[0-9a-f]{16}", first)


def test_finding_id_changes_with_every_input() -> None:
    base = finding_id("c", "t", "case", IDENTITY)
    assert finding_id("c2", "t", "case", IDENTITY) != base
    assert finding_id("c", "t2", "case", IDENTITY) != base
    assert finding_id("c", "t", "case2", IDENTITY) != base
    assert finding_id("c", "t", "case", {**IDENTITY, "version": "2.0"}) != base


def test_finding_id_ignores_identity_key_order() -> None:
    reordered = dict(reversed(list(IDENTITY.items())))
    assert finding_id("c", "t", "case", reordered) == finding_id("c", "t", "case", IDENTITY)


def test_finding_id_distinguishes_no_tool_from_empty_tool() -> None:
    assert finding_id("c", None, "case", IDENTITY) != finding_id("c", "", "case", IDENTITY)


def test_finding_id_has_no_delimiter_collisions() -> None:
    assert finding_id("a|b", "c", "d", IDENTITY) != finding_id("a", "b|c", "d", IDENTITY)


def _key(**overrides: object) -> str:
    params: dict[str, object] = {
        "target_identity": IDENTITY,
        "probe_version": "1.0.0",
        "catalog_version": "1",
        "scoring_version": "1.0",
        "profile_hash": "p" * 64,
        "mode": "standard",
        "seed": 1337,
    }
    params.update(overrides)
    return scan_key(**params)  # type: ignore[arg-type]


def test_scan_key_is_full_sha256_and_deterministic() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", _key())
    assert _key() == _key()


def test_scan_key_changes_with_every_input() -> None:
    base = _key()
    for override in (
        {"target_identity": {**IDENTITY, "version": "2"}},
        {"probe_version": "1.0.1"},
        {"catalog_version": "2"},
        {"scoring_version": "1.1"},
        {"profile_hash": "q" * 64},
        {"mode": "deep"},
        {"seed": 1},
    ):
        assert _key(**override) != base, override
