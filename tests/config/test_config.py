"""Mode budgets and the minimal profile."""

from pathlib import Path

import pytest

from probe.config.modes import DEFAULT_MODE, MODES, settings_for
from probe.config.profile import Profile, ProfileError, load_profile, parse_profile


def test_the_mode_table_matches_the_design() -> None:
    assert {m: (s.scan_calls, s.wall_clock_s) for m, s in MODES.items()} == {
        "quick": (150, 90.0),
        "standard": (400, 300.0),
        "deep": (1500, 900.0),
    }
    assert DEFAULT_MODE == "standard"


def test_timeout_scale_stretches_only_time() -> None:
    scaled = settings_for("quick", 2.0)
    assert (scaled.scan_calls, scaled.wall_clock_s) == (150, 180.0)


@pytest.mark.parametrize(("mode", "scale"), [("fast", 1.0), ("quick", 0.0), ("quick", -1.0)])
def test_bad_mode_or_scale_is_refused(mode: str, scale: float) -> None:
    with pytest.raises(ValueError):
        settings_for(mode, scale)


def test_an_empty_profile_is_valid_and_has_a_stable_hash() -> None:
    assert parse_profile("").hash == parse_profile("{}").hash == Profile().hash
    assert len(Profile().hash) == 64


def test_a_full_profile_round_trips() -> None:
    profile = parse_profile(
        """
target: {name: demo, env: {A: "1"}}
checks: {skip: ["safety.*", "protocol.stdout_clean"]}
tools: {danger: {kind: destructive}}
"""
    )
    assert profile.target.name == "demo"
    assert profile.target.env == {"A": "1"}
    assert profile.checks.skip == ["safety.*", "protocol.stdout_clean"]
    assert profile.classifier_view() == {"tools": {"danger": {"kind": "destructive"}}}


def test_the_hash_depends_on_content_not_key_order() -> None:
    a = parse_profile("target: {env: {A: '1', B: '2'}}")
    b = parse_profile("target: {env: {B: '2', A: '1'}}")
    assert a.hash == b.hash != parse_profile("target: {env: {A: '1'}}").hash


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("targt: {}", "targt"),  # a typo must not silently do nothing
        ("target: {env: {A: 1}}", "target.env.A"),  # env values are strings
        ("tools: {x: {kind: big}}", "tools.x.kind"),
        ("- a\n- b", "top level"),
        ("a: [unclosed", "not valid YAML"),
    ],
)
def test_invalid_profiles_are_rejected_with_where(text: str, fragment: str) -> None:
    with pytest.raises(ProfileError, match="profile") as info:
        parse_profile(text)
    assert fragment in str(info.value)


def test_the_shipped_reference_profile_is_valid() -> None:
    profile = load_profile(Path(__file__).parents[2] / "profiles" / "refserver-local.yaml")
    assert profile.target.name == "refserver"


def test_a_missing_profile_file_is_a_profile_error(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="cannot read"):
        load_profile(tmp_path / "nope.yaml")
