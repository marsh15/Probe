"""Mode budgets."""

import pytest

from probe.config.modes import DEFAULT_MODE, MODES, settings_for


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
