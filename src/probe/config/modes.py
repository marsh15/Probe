"""What each scan mode is allowed to spend (the budget table in the design)."""

from dataclasses import dataclass

from probe.engine.outcomes import Mode


@dataclass(frozen=True, slots=True)
class ModeSettings:
    scan_calls: int  # calls a whole scan may make
    wall_clock_s: float  # soft time budget for the scan


MODES: dict[Mode, ModeSettings] = {
    "quick": ModeSettings(scan_calls=150, wall_clock_s=90.0),
    "standard": ModeSettings(scan_calls=400, wall_clock_s=300.0),
    "deep": ModeSettings(scan_calls=1500, wall_clock_s=900.0),
}
DEFAULT_MODE: Mode = "standard"


def settings_for(mode: str, timeout_scale: float = 1.0) -> ModeSettings:
    """Budget for ``mode``; ``timeout_scale`` stretches the time budget for slow servers."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; choose quick, standard or deep")
    if timeout_scale <= 0:
        raise ValueError("timeout scale must be positive")
    base = MODES[mode]
    return ModeSettings(base.scan_calls, base.wall_clock_s * timeout_scale)
