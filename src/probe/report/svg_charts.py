# ruff: noqa: S704 - markup is built from numbers and fixed strings only
"""Inline SVG charts for the HTML report.

Drawn from numbers only, so nothing from the target can reach the markup. Each chart has a
``<title>`` and ``<desc>``; the table next to it carries the same values as text.
"""

from markupsafe import Markup

_WIDTH = 240
_HEIGHT = 12


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def meter(value: float | None, label: str, *, css_class: str = "bar") -> Markup:
    """A horizontal bar for a 0..100 value; ``None`` draws an empty track (nothing to measure)."""
    if value is None:
        text, fill = f"{label}: not measured", 0.0
    else:
        fill = _clamp(value) / 100 * _WIDTH
        text = f"{label}: {value:.1f} out of 100"
    title = Markup("<title>{}</title>").format(text)
    svg = (
        f'<svg class="{css_class}" role="img" viewBox="0 0 {_WIDTH} {_HEIGHT}" '
        f'width="{_WIDTH}" height="{_HEIGHT}" preserveAspectRatio="none">'
    )
    parts = [
        Markup(svg),
        title,
        Markup(f'<rect class="track" x="0" y="0" width="{_WIDTH}" height="{_HEIGHT}" rx="2"/>'),
        Markup(f'<rect class="fill" x="0" y="0" width="{fill:.1f}" height="{_HEIGHT}" rx="2"/>'),
        Markup("</svg>"),
    ]
    return Markup("").join(parts)
