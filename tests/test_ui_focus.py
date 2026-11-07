"""NFR-08, keyboard: the page's style draws a visible outline around the focused link, button or expander, in a colour
that reads on both themes (E's FE-E2 audit found Streamlit's own mark on a focused menu link too faint)."""
import pytest

from ui.style import FOCUS_COLOUR, PAGE_CSS

# The page and sidebar backgrounds of Streamlit 1.67's built-in themes, as drawn in the FE-E2 screenshots.
BACKGROUNDS = {"light page": "#FFFFFF", "light sidebar": "#F0F2F6", "dark page": "#0E1117", "dark sidebar": "#262730"}
MIN_FOCUS_CONTRAST = 3.0  # WCAG 2.1 SC 1.4.11: a focus indicator against what surrounds it


def contrast(first: str, second: str) -> float:
    """The WCAG contrast ratio of two "#RRGGBB" colours, from 1 (the same) to 21 (black on white)."""
    def luminance(colour: str) -> float:
        channels = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_focused_links_buttons_and_expanders_get_an_outline():
    for selector in (".stApp a:focus-visible", ".stApp button:focus-visible", ".stApp summary:focus-visible"):
        assert selector in PAGE_CSS
    assert f"outline: 3px solid {FOCUS_COLOUR}" in PAGE_CSS
    assert "font-size: max(1rem, 1em)" in PAGE_CSS  # the 16 px rule is still there


@pytest.mark.parametrize("background", BACKGROUNDS)
def test_the_focus_outline_reads_on_both_themes(background):
    assert contrast(FOCUS_COLOUR, BACKGROUNDS[background]) >= MIN_FOCUS_CONTRAST
