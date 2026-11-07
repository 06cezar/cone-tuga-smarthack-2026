"""Acasă's main feature (Mihnea's directive, 2026-11-08): choosing the scan, in a large box right under the title and
before the headline. The box holds the same two widgets as before (the example list and the upload) inside
st.container(key=PICKER_KEY), which ui/style.py styles. The theme's own text keeps WCAG AA contrast on the box's
tint, on both themes (NFR-08)."""
from pathlib import Path

import pytest

from test_ui_focus import contrast
from ui.pages.home import TEXT
from ui.style import FOCUS_COLOUR, PAGE_CSS, PICKER_KEY, PICKER_TINT_ALPHA

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
LANGUAGES = {"ro": "Română", "en": "English"}  # the sidebar's language switch
# Streamlit 1.67's built-in themes: the page background and the normal text colour.
THEMES = {"light": ("#FFFFFF", "#31333F"), "dark": ("#0E1117", "#FAFAFA")}
MIN_TEXT_CONTRAST = 4.5  # WCAG 2.1 SC 1.4.3, normal text


def run(lang: str):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if lang != "ro":
        app.radio[0].set_value(LANGUAGES[lang]).run()
    assert not app.exception
    return app


def picker_box(app):
    """The block st.container(key=PICKER_KEY) drew: AppTest gives a keyed block an id ending in "-<key>"."""
    blocks = [app.main]
    while blocks:
        block = blocks.pop()
        if str(getattr(block.proto, "id", "")).endswith(f"-{PICKER_KEY}"):
            return block
        blocks.extend(child for child in getattr(block, "children", {}).values() if hasattr(child, "children"))
    return None


def tinted(background: str) -> str:
    """The colour the box shows: FOCUS_COLOUR at PICKER_TINT_ALPHA over the page background."""
    mixed = [round((1 - PICKER_TINT_ALPHA) * int(background[i:i + 2], 16) + PICKER_TINT_ALPHA
                   * int(FOCUS_COLOUR[i:i + 2], 16)) for i in (1, 3, 5)]
    return "#" + "".join(f"{channel:02X}" for channel in mixed)


@pytest.mark.parametrize("lang", LANGUAGES)
def test_the_example_list_and_the_upload_are_in_the_picker_box(lang):
    box = picker_box(run(lang))
    assert box is not None
    assert [s.label for s in box.selectbox] == [TEXT[lang]["pick"]]
    assert len(box.get("file_uploader")) == 1
    assert f"### {TEXT[lang]['start']}" in [m.value for m in box.markdown]


@pytest.mark.parametrize("lang", LANGUAGES)
def test_the_picker_comes_right_after_the_title_and_before_the_headline(lang):
    """The person first sees where to choose a scan, then the answer to "which device is the most dangerous"."""
    app = run(lang)
    assert app.title[0].value == TEXT[lang]["title"]
    shown = [m.value for m in app.markdown]
    start = shown.index(f"### {TEXT[lang]['start']}")
    headline = next(i for i, value in enumerate(shown) if value.startswith("## "))
    assert start < headline


def test_the_page_style_draws_the_picker_box_and_keeps_the_16_px_rule():
    assert f".st-key-{PICKER_KEY}" in PAGE_CSS and f"border: 2px solid {FOCUS_COLOUR}" in PAGE_CSS
    assert "font-size: max(1rem, 1em)" in PAGE_CSS


@pytest.mark.parametrize("theme", THEMES)
def test_text_on_the_picker_box_keeps_wcag_aa_contrast(theme):
    background, text = THEMES[theme]
    assert contrast(text, tinted(background)) >= MIN_TEXT_CONTRAST
