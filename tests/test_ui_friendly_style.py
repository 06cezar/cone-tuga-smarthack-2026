"""The friendly look (ui/style.py): a coloured card per device status, Tuga's speech bubble, the green "Ce-ar fi
dacă repar?" note, large buttons. The theme's own text keeps WCAG AA contrast on every tint, on both themes, and
the keys ui/cards.py builds are plain CSS classes even with hostile scan text (NFR-03, NFR-08)."""
import re
from pathlib import Path

import pytest

from test_ui_focus import contrast
from ui.style import (PAGE_CSS, STATUS_COLOURS, TARGET_HEIGHT, TINT_ALPHA, TUGA_COLOUR, block_key)
from ui.view import status_options

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
THEMES = {"light": ("#FFFFFF", "#31333F"), "dark": ("#0E1117", "#FAFAFA")}  # Streamlit 1.67: page, text
MIN_TEXT_CONTRAST = 4.5  # WCAG 2.1 SC 1.4.3, normal text
MIN_TARGET_PX = 44  # WCAG 2.5.5


def blend(colour: str, background: str, alpha: float) -> str:
    """The colour a translucent tint shows on a background."""
    mix = [round(alpha * int(colour[i:i + 2], 16) + (1 - alpha) * int(background[i:i + 2], 16)) for i in (1, 3, 5)]
    return "#" + "".join(f"{value:02X}" for value in mix)


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def test_every_device_status_has_a_card_colour():
    assert set(STATUS_COLOURS) == {value for value, _label in status_options("ro")}
    for status in STATUS_COLOURS:
        assert f'st-key-card-{status}-' in PAGE_CSS


@pytest.mark.parametrize("theme", THEMES)
def test_the_text_keeps_aa_contrast_on_every_tint(theme):
    page, text = THEMES[theme]
    for colour in [*STATUS_COLOURS.values(), TUGA_COLOUR]:
        assert contrast(text, blend(colour, page, TINT_ALPHA)) >= MIN_TEXT_CONTRAST, (theme, colour)


def test_buttons_and_card_titles_are_easy_to_hit():
    assert int(TARGET_HEIGHT.removesuffix("px")) >= MIN_TARGET_PX
    assert f"summary {{ min-height: {TARGET_HEIGHT}" in PAGE_CSS and f"button {{ min-height: {TARGET_HEIGHT}" in PAGE_CSS


def test_a_key_is_a_plain_css_class_even_from_hostile_text():
    key = block_key("say", "tuga", "10.0.0.5", 23, "[click](https://evil.example)", "TELNET_OPEN")
    assert re.fullmatch(r"[a-z0-9-]+", key) and key.startswith("say-tuga-10-0-0-5-23-")


def test_acasa_draws_the_cards_and_tugas_bubbles():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    assert not app.exception
    ids, blocks = [], [app.main]
    while blocks:
        block = blocks.pop()
        ids.append(str(getattr(block.proto, "id", "")))
        blocks.extend(child for child in getattr(block, "children", {}).values() if hasattr(child, "children"))
    assert any("-card-high-192-168-1-40" in i for i in ids) and any("-card-none-" in i for i in ids)
    assert any("-say-tuga-" in i for i in ids) and any("-gain-" in i for i in ids)


def test_the_guides_pictures_have_no_fullscreen_button():
    """Tapping Tuga or Cone reads aloud (ui/talking.py); Streamlit's fullscreen button on a picture got in the way."""
    from ui.style import PICTURE_TOOLBAR
    assert f".stApp {PICTURE_TOOLBAR} {{ display: none; }}" in PAGE_CSS
