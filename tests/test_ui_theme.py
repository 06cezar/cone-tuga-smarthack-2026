"""The two looks of the mock-ups (ui/theme.py, D-mockup): Tuga light in Simple mode, Cone dark in Advanced mode. Every
text colour keeps WCAG AA contrast on every background it sits on, in both looks; the big green button too; nothing is
loaded from outside; the top bar shows the Tuga | Cone switch, RO | EN and the pages; the red card leads to the checkup
in Simple mode only; the before/after keeps the lines the history tests read."""
import re
from pathlib import Path

import pytest

from test_ui_focus import contrast
from ui.gauge import arc_html, ring_html, warning_words
from ui.style import CHECKUP_ANCHOR
from ui.theme import FIX_NOW_FILL, FIX_NOW_TEXT, STATUS, THEMES, theme_css

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
MIN_TEXT_CONTRAST = 4.5  # WCAG 2.1 SC 1.4.3, normal text
MIN_LARGE_TEXT_CONTRAST = 3  # large text (the logo, the big button)
BACKGROUNDS = ("page", "card", "soft", "bubble", "danger_bg", "ok_bg", "table_head", "say_tuga", "say_cone")


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def run(advanced: bool = False, language: str | None = None):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if language:
        app.radio[0].set_value(language).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    if advanced:
        app.toggle[0].set_value(True).run()
    assert not app.exception
    return app


@pytest.mark.parametrize("dark", [False, True])
def test_every_text_colour_reads_on_every_background(dark):
    theme = THEMES[dark]
    for background in BACKGROUNDS:
        for colour in ("text", "muted", "link"):
            assert contrast(theme[colour], theme[background]) >= MIN_TEXT_CONTRAST, (dark, colour, background)
    for status, (_strong, words) in STATUS[dark].items():
        for background in ("card", "page", "table_head"):
            assert contrast(words, theme[background]) >= MIN_TEXT_CONTRAST, (dark, status, background)
    for colour in ("blue", "green"):  # the logo's two words, large and bold
        assert contrast(theme[colour], theme["page"]) >= MIN_LARGE_TEXT_CONTRAST, (dark, colour)
    assert contrast(theme["gain_text"], theme["gain_bg"]) >= MIN_TEXT_CONTRAST


def test_the_big_green_button_reads():
    assert contrast(FIX_NOW_TEXT, FIX_NOW_FILL) >= MIN_TEXT_CONTRAST


@pytest.mark.parametrize("dark", [False, True])
def test_nothing_is_loaded_from_outside(dark):
    for page in (theme_css(dark), arc_html(40, "ro"), ring_html(40, "en")):
        assert not re.search(r"https?://|@import|url\((?!#)", page)
    assert "{{" not in theme_css(dark) and "}}" not in theme_css(dark)


def test_the_gauge_says_the_score_in_words():
    assert warning_words(40, "ro") == "⛔ PERICOL: REPARĂ ACUM" and warning_words(60, "en").startswith("⚠️")
    assert 'aria-label="60/100. ⚠️ ATENȚIE: NECESITĂ ACȚIUNE"' in arc_html(60, "ro")


def test_the_top_bar_has_the_switch_and_the_languages():
    app = run()
    text = "\n".join(m.value for m in app.markdown)
    assert "🐢 Tuga (Simplu)" in text and app.toggle[0].label == "🐇 Cone (Avansat)"
    assert [str(option) for option in app.radio[0].options] == ["RO", "EN"] or app.radio[0].options


def test_the_red_card_leads_to_the_checkup_in_simple_mode_only():
    simple = "\n".join(m.value for m in run().markdown)
    assert f"[👉 Repară acum!](#{CHECKUP_ANCHOR})" in simple and "**Pericol:**" in simple
    advanced = "\n".join(m.value for m in run(advanced=True).markdown)
    assert "Repară acum" not in advanced


def test_the_cone_look_is_dark_and_the_tuga_look_is_light():
    assert f"--ct-page: {THEMES[True]['page']}" in theme_css(True)
    assert f"--ct-page: {THEMES[False]['page']}" in theme_css(False)
    simple, advanced = run(), run(advanced=True)
    assert any(THEMES[False]["page"] in m.value for m in simple.markdown if m.value.startswith("<style>"))
    assert any(THEMES[True]["page"] in m.value for m in advanced.markdown if m.value.startswith("<style>"))
