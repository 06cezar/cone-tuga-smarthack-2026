"""🔍 Scris mare (B's proposal, 2026-11-08): the whole page larger, for a grandparent or a jury reading from a distance.
Off by default, so the headline and the score stay on the first screen (live check 2); with it off the 16 px rule of
NFR-08 holds."""
from pathlib import Path

import pytest

from ui.style import LARGE_TEXT_CSS, LARGE_TEXT_PERCENT, PAGE_CSS

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def styles(app) -> list[str]:
    return [m.value for m in app.sidebar.markdown if m.value.startswith("<style>")]


def large_text_toggle(app):
    return next(t for t in app.sidebar.toggle if "Scris mare" in t.label or "Large text" in t.label)


def test_large_text_is_off_by_default_so_the_first_screen_keeps_the_headline_and_the_score():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    assert large_text_toggle(app).value is False and LARGE_TEXT_CSS not in styles(app)
    assert "font-size: max(1rem, 1em)" in PAGE_CSS  # the 16 px rule (NFR-08)


def test_turning_it_on_scales_the_whole_page():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    large_text_toggle(app).set_value(True).run()
    assert not app.exception and LARGE_TEXT_CSS in styles(app)
    assert f"font-size: {LARGE_TEXT_PERCENT}%" in LARGE_TEXT_CSS and LARGE_TEXT_PERCENT > 100


def test_the_advanced_toggle_is_still_the_first_one():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    assert "Avansat" in app.toggle[0].label


def test_the_toggle_speaks_english_too():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.radio[0].set_value("English").run()
    assert large_text_toggle(app).label == "🔍 Large text"
