"""The whole page (ui/app.py) run headless with Streamlit's AppTest: it starts without an error, the headline is at
the top in both languages, and a broken scan shows an error instead of a crash."""
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def run(scan: str | None = None, language: str | None = None):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if language:
        app.radio[0].set_value(language).run()
    if scan:
        app.selectbox[0].set_value(scan).run()
    return app


def first_heading(app) -> str:
    return next(m.value for m in app.markdown if m.value.startswith("## "))


def test_the_first_screen_names_the_most_dangerous_device_and_the_first_step():
    app = run()
    assert not app.exception
    heading = first_heading(app)
    assert "Cel mai periculos" in heading and "Fă asta întâi" in heading


def test_the_page_switches_to_english():
    app = run(language="English")
    assert not app.exception
    assert "Most dangerous" in first_heading(app)


def test_a_broken_scan_shows_an_error_not_a_crash():
    app = run(scan="V7_broken.xml")
    assert not app.exception
    assert app.error and "V7\\_broken" in app.error[0].value
