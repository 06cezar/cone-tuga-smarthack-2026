"""FE-A3's two lines on Acasă (ui/pages/home.py), run headless with AppTest on the real page: a readable scan shown is
counted once per session, only with statistics on, a broken scan never, and "Șterge istoricul meu" (on Istoric) also
empties the
session's set, so after opting in again the same scan counts again (the insights contract's "Deleting")."""
from pathlib import Path

import pytest

from conetuga.insights import set_enabled, status, top_codes
from ui.insights_panel import SEEN_KEY

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
DELETE_LABEL = "🗑️ Șterge istoricul meu"


def open_scan(scan: str, statistics_on: bool = True):
    """The app, then statistics turned on (or not), then the scan picked. The page shows an example scan (V2) on its
    first load, so statistics are turned on only after it: each test then counts just the scan it opens."""
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if statistics_on:
        set_enabled(True)
    app.selectbox[0].set_value(scan).run()
    assert not app.exception
    return app


def counts() -> dict[str, int]:
    return dict(top_codes(20))


def test_with_statistics_off_showing_a_scan_counts_nothing():
    open_scan("V4_legacy.xml", statistics_on=False)
    assert (status(), counts()) == ("off", {})


def test_the_example_scan_shown_on_the_first_load_counts_too_when_statistics_are_on():
    """With statistics already on, the scan the page opens by itself (V2) is a scan the person looked at."""
    set_enabled(True)
    AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    assert counts()["HTTP_ADMIN_CLEARTEXT"] == 2


def test_with_statistics_on_a_shown_scan_counts_once_per_session():
    app = open_scan("V4_legacy.xml")
    app.run()
    app.run()  # the page reruns on every click: still counted once
    assert counts()["TELNET_OPEN"] == 1 and len(app.session_state[SEEN_KEY]) == 1


def test_two_different_scans_both_count():
    app = open_scan("V2_smart_home.xml")
    app.selectbox[0].set_value("V4_legacy.xml").run()
    assert counts()["HTTP_ADMIN_CLEARTEXT"] == 3 and len(app.session_state[SEEN_KEY]) == 2


def test_a_broken_scan_is_never_counted():
    app = open_scan("V7_broken.xml")
    assert counts() == {} and app.session_state[SEEN_KEY] == set()


# Acasă, then the Istoric page in the same session, as a person clicks from one tab to the other: "Șterge istoricul
# meu" lives on Istoric (ui/pages/history.py) and must empty the set Acasă filled.
TWO_PAGES = ("import streamlit as st\nfrom ui.pages import history, home\n"
             "(history if st.session_state.get('page') == 'history' else home).render()")


def open_scan_then_history(scan: str):
    """Acasă with statistics on and `scan` picked, then the Istoric page in the same session."""
    app = AppTest.from_string(TWO_PAGES, default_timeout=TIMEOUT_SECONDS).run()
    set_enabled(True)
    app.selectbox[0].set_value(scan).run()
    app.session_state["page"] = "history"
    app.run()
    assert not app.exception
    return app


def test_deleting_the_history_also_empties_the_sessions_set():
    app = open_scan_then_history("V4_legacy.xml")
    assert app.session_state[SEEN_KEY]
    next(b for b in app.button if b.label == DELETE_LABEL).click().run()
    assert app.session_state[SEEN_KEY] == set() and status() == "off" and counts() == {}


def test_after_deleting_and_opting_in_again_the_same_scan_counts_again():
    app = open_scan_then_history("V4_legacy.xml")
    next(b for b in app.button if b.label == DELETE_LABEL).click().run()
    set_enabled(True)
    app.session_state["page"] = "home"
    app.run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    app.selectbox[0].set_value("V4_legacy.xml").run()
    assert counts()["TELNET_OPEN"] == 1
