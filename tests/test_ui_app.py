"""The whole page (ui/app.py) run headless with Streamlit's AppTest: it starts without an error, the headline is at
the top in both languages, a broken scan shows an error instead of a crash, and the history shows before/after."""
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    """The page saves every scan it shows: keep it in a temporary folder, never in the real .history/."""
    folder = tmp_path / "history"
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(folder))
    return folder


def run(scan: str | None = None, language: str | None = None):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if language:
        app.radio[0].set_value(language).run()
    if scan:
        app.selectbox[0].set_value(scan).run()
    return app


def first_heading(app) -> str:
    return next(m.value for m in app.markdown if m.value.startswith("## "))


def all_text(app) -> str:
    return "\n".join([m.value for m in app.markdown] + [w.value for w in app.warning] + [s.value for s in app.success])


def test_the_first_screen_names_the_most_dangerous_device_and_the_first_step():
    app = run()
    assert not app.exception
    heading = first_heading(app)
    assert "Cel mai periculos" in heading and "Fă asta întâi" in heading


def test_the_page_switches_to_english():
    app = run(language="English")
    assert not app.exception
    assert "Most dangerous" in first_heading(app)


def test_a_broken_scan_shows_an_error_not_a_crash(history_in_tmp):
    app = run(scan="V7_broken.xml")
    assert not app.exception
    assert app.error and "V7\\_broken" in app.error[0].value


def test_history_shows_before_and_after_with_the_change_alert():
    app = run(scan="V6a_before.xml")
    app.selectbox[0].set_value("V6b_after.xml").run()
    assert not app.exception
    text = all_text(app)
    assert "60 → 100" in text
    assert "Rezolvate (3)" in text
    assert "443/tcp" in text  # the router's newly opened port is flagged (FR-13)


def test_history_never_compares_two_unrelated_networks():
    """C's review (17:37): V2 then V3 showed "🚨 ceva nou în rețea", 4 new devices and "Rezolvate (5)", all false."""
    app = run(scan="V2_smart_home.xml")
    app.selectbox[0].set_value("V3_small_office.xml").run()
    assert not app.exception
    text = all_text(app)
    assert not app.warning
    assert len(app.selectbox) == 1  # only the scan picker: no "compare with" box
    assert "40 → 45" not in text and "Rezolvate" not in text
    assert "Nicio scanare mai veche din istoric nu are dispozitivele acestei rețele" in text


def test_history_shows_our_lab_before_and_after():
    """Live check 6: our hotspot lab, scan_01 then scan_03."""
    app = run(scan="scan_01.xml")
    app.selectbox[0].set_value("scan_03.xml").run()
    assert not app.exception
    text = all_text(app)
    assert "0 → 70" in text
    assert "Rezolvate (4)" in text
    assert not app.warning


def test_a_jury_file_opened_after_our_lab_is_the_first_scan_of_its_network():
    """The hands-on check: with our lab in the history, the jury's file must not be compared with it. The history
    orders scans saved in the same second by file name, so this checks what matters (no comparison offered, no alert),
    not which of the two "first scan" sentences shows."""
    app = run(scan="scan_01.xml")
    app.selectbox[0].set_value("scan_03.xml").run()
    app.selectbox[0].set_value("V1_home_basic.xml").run()
    assert not app.exception
    assert not app.warning
    assert len(app.selectbox) == 1  # only the scan picker: no "compare with" box
    assert "Rezolvate" not in all_text(app)


def test_delete_my_history_leaves_nothing(history_in_tmp):
    app = run(scan="V6a_before.xml")
    assert any(history_in_tmp.iterdir())
    app.button[0].click().run()
    assert not app.exception
    assert not history_in_tmp.exists()
    assert "Istoricul a fost șters" in all_text(app)
