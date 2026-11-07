"""The "Cele mai comune probleme" panel (FE-A3, ui/insights_panel.py): its data, and the component run headless with
Streamlit's AppTest, off by default, turned on, unavailable, and a save the store refuses. Every test has its own
history folder (tests/conftest.py), so the statistics store starts empty."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from conetuga.history import digest_of
from conetuga.insights import record, set_enabled, status
from ui.insights_panel import TEXT, common_problems, how_many_times

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
TITLES = {"HTTP_ADMIN_CLEARTEXT": "Pagină de administrare fără criptare", "TELNET_OPEN": "Telnet necriptat"}
APP_TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def count(*names: str) -> None:
    seen: set[str] = set()
    for name in names:
        path = SCANS / name
        assert record(analyse_file(path), digest_of(path.read_bytes()), seen)


def page_with_the_panel(titles: dict, lang: str) -> None:
    """What B's Wiki page does: draw the panel with the titles of the current language and mode."""
    from ui.insights_panel import render_common_problems
    render_common_problems(titles, lang)


def run_panel(lang: str = "ro", titles: dict | None = None):
    return AppTest.from_function(page_with_the_panel, kwargs={"titles": titles or TITLES, "lang": lang},
                                 default_timeout=APP_TIMEOUT_SECONDS).run()


def shown(app) -> str:
    return "\n".join([m.value for m in app.markdown] + [m.value for m in app.info] + [m.value for m in app.warning]
                     + [m.value for m in app.error] + [c.value for c in app.caption])


# --- The data ---

def test_no_statistics_give_no_rows():
    assert common_problems(5, TITLES) == []


def test_rows_are_the_top_codes_with_the_pages_titles():
    set_enabled(True)
    count("V2_smart_home.xml", "V4_legacy.xml")
    rows = common_problems(2, TITLES)
    assert [(r.code, r.title, r.count) for r in rows] == [
        ("HTTP_ADMIN_CLEARTEXT", "Pagină de administrare fără criptare", 3), ("CAMERA_STREAM_EXPOSED",
                                                                             "CAMERA_STREAM_EXPOSED", 1)]


def test_a_code_without_a_title_shows_the_code():
    set_enabled(True)
    count("V4_legacy.xml")
    assert all(r.title == r.code for r in common_problems(5, {}))


# --- The component ---

def test_statistics_are_off_until_the_person_turns_them_on():
    app = run_panel()
    assert not app.exception
    assert app.toggle[0].value is False
    assert TEXT["ro"]["off"] in shown(app) and status() == "off"


def test_turning_the_switch_on_saves_the_choice():
    app = run_panel()
    app.toggle[0].set_value(True).run()
    assert status() == "on" and app.toggle[0].value is True
    assert TEXT["ro"]["empty"] in shown(app)


def test_the_list_shows_titles_and_counts_in_the_scans_looked_at():
    set_enabled(True)
    count("V2_smart_home.xml", "V4_legacy.xml")
    app = run_panel("en")
    text = shown(app)
    assert TEXT["en"]["list_intro"] in text
    assert "1. Pagină de administrare fără criptare: 3 times" in text and "once" in text


def test_the_panel_never_shows_a_scan_detail():
    """It only knows codes and counts: no IP, MAC or hostname of the counted scans can appear."""
    set_enabled(True)
    count("V2_smart_home.xml")
    text = shown(run_panel("en"))
    assert not any(detail in text for detail in ("192.168.", "50:C7:BF", "router.lan", "ipcam", "TP-Link"))


def test_a_store_that_cant_be_read_shows_unavailable_and_no_switch():
    store_file = Path(__import__("conetuga.insights.store", fromlist=["store_path"]).store_path())
    store_file.parent.mkdir(parents=True)
    store_file.write_bytes(b"not an SQLite database")
    app = run_panel()
    assert not app.exception and len(app.toggle) == 0
    assert TEXT["ro"]["unavailable"] in shown(app) and app.warning[0].icon == "⚠️"


def test_a_save_the_store_refuses_is_reported_and_the_switch_shows_the_real_state(tmp_path, monkeypatch):
    """The history folder can't be created (a file is in its place): status() reads "off" fine, but the write fails.
    The panel says so from set_enabled's answer, and the switch goes back to off."""
    blocker = tmp_path / "a-file-not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(blocker / "history"))
    app = run_panel()
    app.toggle[0].set_value(True).run()
    assert TEXT["ro"]["not_saved"] in shown(app) and app.error[0].icon == "⚠️"  # an icon and words (NFR-08)
    assert app.toggle[0].value is False and status() == "off"


def test_the_switch_follows_the_store_after_the_history_is_deleted():
    """After "Șterge istoricul meu" (another page), the switch shows off, not the session's old value."""
    from conetuga.history import delete_history
    app = run_panel()
    app.toggle[0].set_value(True).run()
    delete_history()
    app.run()
    assert app.toggle[0].value is False and TEXT["ro"]["off"] in shown(app)


@pytest.mark.parametrize("count, ro", [(1, "o dată"), (2, "2 ori"), (19, "19 ori"), (20, "20 de ori"), (21, "21 de ori"),
                                       (99, "99 de ori"), (100, "100 de ori"), (101, "101 ori"), (119, "119 ori"),
                                       (120, "120 de ori"), (1000, "1000 de ori"), (1001, "1001 ori")])
def test_romanian_counts_take_de_after_00_or_20_and_above(count, ro):
    """E's P3 on #60 (NFR-09): "20 de ori", "100 de ori", but "101 ori"."""
    assert how_many_times(count, "ro") == ro


@pytest.mark.parametrize("count, en", [(1, "once"), (2, "2 times"), (20, "20 times"), (101, "101 times")])
def test_english_counts_have_no_de(count, en):
    assert how_many_times(count, "en") == en

