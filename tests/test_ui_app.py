"""The whole page (ui/app.py) run headless with Streamlit's AppTest: it starts without an error, the headline is at
the top in both languages, a broken scan shows an error instead of a crash, Acasă saves each scan, and the
history page (ui/pages/history.py) shows before/after."""
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


def history_page(*scans: str, current: str | None = None, language: str = "Română", advanced: bool = False):
    """The Istoric page with these example scans stored in this order, as Acasă would have saved them, and `current`
    (by default the last one) as the scan on screen. The scans are saved once per session, so a click on "delete"
    leaves the history empty."""
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\n"
              "from conetuga.analysis import analyse_file\nfrom conetuga.history import digest_of, save_scan\n"
              "from ui.pages.home import example_scans\nfrom ui.state import remember_digest\n"
              "paths = {path.name: path for path in example_scans()}\n"
              "if not st.session_state.get('stored'):\n"
              f"    for name in {list(scans)!r}:\n"
              "        save_scan(analyse_file(paths[name]), paths[name].read_bytes())\n"
              "    st.session_state['stored'] = True\n"
              f"remember_digest(digest_of(paths[{current or scans[-1]!r}].read_bytes()))\n"
              "from ui.pages import history\nhistory.render()")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def test_acasa_saves_every_scan_it_shows(history_in_tmp):
    """FR-10: the history has its own page now, but Acasă still stores each scan it shows, once."""
    from conetuga.history import load_history

    app = run(scan="V6a_before.xml")
    app.selectbox[0].set_value("V6b_after.xml").run()
    app.selectbox[0].set_value("V6b_after.xml").run()
    assert not app.exception
    assert [record.file for record in load_history()] == ["V2_smart_home.xml", "V6a_before.xml", "V6b_after.xml"]


def test_history_shows_before_and_after_with_the_change_alert():
    app = history_page("V6a_before.xml", "V6b_after.xml")
    text = all_text(app)
    assert "60 → 100" in text
    assert "Rezolvate (3)" in text
    assert "443/tcp" in text  # the router's newly opened port is flagged (FR-13)


def nothing_compared(app) -> bool:
    """No comparison on screen: the comparator's "before" box with nothing picked, and no "Rezolvate" list."""
    return app.selectbox(key="history_before").value is None and "Rezolvate" not in all_text(app)


def test_history_never_compares_two_unrelated_networks_on_its_own():
    """C's review (17:37): V2 then V3 showed "🚨 ceva nou în rețea", 4 new devices and "Rezolvate (5)", all false."""
    app = history_page("V2_smart_home.xml", "V3_small_office.xml")
    assert not app.warning
    assert nothing_compared(app)
    assert "40 → 45" not in all_text(app)
    assert "Nicio scanare mai veche nu are aceleași dispozitive ca aceasta" in all_text(app)


def test_the_person_can_still_compare_with_any_earlier_scan():
    """Nothing is hidden: the "before" box lists every stored scan, and picking one shows its before/after."""
    app = history_page("V2_smart_home.xml", "V3_small_office.xml")
    app.selectbox(key="history_before").set_value(0).run()  # the only earlier scan, V2
    assert not app.exception
    assert "40 → 45" in all_text(app)


def test_one_shared_router_does_not_make_two_homes_the_same_network():
    """V1 and V2 both have 192.168.1.1 "router.lan" and nothing else in common; CI caught V1 being compared with the
    V2 the page opens by default, with a false alert."""
    app = history_page("V2_smart_home.xml", "V1_home_basic.xml")
    assert not app.warning
    assert nothing_compared(app)


def test_history_shows_our_lab_before_and_after():
    """Live check 6: our hotspot lab, scan_01 then scan_03."""
    app = history_page("scan_01.xml", "scan_03.xml")
    text = all_text(app)
    assert "0 → 70" in text
    assert "Rezolvate (4)" in text
    assert not app.warning


def test_a_jury_file_opened_after_our_lab_is_the_first_scan_of_its_network():
    """The hands-on check: with our lab in the history, the jury's file must not be compared with it."""
    app = history_page("scan_01.xml", "scan_03.xml", "V1_home_basic.xml")
    assert not app.warning
    assert nothing_compared(app)


def test_delete_my_history_leaves_nothing(history_in_tmp):
    app = history_page("V6a_before.xml")
    assert any(history_in_tmp.iterdir())
    next(b for b in app.button if b.label == "🗑️ Șterge istoricul meu").click().run()
    assert not app.exception
    assert not history_in_tmp.exists()
    assert "Istoricul a fost șters" in all_text(app)


def answer_of(app) -> str:
    return " ".join(i.value for i in app.info).replace("\\", "")  # as a person reads it, without Markdown escapes


def ask(scan: str, question: str, language: str = "English"):
    app = run(scan=scan, language=language)
    app.text_input[0].input(question).run()
    return app


def test_the_question_box_answers_the_briefs_example_from_the_scan():
    app = ask("V3_small_office.xml", "is it safe that my printer has port 9100 open?")
    assert not app.exception
    assert "[192.168.1.10:9100 PRINTER_RAW_EXPOSED]" in answer_of(app)


def test_the_question_box_says_when_the_scan_cannot_answer():
    app = ask("V3_small_office.xml", "Is WPS turned on?")
    assert answer_of(app) == "The scan doesn't show this."


def test_the_question_box_answers_in_romanian_too():
    app = ask("V3_small_office.xml", "E activat WPS?", language="Română")
    assert answer_of(app) == "Scanul nu arată asta."


def test_a_hostile_question_is_never_shown_back():
    app = ask("V3_small_office.xml", "<script>alert(1)</script> [click](javascript:x) :red[fake]")
    assert not app.exception
    shown = answer_of(app)
    assert "<script>" not in shown and "javascript:" not in shown and ":red[" not in shown


def test_an_empty_question_shows_no_answer():
    app = ask("V3_small_office.xml", "   ")
    assert not app.exception and not app.info


def test_simple_mode_is_the_default_and_tuga_speaks():
    app = run(scan="V2_smart_home.xml")
    assert not app.exception
    assert app.toggle[0].value is False
    text = all_text(app)
    assert "🐢 **Tuga:**" in text and "🐇 **Cone:**" not in text
    assert "PRINTER_RAW_EXPOSED" not in text and "CAMERA_STREAM_EXPOSED" not in text  # no catalog codes for Tuga


def test_advanced_mode_lets_cone_show_the_evidence_and_references():
    app = run(scan="V2_smart_home.xml")
    app.toggle[0].set_value(True).run()
    assert not app.exception
    text = all_text(app)
    assert "🐇 **Cone:**" in text and "🐢 **Tuga:**" not in text
    assert "CAMERA_STREAM_EXPOSED" in text and "OWASP IoT" in text
    assert "Cel mai periculos" in first_heading(app)  # the headline stays the same in both modes


def test_the_about_page_explains_the_guides_in_both_languages():
    for language, words in (("Română", "Cei doi ghizi"), ("English", "The two guides")):
        script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
                  "from ui.pages import about\nabout.render()")
        app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
        assert not app.exception
        assert words in " ".join(m.value for m in app.markdown)
