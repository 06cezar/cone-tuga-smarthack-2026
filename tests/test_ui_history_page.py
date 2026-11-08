"""The Istoric page (ui/pages/history.py): the change banner and the red delete button on top, the score over time and
the stored scans on the left, the before/after comparator on the right with "REZOLVAT" badges, Tuga's progress
summary in Simple mode, Cone's technical diff log and the standard export in Advanced mode. The page is run on its own
with the scans stored as Acasă would store them (tests/test_ui_app.py covers the same path for the old checks)."""
import tempfile
from pathlib import Path

import pytest

from conetuga.guard.export import export
from ui.pages.home import EXAMPLE_FOLDERS

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
VALIDATION = EXAMPLE_FOLDERS[0]


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    """The page reads and deletes the history: keep it in a temporary folder, never in the real .history/."""
    folder = tmp_path / "history"
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(folder))
    return folder


def history_page(*scans: str, language: str = "Română", advanced: bool = False) -> AppTest:
    """Istoric with these example scans stored in this order; the last one is the scan on screen."""
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\n"
              "from conetuga.analysis import analyse_file\nfrom conetuga.history import digest_of, save_scan\n"
              "from ui.pages.home import example_scans\nfrom ui.state import remember_digest\n"
              "paths = {path.name: path for path in example_scans()}\n"
              f"for name in {list(scans)!r}:\n"
              "    save_scan(analyse_file(paths[name]), paths[name].read_bytes())\n"
              f"remember_digest(digest_of(paths[{scans[-1]!r}].read_bytes()))\n" if scans else
              f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n")
    app = AppTest.from_string(script + "from ui.pages import history\nhistory.render()",
                              default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def markdown(app: AppTest) -> str:
    return "\n".join(m.value for m in app.markdown)


def test_the_banner_counts_what_changed_and_the_red_delete_button_is_on_top():
    """FR-13 and NFR-02: V6a → V6b, the contract "diff" example: 3 resolved, one port opened, no device added."""
    app = history_page("V6a_before.xml", "V6b_after.xml")
    text = markdown(app)
    assert "🔔 Ce s-a schimbat" in text
    assert "<strong>✅ 3</strong> probleme rezolvate" in text and "<strong>🔓 1</strong> porturi deschise" in text
    assert "<strong>🆕 0</strong> dispozitive noi" in text
    delete = next(b for b in app.button if b.label == "🗑️ Șterge istoricul meu")
    assert delete.proto.type == "primary"  # drawn red by ui/theme.py, the first button on the page
    assert app.button[0].label == delete.label


def test_the_left_column_charts_the_score_and_lists_every_scan():
    app = history_page("V6a_before.xml", "V6b_after.xml")
    assert len(app.get("vega_lite_chart")) == 1
    text = markdown(app)
    assert "**#2** · " in text and "V6b\\_after\\.xml · 🟢 100/100 · **⬅️ acum**" in text
    assert "**#1** · " in text and "V6a\\_before\\.xml" in text


def test_a_single_scan_of_a_network_has_no_chart_yet():
    app = history_page("V2_smart_home.xml")
    assert not app.get("vega_lite_chart")
    assert "Doar o scanare din această rețea până acum" in markdown(app)


def test_the_comparator_marks_the_fixed_findings_resolved():
    app = history_page("V6a_before.xml", "V6b_after.xml")
    assert app.selectbox(key="history_before").value == 0 and app.selectbox(key="history_after").value == 1
    text = markdown(app)
    assert text.count('<span class="ct-tag ct-tag-ok">REZOLVAT</span>') == 3
    assert "60 → 100 (+40, mai bine)" in text


def test_simple_mode_tuga_sums_up_the_progress():
    app = history_page("V6a_before.xml", "V6b_after.xml")
    text = markdown(app)
    assert "Bravo! Scorul a urcat de la **60** la **100** (+40). Ai reparat **3** probleme." in text
    assert "Jurnal tehnic" not in text and "`TELNET_OPEN`" not in text
    assert not any(button.label.endswith(".csv") for button in app.get("download_button"))


def test_advanced_mode_cone_lists_every_technical_change():
    app = history_page("V6a_before.xml", "V6b_after.xml", language="English", advanced=True)
    text = markdown(app)
    assert "Technical diff log" in text
    assert "| 🔓 port opened | " in text and "| 443/tcp | " in text
    assert text.count("| ✅ resolved | ") == 3 and "`TELNET_OPEN`" in text and "`UPNP_EXPOSED`" in text
    assert "Well done!" not in text


def test_advanced_mode_offers_the_standard_export_of_a_folder():
    """FR-15: the two files are exactly what C's `export` writes for the Validation Set (the contract "export")."""
    from ui.pages.history import exported_files

    app = history_page("V2_smart_home.xml", advanced=True)
    buttons = {element.proto.label for element in app.get("download_button")}
    assert buttons == {"⬇️ findings.csv", "⬇️ scores.csv"}
    assert app.selectbox(key="history_export_folder").value == VALIDATION
    with tempfile.TemporaryDirectory() as out:
        export(VALIDATION, Path(out))
        expected = {name: (Path(out) / name).read_bytes() for name in ("findings.csv", "scores.csv")}
    assert exported_files(VALIDATION) == expected
    assert b"V7_broken.xml,ERROR\n" in expected["scores.csv"]


def test_an_empty_history_says_so_and_offers_no_comparison():
    app = history_page()
    assert "Istoricul e gol" in " ".join(i.value for i in app.info)
    assert not app.selectbox


def test_the_page_speaks_english():
    app = history_page("V6a_before.xml", "V6b_after.xml", language="English")
    text = markdown(app)
    assert "🔔 What changed" in text and "Well done! The score went up from **60** to **100**" in text
    assert app.button[0].label == "🗑️ Delete my history"
