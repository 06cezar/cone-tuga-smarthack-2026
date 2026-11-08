"""Two Simple-mode helpers on a finding: "Ce-ar fi dacă repar?" (the score once it is fixed, from A's standard_score)
and Tuga reading aloud with a voice already on the computer (ui/voice.py): local voices only, nothing loaded, and scan
text that can never break out of the script."""
import re
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from ui.view import score_if_fixed
from ui.voice import TUGA_PITCH, TUGA_RATE, read_aloud_html, spoken_text

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
HOSTILE = "</script><script>alert(1)</script>"


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def test_fixing_the_camera_stream_raises_v2_from_40_to_60():
    result = analyse_file(SCANS / "V2_smart_home.xml")
    camera = next(f for f in result.findings if f.code == "CAMERA_STREAM_EXPOSED")
    assert (result.score, score_if_fixed(result, camera)) == (40, 60)


def test_a_finding_with_no_points_changes_nothing():
    result = analyse_file(SCANS / "V3_small_office.xml")
    assert all(score_if_fixed(result, f) == result.score for f in result.findings if f.points == 0)


def test_the_score_after_a_fix_never_passes_100():
    for path in sorted(SCANS.glob("*.xml")):
        result = analyse_file(path)
        assert all(result.score <= score_if_fixed(result, f) <= 100 for f in result.findings), path.name


def test_acasa_says_how_much_each_fix_gives():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    assert not app.exception
    text = "\n".join(m.value for m in app.markdown)
    assert "Scorul urcă de la 40 la 60 (+20)" in text and "Scorul urcă de la 40 la 50 (+10)" in text


def test_tuga_says_the_title_the_explanation_and_the_steps():
    assert spoken_text("Titlu", "Explicație.", "Ce să faci", ["Unu", "Doi"]) == \
        "Titlu. Explicație. Ce să faci: 1. Unu 2. Doi"


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_only_voices_on_this_computer_are_used(lang):
    page = read_aloud_html("Salut", lang)
    assert "v.localService" in page and f"rate: {TUGA_RATE}" in page and f"pitch: {TUGA_PITCH}" in page


def test_the_voice_page_loads_nothing_from_outside():
    assert not re.search(r"(src|href)\s*=|https?://|@import", read_aloud_html("Salut", "ro", dark=True))


def test_scan_text_cannot_close_the_script():
    page = read_aloud_html(f"Dispozitivul {HOSTILE} are o problemă", "en")
    assert HOSTILE not in page and "</script><script>" not in page
    assert page.count("</script>") == 1

