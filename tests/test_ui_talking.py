"""The talking guide beside Acasă's headline (ui/talking.py): tap the picture and the guide reads the headline and the
score aloud with a voice on this computer. Its page loads nothing, keeps scan text out of the HTML, and the style
moves nothing when the operating system asks for reduced motion."""
import re
from pathlib import Path

import pytest

from ui.style import HEADLINE_KEY, PAGE_CSS, TALKING_CLASS
from ui.talking import talking_html
from ui.voice import CONE_RATE, TUGA_RATE

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
HOSTILE = "</script><img src=x onerror=alert(1)>"


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def test_the_guide_speaks_at_its_own_pace_with_local_voices_only():
    tuga, cone = talking_html("Salut", "ro", "tuga"), talking_html("Hello", "en", "cone")
    assert f'"rate": {TUGA_RATE}' in tuga and f'"rate": {CONE_RATE}' in cone
    assert "v.localService" in tuga and '"key": "headline-tuga"' in tuga and '"key": "headline-cone"' in cone


def test_scan_text_never_becomes_html_and_nothing_is_loaded():
    page = talking_html(f"Cel mai periculos: {HOSTILE}", "ro", "tuga")
    assert HOSTILE not in page and page.count("</script>") == 1
    assert not re.search(r"(src|href)\s*=|https?://|@import", talking_html("Salut", "ro", "tuga"))


def test_the_style_animates_the_guide_but_not_for_reduced_motion():
    assert f".st-key-{HEADLINE_KEY}-tuga img {{ animation: guide-walk-in" in PAGE_CSS
    assert f".{TALKING_CLASS} img" in PAGE_CSS
    reduced = PAGE_CSS.split("@media (prefers-reduced-motion: reduce)", 1)[1]
    assert "animation: none !important" in reduced


def test_acasa_puts_the_headline_and_its_voice_in_one_block():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    assert not app.exception
    heading = next(m.value for m in app.markdown if m.value.startswith("## "))
    assert "🔊 Apasă pe poză și îți citesc" in heading
