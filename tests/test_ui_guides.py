"""FE-D2: the current guide says Acasă's headline. Tuga 🐢 in Simple mode and Cone 🐇 in Advanced mode, as a picture with
its alternative text and its name beside the headline and in the sidebar, never the picture alone (NFR-08). The
headline's words stay the same in both modes."""
from pathlib import Path

import pytest

from ui.assets import guide_picture

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def run(language: str | None = None, advanced: bool = False, scan: str | None = None):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    if language:
        app.radio[0].set_value(language).run()
    if advanced:
        app.toggle[0].set_value(True).run()
    if scan:
        app.selectbox[0].set_value(scan).run()
    assert not app.exception
    return app


def pictures(app) -> list:
    return [element.proto.imgs[0] for element in app.get("image")]


def texts(app) -> str:
    return "\n".join(m.value for m in app.markdown)


def headline(app) -> str:
    return next(m.value for m in app.markdown if m.value.startswith("## "))


def test_in_simple_mode_tuga_says_the_headline_and_sits_in_the_sidebar():
    app = run()
    alts = [p.alt for p in pictures(app)]
    assert alts == [guide_picture("tuga", "ro")[1]] * 2  # the sidebar and the headline
    assert all(p.url.startswith("data:image/svg+xml") for p in pictures(app))
    assert "🐢 **Tuga**" in texts(app)  # named beside the picture, never the picture alone


def test_in_advanced_mode_cone_takes_over_and_the_headline_stays_the_same():
    simple = headline(run())
    app = run(advanced=True)
    assert [p.alt for p in pictures(app)] == [guide_picture("cone", "ro")[1]] * 2
    assert "🐇 **Cone**" in texts(app)
    assert headline(app) == simple


def test_the_alternative_text_follows_the_language():
    app = run(language="English")
    assert [p.alt for p in pictures(app)] == [guide_picture("tuga", "en")[1]] * 2
    assert "Most dangerous" in headline(app)


def test_with_nothing_dangerous_the_guide_says_so():
    app = run(scan="V6b_after.xml")
    assert "Nu am găsit nimic periculos" in headline(app)
    assert len(pictures(app)) == 2


def test_a_broken_scan_shows_only_the_sidebar_guide_and_the_error():
    app = run(scan="V7_broken.xml")
    assert app.error
    assert len(pictures(app)) == 1  # no headline to say, so no guide beside it
