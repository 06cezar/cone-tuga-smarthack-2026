"""The Wiki page (FE-B4): every problem ConeTuga can find, then five basic ideas, as the current guide tells them
(B's wiki_entries), each problem with the catalog's severity, related entries named by their titles, references, and
A's "most common problems" panel at the top. The page is run on its own; it reads no scan."""
import pytest

from conetuga.explain import wiki_entries
from ui.assets import guide_picture

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
CODES = 15  # the catalog's codes
CONCEPTS = 5  # port, encryption, firewall, mac, upnp


def show(language: str = "Română", advanced: bool = False) -> AppTest:
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\nfrom ui.pages import wiki\nwiki.render()")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def labels(app) -> list[str]:
    return [section.label for section in app.expander]


def plain(text: str) -> str:
    """Page text without view.md's backslashes, to compare it with the data."""
    return text.replace("\\", "")


def test_simple_mode_lists_every_problem_then_the_basics_with_tugas_titles():
    app = show()
    entries = wiki_entries("ro", "simple")
    shown = labels(app)
    assert len(shown) == CODES + CONCEPTS
    assert [plain(label).split(" · ")[-1] for label in shown] == [entry.title for entry in entries]
    assert "⛔ Risc mare" in shown[0]  # TELNET_OPEN, with the catalog's severity as icon and words
    assert [s.value for s in app.subheader][-2:] == ["Problemele pe care le poate găsi ConeTuga",
                                                      "Idei de bază despre rețele"]


def test_advanced_mode_cone_tells_them_with_the_catalog_code():
    app = show("English", advanced=True)
    first = wiki_entries("en", "advanced")[0]
    assert "`TELNET_OPEN`" in labels(app)[0] and first.title in plain(labels(app)[0])
    assert "🐇 **Cone**" in "\n".join(m.value for m in app.markdown)


def test_related_entries_are_named_by_their_titles():
    app = show()
    titles = {entry.id: entry.title for entry in wiki_entries("ro", "simple")}
    related = [plain(m.value) for m in app.markdown if m.value.startswith("**Legat de:**")]
    both = next(line for line in related if titles["FTP_CLEARTEXT"] in line and titles["TELNET_OPEN"] in line)
    assert "FTP_CLEARTEXT" not in both  # titles, never raw codes, in Simple mode


def test_problems_cite_their_references_and_ideas_none():
    app = show()
    assert sum(1 for m in app.markdown if m.value.startswith("*Referințe:")) == CODES


def test_the_common_problems_panel_is_at_the_top():
    headings = [s.value for s in show().subheader]
    assert headings.index("📊 Cele mai comune probleme") < headings.index("Problemele pe care le poate găsi ConeTuga")


@pytest.mark.parametrize("language, lang, advanced, speaker",
                         [("Română", "ro", False, "tuga"), ("English", "en", True, "cone")])
def test_the_guide_beside_the_introduction_follows_the_mode_and_the_language(language, lang, advanced, speaker):
    app = show(language, advanced)
    assert [element.proto.imgs[0].alt for element in app.get("image")] == [guide_picture(speaker, lang)[1]]
