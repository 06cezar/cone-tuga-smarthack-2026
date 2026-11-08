"""Despre & Wiki (ui/pages/about.py): the app and its two guides beside the Ethical Shield (the allowed subnet as the
live scan reads it, the hotspot rule, MAC masking, 100% local), then the Common Threat Wiki with its search and its
severity filter: Tuga's steps in Simple mode, Cone's detection rule from data/catalog.toml in Advanced mode."""
import pytest

from conetuga.analysis.catalog import load_catalog
from conetuga.guard import Network, NetworkNotFound

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
HOTSPOT = Network("Wi-Fi", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")  # the detect_network contract's example
CATALOG = load_catalog()
HIGH_CODES = sum(1 for rule in CATALOG.rules if rule.severity == "high")
CONCEPTS = 5


@pytest.fixture
def on_hotspot(monkeypatch):
    import ui.pages.about as page
    monkeypatch.setattr(page, "detect_network", lambda: HOTSPOT)


@pytest.fixture
def offline(monkeypatch):
    import ui.pages.about as page

    def no_network():
        raise NetworkNotFound("no network")
    monkeypatch.setattr(page, "detect_network", no_network)


def about(language: str = "Română", advanced: bool = False) -> AppTest:
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\nfrom ui.pages import about\nabout.render()")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def markdown(app: AppTest) -> str:
    return "\n".join(m.value for m in app.markdown)


def problem_labels(app: AppTest) -> list[str]:
    """The wiki's problem cards (each has a severity), not its basic ideas."""
    return [section.label for section in app.expander if "p · " in section.label]


def test_the_shield_shows_the_subnet_the_live_scan_may_cover(on_hotspot):
    app = about()
    assert "🛡️ Scutul Etic & Guardrail activ" in [s.value for s in app.subheader]
    text = markdown(app)
    assert "`172.20.10.0/28` pe Wi\\-Fi" in text
    assert "„RSH\\-ConeTuga”" in text and "`AA:BB:CC:xx:xx:xx`" in text and "**100% local:**" in text


def test_with_no_network_the_shield_says_the_live_scan_is_blocked(offline):
    assert "scanarea live e blocată" in markdown(about())


def test_the_app_and_its_guides_sit_beside_the_shield_then_the_wiki(on_hotspot):
    app = about("English")
    text = markdown(app)
    assert "**The two guides.**" in text and "🛡️ Ethical Shield & active guardrail" in [s.value for s in app.subheader]
    assert app.header[0].value == "📚 Common Threat Wiki: the catalog of 15 problems"


def test_every_problem_card_shows_its_severity_and_points(on_hotspot):
    labels = problem_labels(about())
    assert len(labels) == len(CATALOG.rules)
    assert labels[0].startswith("⛔ Risc mare · −20p · ")  # TELNET_OPEN
    assert labels[-1].startswith("💬 Doar informativ · 0p · ")  # SSH_OPEN


def test_the_severity_filter_keeps_only_the_chosen_problems(on_hotspot):
    app = about()
    app.button_group(key="wiki_severity").set_value(["high"]).run()
    assert not app.exception
    labels = problem_labels(app)
    assert len(labels) == HIGH_CODES and all(label.startswith("⛔ Risc mare · −20p") for label in labels)
    assert f"Afișate: {HIGH_CODES} din 15 probleme." in markdown(app)


def test_the_search_finds_a_problem_by_its_words(on_hotspot):
    app = about()
    app.text_input(key="wiki_search").input("telnet").run()
    labels = problem_labels(app)
    assert labels and all("Telnet" in label or "Risc mare" in label for label in labels)
    assert len(labels) < len(CATALOG.rules)


def test_a_search_with_no_match_says_so(on_hotspot):
    app = about()
    app.text_input(key="wiki_search").input("nimic de găsit aici").run()
    assert not problem_labels(app)
    assert "Nicio problemă nu se potrivește" in " ".join(i.value for i in app.info)


def test_simple_mode_tuga_gives_the_fix_steps(on_hotspot):
    text = markdown(about())
    assert "**Ce faci, pas cu pas**\n1. Intră în setările dispozitivului" in text
    assert "Regula de detecție" not in text


def test_advanced_mode_cone_gives_the_detection_rule_from_the_catalog(on_hotspot):
    app = about("English", advanced=True)
    text = markdown(app)
    assert "**Detection rule**" in text and "What to do, step by step" not in text
    assert "Service reported by nmap: `telnet`, on any port." in text
    assert "Service reported by nmap: `upnp`, on any port (UDP only)." in text
    assert "`OpenSSH < 7.4`" in text and "`vsftpd = 2.3.4`" in text and "`Apache httpd ≤ 2.2`" in text
    assert "OWASP IoT" in text  # the references stay
    assert "`TELNET_OPEN`" in problem_labels(app)[0]
