"""The Scanare page (FE-C1): the network (FR-01), the guardrail's verdict (FR-02) and the command to run, and nothing
run from the browser (NFR-04). The network is a fake: no test reads this computer's network or runs nmap."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import conetuga.guard.scan as live
import ui.pages.scan as page
from conetuga.guard import Network, NetworkNotFound

TIMEOUT_SECONDS = 30  # as in tests/test_ui_app.py: a cold Streamlit import on a CI runner takes seconds
HOTSPOT = Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1")
VENUE = Network("wlp0s20f3", "10.240.7.21", "10.240.0.0/16", "10.240.0.1")
PAGE_FILE = Path(__file__).resolve().parents[1] / "ui" / "pages" / "scan.py"


@pytest.fixture(autouse=True)
def nothing_runs(monkeypatch):
    """The page must never start a scan: if it reached nmap or live_scan, the test fails."""
    def forbidden(*args, **kwargs):
        raise AssertionError("the Scanare page tried to scan")

    monkeypatch.setattr(live, "live_scan", forbidden)
    monkeypatch.setattr(live, "_run_nmap", forbidden)
    monkeypatch.setattr(page, "_on_windows", lambda: False)


def on(monkeypatch, network: Network, ssid: str) -> None:
    monkeypatch.setattr(page, "detect_network", lambda: network)
    monkeypatch.setattr(page, "wifi_ssid", lambda interface: ssid)


def show(language: str = "Română", advanced: bool = False) -> AppTest:
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\nfrom ui.pages import scan\nscan.render()")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def text_of(app: AppTest) -> str:
    parts = [*app.title, *app.subheader, *app.markdown, *app.success, *app.error, *app.warning, *app.caption, *app.code]
    return "\n".join(str(part.value) for part in parts).replace("\\", "")


def test_on_our_hotspot_the_page_says_the_scan_is_allowed_and_shows_the_command(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    app = show()
    assert app.success and "permisă" in app.success[0].value
    assert app.code[0].value == ".venv/bin/python -m conetuga scan --confirm"
    assert "RSH-ConeTuga" in text_of(app) and "172.20.10.0/28" in text_of(app)


def test_on_the_venue_wifi_the_page_says_the_scan_would_be_refused_and_why(monkeypatch):
    on(monkeypatch, VENUE, "UnivBuc Free")
    app = show(language="English")
    assert not app.success and app.error
    assert "would be refused" in app.error[0].value and "not on our hotspot" in app.error[0].value
    assert "Connect the laptop only to the hotspot" in text_of(app)


def test_with_no_network_the_page_says_so_and_still_shows_the_command(monkeypatch):
    def no_network():
        raise NetworkNotFound("Laptopul nu este conectat la nicio rețea.\nThe laptop is not connected to any network.")

    monkeypatch.setattr(page, "detect_network", no_network)
    app = show()
    assert app.warning and "Nu găsesc nicio rețea" in app.warning[0].value
    assert app.code[0].value.endswith("scan --confirm")


def test_simple_mode_keeps_the_technical_details_out(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    text = text_of(show())
    assert "--max-rate" not in text and "Gateway" not in text and "172.20.10.1 " not in text


def test_advanced_mode_shows_the_interface_gateway_and_what_nmap_does(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    text = text_of(show(language="English", advanced=True))
    for expected in ("wlp0s20f3", "172.20.10.1", "-sS -sU -sV", "http-title", "at most 100 packets per second",
                     "1,000 most common TCP ports plus 1883, 6379, 6380, 27017", "UDP 53, 123, 161, 1900, 5353",
                     "--exclude 172.20.10.13", "at most 5 minutes per device"):
        assert expected in text, expected


def test_on_windows_the_command_uses_the_windows_python_and_an_admin_terminal(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    monkeypatch.setattr(page, "_on_windows", lambda: True)
    app = show(language="English")
    assert app.code[0].value == r".venv\Scripts\python -m conetuga scan --confirm"
    assert "Run as administrator" in text_of(app)


def test_a_hostile_wifi_name_is_escaped(monkeypatch):
    """Anyone can name a Wi-Fi network: markdown, links or HTML in it are shown as text (NFR-03)."""
    on(monkeypatch, HOTSPOT, "Free [click](http://x.y) <b>**WiFi**</b>")
    app = show(advanced=True)
    shown = "\n".join(str(m.value) for m in app.markdown)
    assert "[click](http://x.y)" not in shown and "<b>" not in shown and "**WiFi**" not in shown


def test_the_page_never_imports_a_way_to_run_a_scan():
    """NFR-04: the UI stays unprivileged; a live scan only runs from the terminal."""
    source = PAGE_FILE.read_text(encoding="utf-8")
    for forbidden in ("live_scan", "subprocess", "_run_nmap", "os.system", "Popen"):
        assert forbidden not in source, forbidden


def test_the_command_is_plain_text_so_its_contrast_passes_wcag_aa(monkeypatch):
    """E's FE-E2 audit: shell highlighting coloured "--confirm" at 2.69:1 in the light theme (WCAG AA needs 4.5:1)."""
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    assert show().code[0].language == "plaintext"


def test_romanian_puts_de_after_numbers_of_twenty_or_more(monkeypatch):
    """NFR-09, E's note on #57: "1.000 de porturi", "100 de pachete"."""
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    text = text_of(show(advanced=True))
    assert "cele mai folosite 1.000 de porturi TCP" in text and "cel mult 100 de pachete pe secundă" in text
    assert [page._de(count) for count in (5, 19, 20, 100, 101, 1000)] == ["", "", "de ", "de ", "", "de "]
