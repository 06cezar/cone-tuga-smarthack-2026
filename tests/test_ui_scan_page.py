"""The Scanare page (FE-C1): the network (FR-01), the guardrail's verdict (FR-02), the "Scanează acum" button and the
command to run. The button scans only through scan_from_app, behind the guardrail and the tick (NFR-04). The network
and the scan are fakes: no test reads this computer's network or runs nmap."""
import os
import shutil
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import conetuga.guard.scan as live
import ui.pages.scan as page
from conetuga import ledger
from conetuga.guard import Network, NetworkNotFound
from conetuga.guard.scan import LiveScan, PasswordWindowRefused, ScanRefused
from conetuga.history import load_history

TIMEOUT_SECONDS = 30  # as in tests/test_ui_app.py: a cold Streamlit import on a CI runner takes seconds
HOTSPOT = Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1")
VENUE = Network("wlp0s20f3", "10.240.7.21", "10.240.0.0/16", "10.240.0.1")
PAGE_FILE = Path(__file__).resolve().parents[1] / "ui" / "pages" / "scan.py"
V1 = Path(__file__).resolve().parent / "fixtures" / "validation" / "scans" / "V1_home_basic.xml"


@pytest.fixture(autouse=True)
def nothing_runs(monkeypatch):
    """No test starts a scan: every way to nmap fails the test, unless a test replaces scan_from_app with a fake."""
    def forbidden(*args, **kwargs):
        raise AssertionError("the Scanare page tried to scan")

    monkeypatch.setattr(live, "live_scan", forbidden)
    monkeypatch.setattr(live, "_run_nmap", forbidden)
    monkeypatch.setattr(live, "_run_nmap_for_xml", forbidden)
    monkeypatch.setattr(live, "_run_as_admin", forbidden)
    monkeypatch.setattr(page, "scan_from_app", forbidden)
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


def test_the_page_scans_only_through_scan_from_app():
    """NFR-04: the UI stays unprivileged. Its one way to a scan is scan_from_app, which asks the guardrail first and
    gives the rights to nmap alone; the page never starts a program or asks for rights itself."""
    source = PAGE_FILE.read_text(encoding="utf-8")
    for forbidden in ("live_scan", "subprocess", "_run_nmap", "_run_as_admin", "os.system", "Popen", "pkexec",
                      "ShellExecute", "sudo", "password_input", 'type="password"'):
        assert forbidden not in source, forbidden
    assert source.count("scan_from_app(") == 1


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


# --- the "Scanează acum" button (scan_from_app) ------------------------------------------------------------------

def as_read(value: str) -> str:
    """The text as a person reads it: md() escapes punctuation with backslashes the screen doesn't show."""
    return value.replace("\\", "")


def button(app: AppTest):
    return next(b for b in app.button if "Scan" in b.label)


def fake_scan(monkeypatch, tmp_path, timed_out=()) -> list[bool]:
    """scan_from_app as it answers after a good scan: a copy of V1 where nmap's XML would land."""
    calls = []

    def scan_from_app(confirmed):
        calls.append(confirmed)
        xml = tmp_path / "scan_20261108-091500.xml"
        shutil.copyfile(V1, xml)
        return LiveScan(network=HOTSPOT, ssid="RSH-ConeTuga", scanned="172.20.10.0/28", xml=xml, minutes=5,
                        timed_out=tuple(timed_out))

    monkeypatch.setattr(page, "scan_from_app", scan_from_app)
    return calls


def test_on_our_hotspot_the_button_waits_for_the_tick(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    app = show()
    assert button(app).disabled and not app.checkbox[0].disabled
    assert "Confirm că vreau să scanez rețeaua asta" == app.checkbox[0].label
    app.checkbox[0].check().run()
    assert not button(app).disabled


def test_on_the_venue_wifi_the_tick_and_the_button_stay_off(monkeypatch):
    on(monkeypatch, VENUE, "UnivBuc Free")
    app = show(language="English")
    assert app.checkbox[0].disabled and button(app).disabled


def test_with_no_network_there_is_no_button(monkeypatch):
    def no_network():
        raise NetworkNotFound("Laptopul nu este conectat la nicio rețea.\nThe laptop is not connected to any network.")

    monkeypatch.setattr(page, "detect_network", no_network)
    app = show()
    assert not [b for b in app.button if "Scan" in b.label]


def test_a_scan_from_the_button_lands_in_the_history_and_points_to_home(monkeypatch, tmp_path):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    calls = fake_scan(monkeypatch, tmp_path)
    app = show()
    app.checkbox[0].check().run()
    button(app).click().run()
    assert not app.exception and calls == [True]
    assert any("scor 90, 3 dispozitive, 1 problemă" in s.value for s in app.success), [s.value for s in app.success]
    assert "Acasă" in text_of(app)
    assert [record.result.score for record in load_history()] == [90]


def test_a_device_nmap_gave_up_on_is_named(monkeypatch, tmp_path):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    fake_scan(monkeypatch, tmp_path, timed_out=["172.20.10.2"])
    app = show(language="English")
    app.checkbox[0].check().run()
    button(app).click().run()
    warnings = [as_read(w.value) for w in app.warning]
    assert any("172.20.10.2 didn't finish within 5 minutes" in w and "--minutes 10" in w for w in warnings), warnings


def test_a_refused_password_window_says_so_shows_the_command_and_saves_nothing(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")

    def refused(confirmed):
        raise PasswordWindowRefused("Fereastra de parolă a fost închisă.\nThe password window was closed.")

    monkeypatch.setattr(page, "scan_from_app", refused)
    app = show(language="English")
    app.checkbox[0].check().run()
    button(app).click().run()
    warnings = [as_read(w.value) for w in app.warning]
    assert any("The password window was closed." in w and "terminal" in w for w in warnings), warnings
    assert app.code[0].value.endswith("scan --confirm") and not app.success[1:]
    assert load_history() == []


def test_a_guardrail_refusal_from_the_button_is_shown_escaped(monkeypatch):
    """The laptop left the hotspot after the page loaded: scan_from_app asks the guardrail again and says no."""
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")

    def refused(confirmed):
        raise ScanRefused("Nu ești pe hotspot.\nNot on our hotspot: [Free](http://x.y)")

    monkeypatch.setattr(page, "scan_from_app", refused)
    app = show(language="English")
    app.checkbox[0].check().run()
    button(app).click().run()
    shown = "\n".join(e.value for e in app.error)
    assert "Not on our hotspot" in shown and "[Free](http://x.y)" not in shown and "Free" in as_read(shown)
    assert load_history() == []


def test_on_windows_the_page_names_the_uac_window(monkeypatch):
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    monkeypatch.setattr(page, "_on_windows", lambda: True)
    assert "UAC" in text_of(show(language="English"))


# --- after a scan from the button: the findings log's batches go on the chain, as with the CLI -------------------

CHAIN_ENV_FILE = ("CONETUGA_CHAIN_RPC_URL=http://127.0.0.1:8545\n"
                  "CONETUGA_CHAIN_CONTRACT=0x5FbDB2315678afecb367f032d93F642f64180aa3\n"
                  "CONETUGA_CHAIN_PRIVATE_KEY=0xtest-key-of-this-test\n")


def scan_from_the_button(monkeypatch, tmp_path, language: str = "English") -> AppTest:
    on(monkeypatch, HOTSPOT, "RSH-ConeTuga")
    fake_scan(monkeypatch, tmp_path)
    app = show(language=language)
    app.checkbox[0].check().run()
    button(app).click().run()
    assert not app.exception
    return app


def chain_in_env_file(monkeypatch, tmp_path) -> None:
    path = tmp_path / "test.env"
    path.write_text(CHAIN_ENV_FILE, encoding="utf-8")
    monkeypatch.setenv("CONETUGA_ENV_FILE", str(path))


def test_with_the_chain_in_env_the_button_anchors_the_full_batches(monkeypatch, tmp_path):
    chain_in_env_file(monkeypatch, tmp_path)
    sent_with = []
    monkeypatch.setattr(ledger, "anchor_pending", lambda settings: sent_with.append(settings) or [(0, "0xabc123")])
    app = scan_from_the_button(monkeypatch, tmp_path)
    assert [s.rpc_url for s in sent_with] == ["http://127.0.0.1:8545"]
    assert "batch(es) 0" in as_read(text_of(app)) and "0xabc123" in text_of(app)
    assert "CONETUGA_CHAIN_RPC_URL" not in os.environ  # .env read, the app's environment unchanged


def test_without_a_chain_the_button_never_reaches_one(monkeypatch, tmp_path):
    def forbidden(settings):
        raise AssertionError("the page tried to reach a chain with none set up")

    monkeypatch.setattr(ledger, "anchor_pending", forbidden)
    app = scan_from_the_button(monkeypatch, tmp_path)
    assert "Blockchain" not in text_of(app)


def test_a_chain_that_refuses_is_a_warning_and_the_scan_still_stands(monkeypatch, tmp_path):
    chain_in_env_file(monkeypatch, tmp_path)

    def unreachable(settings):
        raise ledger.LedgerError("Blockchain-ul nu răspunde.\nThe chain doesn't answer.")

    monkeypatch.setattr(ledger, "anchor_pending", unreachable)
    app = scan_from_the_button(monkeypatch, tmp_path)
    warnings = [as_read(w.value) for w in app.warning]
    assert any("didn't reach the blockchain" in w and "The chain doesn't answer." in w for w in warnings), warnings
    assert any("score 90" in s.value for s in app.success) and load_history()


def test_no_new_full_batch_is_said_plainly(monkeypatch, tmp_path):
    chain_in_env_file(monkeypatch, tmp_path)
    monkeypatch.setattr(ledger, "anchor_pending", lambda settings: [])
    app = scan_from_the_button(monkeypatch, tmp_path, language="Română")
    assert "niciun lot nou de 10 constatări" in as_read(text_of(app))
