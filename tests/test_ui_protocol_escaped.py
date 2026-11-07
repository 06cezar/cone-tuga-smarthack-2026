"""A port's protocol comes from the scan file, so it is outside text like a banner (NFR-03). A's review of #59: a hostile
protocol="[click](https://evil.example)" showed as a clickable link in a finding's card. The cards and the history's
port lines now escape it with view.md; A's parser will also accept only nmap's protocols (a second layer, A's PR)."""
import pytest

from nmap_xml import host, port, write_scan

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

HOSTILE = "[click](https://evil.example)"
ESCAPED = "\\[click\\]\\(https\\:"
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def page_text(app) -> str:
    return "\n".join([m.value for m in app.markdown] + [w.value for w in app.warning])


def test_a_hostile_protocol_is_plain_text_in_a_finding_card(tmp_path):
    scan = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet", proto=HOSTILE)))
    script = ("import streamlit as st\nfrom pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              f"from ui.state import remember_scan\nremember_scan(analyse_file(Path({str(scan)!r})))\n"
              "from ui.pages import devices\ndevices.render()")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    text = page_text(app)
    assert ESCAPED in text and HOSTILE not in text


def test_a_hostile_protocol_is_plain_text_in_the_history_changes(tmp_path):
    before = write_scan(tmp_path, host("10.0.0.5", port(80, "http")), name="before.xml")
    after = write_scan(tmp_path, host("10.0.0.5", port(80, "http"), port(23, "telnet", proto=HOSTILE)),
                       name="after.xml")
    script = ("import streamlit as st\nfrom pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from ui.pages.home import show_diff\n"
              f"show_diff(analyse_file(Path({str(before)!r})), analyse_file(Path({str(after)!r})), 'ro')")
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    text = page_text(app)
    assert ESCAPED in text and HOSTILE not in text
