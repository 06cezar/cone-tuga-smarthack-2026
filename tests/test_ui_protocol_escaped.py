"""A port's protocol comes from the scan file, so it is outside text like a banner (NFR-03). A's review of #59: a hostile
protocol="[click](https://evil.example)" showed as a clickable link in a finding's card. Two layers stop it now: A's
parser refuses any protocol nmap never writes (#63, tests/test_traps.py), and the UI escapes the protocol with view.md.
These tests check the UI layer on its own: the hostile value is put into the result after the parser, as if a future
parser change let one through."""
import dataclasses

import pytest

from nmap_xml import host, port, write_scan

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

HOSTILE = "[click](https://evil.example)"
ESCAPED = "\\[click\\]\\(https\\:"
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def with_protocol(result, proto: str):
    """The same FileResult with every port's and finding's protocol replaced (UNKNOWN_DEVICE has no port: kept)."""
    hosts = [dataclasses.replace(h, ports=[dataclasses.replace(p, proto=proto) for p in h.ports])
             for h in result.hosts]
    findings = [dataclasses.replace(f, proto=proto) if f.port is not None else f for f in result.findings]
    return dataclasses.replace(result, hosts=hosts, findings=findings)


def page_text(app) -> str:
    return "\n".join([m.value for m in app.markdown] + [w.value for w in app.warning])


def run(script: str):
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def test_a_hostile_protocol_is_plain_text_in_a_finding_card(tmp_path):
    scan = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet")))
    app = run("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from test_ui_protocol_escaped import HOSTILE, with_protocol\nfrom ui.state import remember_scan\n"
              f"remember_scan(with_protocol(analyse_file(Path({str(scan)!r})), HOSTILE))\n"
              "from ui.pages import devices\ndevices.render()")
    text = page_text(app)
    assert ESCAPED in text and HOSTILE not in text


def test_a_hostile_protocol_is_plain_text_in_the_history_changes(tmp_path):
    before = write_scan(tmp_path, host("10.0.0.5", port(80, "http")), name="before.xml")
    after = write_scan(tmp_path, host("10.0.0.5", port(80, "http"), port(23, "telnet")), name="after.xml")
    app = run("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from test_ui_protocol_escaped import HOSTILE, with_protocol\nfrom ui.pages.home import show_diff\n"
              f"show_diff(analyse_file(Path({str(before)!r})), "
              f"with_protocol(analyse_file(Path({str(after)!r})), HOSTILE), 'ro')")
    text = page_text(app)
    assert ESCAPED in text and HOSTILE not in text
