"""A host's IP address comes from the scan file, so it is outside text like a banner (NFR-03). Python's ipaddress
accepts an IPv6 zone after "%" holding almost any text ("fe80::1%[x](tel:0900123123)"), so a hostile file could put a
clickable phone number in a device card, in findings.csv and in the local model's evidence (NFR-06: no invented phone
numbers). Two layers stop it: the parser refuses a zone, which nmap never writes, and the UI escapes the IP with md().
The UI tests put the hostile value in after the parser, as if a future parser change let one through."""
import dataclasses

import pytest

from conetuga.analysis import analyse_file
from nmap_xml import NMAP_FOOTER, NMAP_HEADER, host, port, write_scan

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

HOSTILE = "fe80::1%[x](tel:0900123123)"  # a valid address for ipaddress, so sorting by IP doesn't stop it
LINK = "[x](tel:"
ESCAPED = "\\[x\\]\\(tel\\:"
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def zone_scan(tmp_path, address: str):
    path = tmp_path / "zone.xml"
    path.write_text(NMAP_HEADER + f'<host><status state="up"/><address addr="{address}" addrtype="ipv6"/>'
                    '<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
                    '</ports></host>\n' + NMAP_FOOTER, encoding="utf-8")
    return path


@pytest.mark.parametrize("address", [HOSTILE, "fe80::1%eth0", "fe80::1%Sună la 0900 123 123"])
def test_an_ipv6_zone_makes_the_file_an_error_without_echoing_it(tmp_path, address):
    result = analyse_file(zone_scan(tmp_path, address))
    assert result.score is None and result.hosts == [] and result.findings == []
    assert "zone" in result.error and address.split("%")[1] not in result.error


def test_an_ipv6_address_without_a_zone_still_reads(tmp_path):
    result = analyse_file(zone_scan(tmp_path, "fe80::1"))
    assert result.error == "" and [f.ip for f in result.findings if f.code == "TELNET_OPEN"] == ["fe80::1"]


def with_ip(result, ip: str):
    """The same FileResult with every host's and finding's IP replaced (the scan has one host)."""
    hosts = [dataclasses.replace(h, ip=ip) for h in result.hosts]
    findings = [dataclasses.replace(f, ip=ip) for f in result.findings]
    return dataclasses.replace(result, hosts=hosts, findings=findings)


def page_text(app) -> str:
    return "\n".join([m.value for m in app.markdown] + [w.value for w in app.warning]
                     + [e.label for e in app.expander])


def run(script: str):
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


@pytest.mark.parametrize("advanced", [False, True])
def test_a_hostile_ip_is_plain_text_in_a_device_card(tmp_path, advanced):
    scan = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet")))
    app = run("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from test_hostile_ip import HOSTILE, with_ip\nfrom ui.view import devices_by_risk\n"
              "from ui.cards import show_device\n"
              f"result = with_ip(analyse_file(Path({str(scan)!r})), HOSTILE)\n"
              f"show_device(devices_by_risk(result, 'ro')[0], 'ro', True, {advanced}, result)")
    labels = "\n".join(e.label for e in app.expander)
    assert ESCAPED in labels and LINK not in labels


def test_a_hostile_ip_is_plain_text_in_a_home_tile(tmp_path):
    scan = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet")))
    app = run("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from test_hostile_ip import HOSTILE, with_ip\nfrom ui.view import devices_by_risk\n"
              "from ui.checkup import show_home_map\n"
              f"show_home_map(devices_by_risk(with_ip(analyse_file(Path({str(scan)!r})), HOSTILE), 'ro'), 'ro')")
    text = page_text(app)
    assert ESCAPED in text and LINK not in text


def test_a_hostile_ip_is_plain_text_in_the_history_changes(tmp_path):
    before = write_scan(tmp_path, host("10.0.0.5", port(80, "http")), name="before.xml")
    after = write_scan(tmp_path, host("10.0.0.5", port(80, "http"), port(23, "telnet")), name="after.xml")
    # Every IP hostile in one scan and plain in the other: the device shows as removed and as new.
    app = run("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
              "from test_hostile_ip import HOSTILE, with_ip\nfrom ui.pages.history import show_diff\n"
              f"before, after = analyse_file(Path({str(before)!r})), analyse_file(Path({str(after)!r}))\n"
              "show_diff(before, with_ip(after, HOSTILE), 'ro')\n"
              "show_diff(with_ip(before, HOSTILE), after, 'ro')")
    text = page_text(app)
    assert text.count(ESCAPED) >= 2 and LINK not in text


@pytest.mark.parametrize("ip", ["192.168.1.1", "fd00::5", "FE80::1"])
def test_a_plain_ip_is_shown_as_written(ip):
    from ui.view import ip_md
    assert ip_md(ip) == ip


def test_anything_else_in_an_ip_is_escaped():
    from ui.view import ip_md
    assert ip_md(HOSTILE).startswith("fe80\:\:1%" + ESCAPED)
