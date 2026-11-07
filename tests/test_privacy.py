"""MAC addresses are masked in every output (NFR-02; the jury's live check "masked MACs"): only the vendor part, the
first 3 bytes, is ever shown.

The raw MACs are read straight from the scan files, then looked for in everything the tool makes from them: the
analysis, findings.csv and scores.csv, both commands (`analyse`, and `scan` with a fake nmap), the explanations in
both languages, the history on disk, and the web page itself, run headless as in tests/test_ui_app.py. Each MAC is
looked for in every way it could be written (with ":", with "-", with no separator) and by its device part alone."""
import re
import shutil
from pathlib import Path

from streamlit.testing.v1 import AppTest

import conetuga.__main__ as cli
import conetuga.guard.scan as scan
from conetuga.analysis import analyse_file
from conetuga.explain import device_label, explain
from conetuga.guard import Network
from conetuga.guard.export import export
from conetuga.history import save_scan
from nmap_xml import host, port, write_scan

ROOT = Path(__file__).resolve().parent.parent
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
APP = str(ROOT / "ui" / "app.py")
UI_TIMEOUT_SECONDS = 30  # as in tests/test_ui_app.py: a cold Streamlit import on a CI runner takes seconds
SCAN_FILES = sorted(SCANS.iterdir())
HEX_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
# Read from the text, not with the parser under test, so the broken V7 counts too; nmap writes either attribute first.
MAC_IN_XML = re.compile(rf'<address\b[^>]*\baddr="({HEX_MAC})"[^>]*\baddrtype="mac"'
                        rf'|<address\b[^>]*\baddrtype="mac"[^>]*\baddr="({HEX_MAC})"')
MASKED_MAC = re.compile(r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:xx:xx:xx$")
VALIDATION_SET_MACS = 27  # counted once by hand: a parser change that found none would make every test pass


def raw_macs() -> set[str]:
    return {(match.group(1) or match.group(2)).upper()
            for path in SCAN_FILES
            for match in MAC_IN_XML.finditer(path.read_text(encoding="utf-8", errors="replace"))}


def as_read(text: str) -> str:
    """The text as a person reads it: the page escapes markdown characters ("00\\:11\\:32..."), which hide nothing."""
    return text.replace("\\", "")


def leaked(text: str) -> list[str]:
    """The raw MACs that appear in `text` as a person reads it, written in any form, or by their device part (the
    last 3 bytes)."""
    upper = as_read(text).upper()
    return [mac for mac in raw_macs()
            if any(form in upper for form in (mac, mac.replace(":", "-"), mac.replace(":", ""), mac[9:]))]


def test_the_validation_set_has_raw_macs_to_look_for():
    assert len(raw_macs()) == VALIDATION_SET_MACS


def test_no_raw_mac_in_the_analysis():
    for path in SCAN_FILES:
        assert leaked(repr(analyse_file(path))) == [], path.name


def test_every_device_shows_only_the_vendor_part_of_its_mac():
    for path in SCAN_FILES:
        for device in analyse_file(path).hosts:
            assert device.mac_masked == "" or MASKED_MAC.match(device.mac_masked), (path.name, device.ip)


def test_no_raw_mac_in_findings_or_scores_csv(tmp_path):
    export(SCANS, tmp_path)
    for name in ("findings.csv", "scores.csv"):
        assert leaked((tmp_path / name).read_text(encoding="utf-8")) == [], name


def test_no_raw_mac_in_the_command_line_output(tmp_path, capsys):
    cli.main(["analyse", str(SCANS), "--out", str(tmp_path)])
    captured = capsys.readouterr()
    assert leaked(captured.out + captured.err) == []


def test_no_raw_mac_in_any_explanation_or_device_label():
    for path in SCAN_FILES:
        result = analyse_file(path)
        devices = {device.ip: device for device in result.hosts}
        for lang in ("ro", "en"):
            for finding in result.findings:
                assert leaked(repr(explain(finding, devices[finding.ip], lang))) == [], (path.name, finding.code)
            for device in result.hosts:
                assert leaked(device_label(device.device_type, lang)) == [], (path.name, device.ip)


def test_no_raw_mac_in_the_live_scan_output(monkeypatch, tmp_path, capsys):
    """`scan --confirm` on our hotspot, with a fake nmap that writes each scan file where nmap writes its XML."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan, "detect_network",
                        lambda: Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1"))
    monkeypatch.setattr(scan, "wifi_ssid", lambda interface: "RSH-ConeTuga")
    monkeypatch.setattr(scan, "_find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: [80])
    monkeypatch.setattr(scan, "_is_admin", lambda: True)
    shown = []
    for path in SCAN_FILES:
        def fake_nmap(command, path=path):
            shutil.copyfile(path, command[command.index("-oX") + 1])
            return 0

        monkeypatch.setattr(scan, "_run_nmap", fake_nmap)
        cli.main(["scan", "--confirm"])
        captured = capsys.readouterr()
        shown.append(captured.out + captured.err)
    assert "scor 40" in "".join(shown)  # V2 was really analysed and shown
    assert leaked("".join(shown)) == []


def test_no_raw_mac_in_the_history_on_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))
    for path in SCAN_FILES:
        save_scan(analyse_file(path), path.read_bytes())
    stored = "".join(record.read_text(encoding="utf-8") for record in (tmp_path / "history").iterdir())
    assert "mac_masked" in stored and leaked(stored) == []


def page_text(app) -> str:
    """Every text the page shows: headings, paragraphs, notices, device sections and the scan list."""
    elements = [*app.title, *app.subheader, *app.markdown, *app.info, *app.success, *app.warning, *app.error]
    return "\n".join([str(element.value) for element in elements] + [section.label for section in app.expander]
                     + [str(option) for option in app.selectbox[0].options])


def test_no_raw_mac_on_the_web_page(tmp_path, monkeypatch):
    """Every scan in the list, in Romanian, then the last one in English: what the jury will look at."""
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))
    app = AppTest.from_file(APP, default_timeout=UI_TIMEOUT_SECONDS).run()
    shown = []
    for path in SCAN_FILES:
        app.selectbox[0].set_value(path.name).run()
        assert not app.exception, path.name
        shown.append(page_text(app))
    app.radio[0].set_value("English").run()
    shown.append(page_text(app))
    text = "\n".join(shown)
    masked = {device.mac_masked for device in analyse_file(SCANS / "V2_smart_home.xml").hosts if device.mac_masked}
    assert masked and all(mac in as_read(text) for mac in masked)  # the device sections really show the MACs
    assert "MAC (mascat)" in text and "MAC (masked)" in text
    assert leaked(text) == []


def test_lowercase_and_malformed_macs_are_hidden_too(tmp_path):
    """A hostile file may write a MAC in lowercase or in a shape nmap never writes: the device part never shows."""
    scan = write_scan(tmp_path,
                      host("10.0.0.2", port(80, "http"), mac="aa:bb:cc:dd:ee:f1"),
                      host("10.0.0.3", port(80, "http"), mac="AA:BB:CC:DD:EE:F2:00"),
                      host("10.0.0.4", port(80, "http"), mac="AABBCCDDEEF3"))
    result = analyse_file(scan)
    assert [device.mac_masked for device in result.hosts] == ["AA:BB:CC:xx:xx:xx", "xx:xx:xx:xx:xx:xx",
                                                              "xx:xx:xx:xx:xx:xx"]
    text = repr(result).upper()
    for device_part in ("DD:EE:F1", "DD:EE:F2", "DDEEF3"):
        assert device_part not in text, device_part
