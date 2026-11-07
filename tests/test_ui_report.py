"""The one-page report (ui/report.py, FR-14): it says what the page says, in both languages, with only masked MACs, with
scan text escaped, and with the same bytes for the same inputs."""
import re
from dataclasses import replace
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from ui.report import html_report

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
LAB = Path(__file__).resolve().parents[1] / "lab" / "scans"


def report(name: str, lang: str = "ro", **kwargs) -> str:
    return html_report(analyse_file(SCANS / name), lang, **kwargs)


def test_report_shows_the_standard_score_and_the_headline():
    html = report("V2_smart_home.xml")
    assert "Scor standard: 40/100" in html
    assert "Cel mai periculos" in html and "Fă asta întâi" in html


def test_report_lists_every_finding_with_its_device_and_port():
    result = analyse_file(SCANS / "V4_legacy.xml")
    html = html_report(result, "en")
    sections = html.count("<section>")
    assert sections == len(result.findings)
    for finding in result.findings:
        assert f"({finding.ip})" in html
        if finding.port is not None:
            assert f"port {finding.port}/{finding.proto}" in html


def test_report_lists_every_device_once_also_those_without_findings():
    """V1's laptop and phone have no findings: the supplier still sees every device on the network."""
    result = analyse_file(SCANS / "V1_home_basic.xml")
    html = html_report(result, "en")
    rows = re.findall(r"<tr><td>", html)
    assert len(rows) == len(result.hosts) == 3
    assert all(f"<td>{host.ip}</td>" in html for host in result.hosts)


def test_report_comes_in_both_languages():
    ro, en = report("V1_home_basic.xml", "ro"), report("V1_home_basic.xml", "en")
    assert '<html lang="ro">' in ro and "Raport de securitate a rețelei" in ro
    assert '<html lang="en">' in en and "Network security report" in en


def test_report_shows_only_masked_macs():
    """The Validation Set's raw MACs, by their device part, never reach the report (NFR-02)."""
    raw = (SCANS / "V1_home_basic.xml").read_text(encoding="utf-8")
    device_parts = {mac[9:] for mac in re.findall(r'addr="([0-9A-F:]{17})" addrtype="mac"', raw)}
    html = report("V1_home_basic.xml", "en")
    assert device_parts and not any(part in html for part in device_parts)
    assert "50:C7:BF:xx:xx:xx" in html


def test_hostile_scan_text_is_escaped(tmp_path):
    """A page title or hostname with markup stays text: no <script> tag reaches the report (NFR-03)."""
    result = analyse_file(SCANS / "V1_home_basic.xml")
    hostile = "<script>alert(1)</script>"
    host = replace(result.hosts[0], hostname=hostile, vendor=hostile)
    html = html_report(replace(result, hosts=[host, *result.hosts[1:]]), "en")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_same_inputs_give_the_same_bytes():
    assert report("V2_smart_home.xml", "en", date="2026-11-07") == report("V2_smart_home.xml", "en", date="2026-11-07")


def test_no_date_unless_one_is_given():
    """The report never reads the clock: a re-run gives the same file."""
    assert "Date:" not in report("V1_home_basic.xml", "en")
    assert "Date: 2026-11-07" in report("V1_home_basic.xml", "en", date="2026-11-07")


def test_report_without_findings_says_so():
    assert "No problems found in this scan." in report("V6b_after.xml", "en")


def test_before_and_after_lists_the_resolved_findings():
    before = analyse_file(SCANS / "V6a_before.xml")
    html = html_report(analyse_file(SCANS / "V6b_after.xml"), "en", before=before)
    assert "Standard score 60 → 100" in html
    assert html.count("✅ Resolved") == len(before.findings) == 3


def test_our_lab_before_and_after():
    html = html_report(analyse_file(LAB / "scan_03.xml"), "ro", before=analyse_file(LAB / "scan_01.xml"))
    assert "Scor standard 0 → 70" in html and html.count("✅ Rezolvate") == 4


def test_no_before_and_after_section_without_an_earlier_scan():
    assert "Before and after" not in report("V6b_after.xml", "en")


def test_report_has_no_scripts_and_no_outside_resources():
    """One self-contained file: nothing runs and nothing is fetched when the IT supplier opens it."""
    html = report("V2_smart_home.xml", "en", before=analyse_file(SCANS / "V2_smart_home.xml"))
    assert "<script" not in html and "http://" not in html and "https://" not in html and "src=" not in html


def test_an_unreadable_scan_has_no_report():
    with pytest.raises(ValueError):
        html_report(analyse_file(SCANS / "V7_broken.xml"), "en")


def test_unknown_language_is_refused():
    with pytest.raises(KeyError):
        report("V1_home_basic.xml", "fr")


APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
APP_TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


@pytest.fixture
def page(tmp_path, monkeypatch):
    """The whole page, run headless, with its history in a temporary folder (never the real .history/)."""
    app_test = pytest.importorskip("streamlit.testing.v1").AppTest
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))
    return app_test.from_file(APP, default_timeout=APP_TIMEOUT_SECONDS).run()


def test_the_page_offers_the_report_in_both_languages(page):
    assert not page.exception
    assert [b.proto.label for b in page.get("download_button")] == [
        "📄 Descarcă raportul (o pagină, pentru furnizorul IT sau asigurator)"]
    page.radio[0].set_value("English").run()
    assert [b.proto.label for b in page.get("download_button")] == [
        "📄 Download the report (one page, for your IT supplier or insurer)"]


def test_a_broken_scan_offers_no_report(page):
    page.selectbox[0].set_value("V7_broken.xml").run()
    assert not page.exception and page.error and not page.get("download_button")
