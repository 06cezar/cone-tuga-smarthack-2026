"""MACs written inside scan text (banners, page titles, hostnames, vendors, error reasons) are masked by the parser, so
none reaches a finding's evidence, an explanation or the UI (NFR-02; C's FE-C4 case, D's 21:53 review of #53)."""
import pytest

from conetuga.analysis import analyse_file
from conetuga.analysis.parser import mask_macs_in
from conetuga.explain import explain
from nmap_xml import NMAP_FOOTER, NMAP_HEADER, host, port, write_scan

DEVICE_PART = "11:22:33"  # the part of AA:BB:CC:11:22:33 that must never be shown


@pytest.mark.parametrize("written", ["AA:BB:CC:11:22:33", "aa-bb-cc-11-22-33", "AA:BB-CC:11-22:33",
                                     "aabb.cc11.2233"])
def test_every_way_of_writing_a_mac_is_masked(written):
    assert mask_macs_in(f"before {written} after") == "before AA:BB:CC:xx:xx:xx after"


@pytest.mark.parametrize("text", ["OpenSSH 8.4p1 Debian 5+deb11u3", "up 12:34:56", "fe80::1", "3f4e5a6b7c8d", "1.2.3"])
def test_text_that_is_not_a_mac_is_left_as_it_is(text):
    """Versions, times, IPv6 addresses and 12 hex digits with no separator (a Docker container ID) stay unchanged."""
    assert mask_macs_in(text) == text


def test_cs_case_a_mac_in_the_product_never_reaches_the_explanation(tmp_path):
    """C's FE-C4 case: product "vsftpd AA:BB:CC:11:22:33", version 2.3.4. Still FTP_CLEARTEXT and OUTDATED_SERVICE,
    and neither the evidence nor the explanation, in either language, shows the full MAC."""
    path = write_scan(tmp_path, host("10.0.0.1", port(21, "ftp", product="vsftpd AA:BB:CC:11:22:33", version="2.3.4")))
    result = analyse_file(path)
    assert [f.code for f in result.findings] == ["FTP_CLEARTEXT", "OUTDATED_SERVICE"]
    shown = [f.evidence for f in result.findings] + [result.hosts[0].ports[0].product]
    for finding in result.findings:
        for lang in ("ro", "en"):
            explanation = explain(finding, result.hosts[0], lang)
            shown += [explanation.title, explanation.text, *explanation.steps]
    assert not any(DEVICE_PART in text for text in shown)
    assert "AA:BB:CC:xx:xx:xx" in result.hosts[0].ports[0].product


def test_findings_are_the_same_with_or_without_a_mac_in_the_banner(tmp_path):
    plain = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(21, "ftp", product="vsftpd", version="2.3.4")),
                                    name="plain.xml"))
    hostile = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(21, "ftp", product="vsftpd AA:BB:CC:11:22:33",
                                                                      version="2.3.4")), name="hostile.xml"))
    assert ([(f.ip, f.port, f.code) for f in plain.findings], plain.score) == (
        [(f.ip, f.port, f.code) for f in hostile.findings], hostile.score)


@pytest.mark.parametrize("field", ["version", "title", "hostname", "vendor"])
def test_a_mac_in_any_other_scan_text_is_masked(tmp_path, field):
    hostile = "x AA:BB:CC:11:22:33"
    if field == "version":
        hosts = host("10.0.0.1", port(22, "ssh", product="OpenSSH", version=f"9.6 {hostile}"))
    elif field == "title":
        hosts = host("10.0.0.1", port(80, "http", title=f"Router Login {hostile}"))
    else:
        hosts = host("10.0.0.1", port(22, "ssh"), **{field: hostile})
    result = analyse_file(write_scan(tmp_path, hosts))
    assert DEVICE_PART not in repr(result)


def test_a_mac_in_the_page_title_still_lets_the_admin_rule_match(tmp_path):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(80, "http",
                                                                     title="Router Login AA:BB:CC:11:22:33"))))
    assert [f.code for f in result.findings] == ["HTTP_ADMIN_CLEARTEXT"]


def test_a_mac_quoted_in_an_error_reason_is_masked(tmp_path):
    """An unreadable file's reason can quote text from it: a fake IP address that is a MAC must not show in full."""
    path = tmp_path / "bad_address.xml"
    path.write_text(NMAP_HEADER + '<host><status state="up"/><address addr="AA:BB:CC:11:22:33" addrtype="ipv4"/>'
                    "</host>" + NMAP_FOOTER, encoding="utf-8")
    result = analyse_file(path)
    assert result.error and DEVICE_PART not in result.error and "AA:BB:CC:xx:xx:xx" in result.error


def test_the_file_name_is_never_changed(tmp_path):
    """The file name is the `file` column of findings.csv and scores.csv: masking it would break the answer key."""
    path = write_scan(tmp_path, host("10.0.0.1", port(23, "telnet")), name="scan aa-bb-cc-11-22-33.xml")
    result = analyse_file(path)
    assert result.file == "scan aa-bb-cc-11-22-33.xml" and result.findings[0].file == result.file


@pytest.mark.parametrize("hostname, masked", [
    ("box-DE-AD-BE-EF-12-34", "box-DE:AD:BE:xx:xx:xx"),        # C's 22:01 case: nmap hostnames carry MACs with dashes
    ("cafe-DE-AD-BE-EF-12-34", "cafe-DE:AD:BE:xx:xx:xx"),      # hex letters right before it don't hide it
    ("DE-AD-BE-EF-12-34.lan", "DE:AD:BE:xx:xx:xx.lan"),
])
def test_a_mac_with_dashes_inside_a_hostname_is_masked(tmp_path, hostname, masked):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(22, "ssh"), hostname=hostname)))
    assert result.hosts[0].hostname == masked and "EF-12-34" not in repr(result) and "EF:12:34" not in repr(result)
