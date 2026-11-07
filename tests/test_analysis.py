"""analyse_file: the contract with the other streams, and reading scan files safely (FR-05, NFR-03, NFR-05)."""
from pathlib import Path

import pytest

import conetuga.analysis.parser as parser
from conetuga.analysis import Finding, analyse_file
from nmap_xml import NMAP_HEADER, host, port, write_scan

SCANS = Path(__file__).resolve().parent / "fixtures" / "validation" / "scans"


def test_contract_analyse_file():
    """The example in specs/contracts.md: V1 gives one finding and a score of 90."""
    result = analyse_file(SCANS / "V1_home_basic.xml")
    assert result.error == ""
    assert result.score == 90
    assert [(f.file, f.ip, f.port, f.proto, f.code, f.severity, f.points) for f in result.findings] == [
        ("V1_home_basic.xml", "192.168.1.1", 80, "tcp", "HTTP_ADMIN_CLEARTEXT", "medium", 10)
    ]
    assert all(isinstance(f, Finding) and f.evidence for f in result.findings)


def test_contract_analyse_file_broken_file():
    """The contract's error case: a truncated file (V7) gives no hosts, no findings, no score and a clear error."""
    result = analyse_file(SCANS / "V7_broken.xml")
    assert (result.hosts, result.findings, result.score) == ([], [], None)
    assert "V7_broken.xml" in result.error and "XML" in result.error


def test_same_file_gives_the_same_result_every_time():
    for path in sorted(SCANS.iterdir()):
        assert analyse_file(path) == analyse_file(path), path.name


def test_empty_file_is_an_error(tmp_path):
    path = tmp_path / "empty.xml"
    path.write_bytes(b"")
    result = analyse_file(path)
    assert result.score is None and "empty" in result.error


def test_truncated_file_gives_no_findings_from_its_first_half(tmp_path):
    """A recovering parser would report the telnet host before the cut; that row would be an extra row."""
    complete = write_scan(tmp_path, host("10.0.0.1", port(23, "telnet")), host("10.0.0.2", port(22, "ssh")))
    truncated = tmp_path / "truncated.xml"
    text = complete.read_text(encoding="utf-8")
    truncated.write_text(text[: text.index('<address addr="10.0.0.2"')], encoding="utf-8")
    result = analyse_file(truncated)
    assert (result.hosts, result.findings, result.score) == ([], [], None)
    assert result.error


def test_xml_external_entities_are_refused(tmp_path):
    path = tmp_path / "xxe.xml"
    path.write_text('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                    "<nmaprun>&x;</nmaprun>", encoding="utf-8")
    result = analyse_file(path)
    assert result.score is None and result.error


def test_xml_that_is_not_an_nmap_scan_is_an_error(tmp_path):
    path = tmp_path / "other.xml"
    path.write_text("<?xml version='1.0'?><catalog><book/></catalog>", encoding="utf-8")
    result = analyse_file(path)
    assert result.score is None and "not an nmap scan" in result.error


def test_file_larger_than_the_limit_is_an_error(tmp_path, monkeypatch):
    path = write_scan(tmp_path, host("10.0.0.1", port(23, "telnet")))
    monkeypatch.setattr(parser, "MAX_SCAN_BYTES", path.stat().st_size - 1)
    result = analyse_file(path)
    assert result.score is None and "too large" in result.error


def test_missing_file_is_an_error(tmp_path):
    result = analyse_file(tmp_path / "missing.xml")
    assert result.score is None and "can't be opened" in result.error


def test_host_address_that_is_not_an_ip_is_an_error(tmp_path):
    path = write_scan(tmp_path, host("not-an-ip", port(23, "telnet")))
    result = analyse_file(path)
    assert result.score is None and "not an IP address" in result.error


def test_port_number_that_is_not_a_number_is_an_error(tmp_path):
    path = tmp_path / "bad_port.xml"
    path.write_text(NMAP_HEADER + '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                    '<ports><port protocol="tcp" portid="eighty"><state state="open"/></port></ports></host>'
                    "</nmaprun>", encoding="utf-8")
    result = analyse_file(path)
    assert result.score is None and "port number" in result.error


def test_hosts_that_are_down_are_skipped(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), state="down"))
    result = analyse_file(path)
    assert (result.hosts, result.findings, result.score) == ([], [], 100)


def test_valid_scan_without_hosts_scores_100(tmp_path):
    result = analyse_file(write_scan(tmp_path))
    assert (result.error, result.score) == ("", 100)


def test_mac_is_masked_keeping_only_the_vendor_part(tmp_path):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", mac="a4:5e:60:12:34:56")))
    assert result.hosts[0].mac_masked == "A4:5E:60:xx:xx:xx"


def test_raw_mac_appears_nowhere_in_the_result(tmp_path):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), mac="A4:5E:60:12:34:56")))
    assert "12:34:56" not in repr(result)


def test_malformed_mac_is_hidden_completely():
    assert parser.mask_mac("not-a-mac") == "xx:xx:xx:xx:xx:xx"


def test_only_open_ports_are_kept(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(22, "ssh"), port(23, "telnet", state="closed"),
                                     port(161, "snmp", proto="udp", state="open|filtered")))
    assert [(p.port, p.proto) for p in analyse_file(path).hosts[0].ports] == [(22, "tcp")]


def test_title_is_read_from_the_title_element(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(80, "http", title="Welcome")))
    assert analyse_file(path).hosts[0].ports[0].title == "Welcome"


@pytest.mark.parametrize("name", ["scan.xml", "scan.txt", "scan"])
def test_file_extension_does_not_matter(tmp_path, name):
    """export reads every file of the Test Set folder, whatever its extension (specs/contracts.md, "export")."""
    path = write_scan(tmp_path, host("10.0.0.1", port(23, "telnet")), name=name)
    assert analyse_file(path).score == 80
