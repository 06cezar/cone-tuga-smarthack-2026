"""The official catalog's detection rules (FR-06) and the standard score (FR-09), one behaviour per test.

Each test builds a small scan of its own, so the rules are checked as the brief states them, independently of the
Validation Set, which tests/test_validation_set.py checks as a whole."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from nmap_xml import host, port, write_scan


def rows(tmp_path: Path, *hosts: str) -> list[tuple]:
    """(ip, port, code) of every finding of a scan made of these hosts."""
    return [(f.ip, f.port, f.code) for f in analyse_file(write_scan(tmp_path, *hosts)).findings]


def test_telnet_on_a_nonstandard_port_is_telnet_open(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", port(2323, "telnet"))) == [("10.0.0.1", 2323, "TELNET_OPEN")]


def test_well_known_port_with_another_service_is_not_that_finding(tmp_path):
    """Decided by the service name, not the port number: 23 running ssh is SSH_OPEN, not TELNET_OPEN."""
    assert rows(tmp_path, host("10.0.0.1", port(23, "ssh"))) == [("10.0.0.1", 23, "SSH_OPEN")]


@pytest.mark.parametrize("service, code", [
    ("telnet", "TELNET_OPEN"), ("ms-wbt-server", "RDP_EXPOSED"), ("vnc", "VNC_EXPOSED"),
    ("mysql", "DB_EXPOSED"), ("postgresql", "DB_EXPOSED"), ("redis", "DB_EXPOSED"), ("mongodb", "DB_EXPOSED"),
    ("rtsp", "CAMERA_STREAM_EXPOSED"), ("ftp", "FTP_CLEARTEXT"), ("mqtt", "MQTT_EXPOSED"),
    ("jetdirect", "PRINTER_RAW_EXPOSED"), ("ssh", "SSH_OPEN"),
])
def test_each_catalog_service_gives_its_code(tmp_path, service, code):
    assert rows(tmp_path, host("10.0.0.1", port(4000, service))) == [("10.0.0.1", 4000, code)]


@pytest.mark.parametrize("service", ["ipp", "domain", "ajp13", "sun-answerbook", "http-proxy", ""])
def test_service_not_in_the_catalog_gives_no_finding(tmp_path, service):
    assert rows(tmp_path, host("10.0.0.1", port(8000, service))) == []


@pytest.mark.parametrize("state", ["filtered", "closed", "open|filtered"])
def test_port_that_is_not_open_gives_no_finding(tmp_path, state):
    assert rows(tmp_path, host("10.0.0.1", port(3306, "mysql", state=state))) == []


def test_http_admin_page_without_ssl_is_admin_cleartext(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(8080, "http", title="Device Settings")))
    assert found == [("10.0.0.1", 8080, "HTTP_ADMIN_CLEARTEXT")]


@pytest.mark.parametrize("keyword", ["login", "admin", "config", "setup", "router", "settings"])
def test_each_title_keyword_counts(tmp_path, keyword):
    found = rows(tmp_path, host("10.0.0.1", port(80, "http", title=f"My {keyword} page")))
    assert found == [("10.0.0.1", 80, "HTTP_ADMIN_CLEARTEXT")]


def test_title_keyword_match_ignores_case(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(80, "http", title="PLEASE LOGIN")))
    assert found == [("10.0.0.1", 80, "HTTP_ADMIN_CLEARTEXT")]


def test_https_admin_page_is_not_admin_cleartext(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", port(8443, "http", tunnel="ssl", title="Admin Login"))) == []


def test_http_without_a_title_is_not_admin_cleartext(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", port(80, "http"))) == []


def test_http_title_without_a_keyword_is_not_admin_cleartext(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", port(80, "http", title="Welcome to nginx!"))) == []


def test_redirect_text_is_not_a_title(tmp_path):
    """nmap writes "Did not follow redirect to .../login" as the script output; that "login" is not a page title."""
    redirect = "Did not follow redirect to http://10.0.0.1/login.html"
    assert rows(tmp_path, host("10.0.0.1", port(80, "http", title_output=redirect))) == []


def test_upnp_counts_only_on_udp(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(1900, "upnp", proto="udp"), port(5000, "upnp", proto="tcp")))
    assert found == [("10.0.0.1", 1900, "UPNP_EXPOSED")]


def test_snmp_counts_only_on_udp(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(161, "snmp", proto="udp"), port(1161, "snmp", proto="tcp")))
    assert found == [("10.0.0.1", 161, "SNMP_EXPOSED")]


def test_smb_on_both_ports_gives_one_finding_on_445(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(139, "netbios-ssn"), port(445, "microsoft-ds")))
    assert found == [("10.0.0.1", 445, "SMB_EXPOSED")]


def test_smb_only_on_139_is_reported_on_139(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", port(139, "netbios-ssn"))) == [("10.0.0.1", 139, "SMB_EXPOSED")]


def test_smb_is_one_finding_per_device_not_per_scan(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(445, "microsoft-ds")), host("10.0.0.2", port(445, "microsoft-ds")))
    assert found == [("10.0.0.1", 445, "SMB_EXPOSED"), ("10.0.0.2", 445, "SMB_EXPOSED")]


def test_outdated_version_adds_a_second_row_on_the_same_port(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(21, "ftp", product="vsftpd", version="2.3.4")))
    assert found == [("10.0.0.1", 21, "FTP_CLEARTEXT"), ("10.0.0.1", 21, "OUTDATED_SERVICE")]


def test_outdated_version_is_reported_without_a_finding_of_its_own(tmp_path):
    """Apache 2.2 serving a page with no admin title has no HTTP finding, but its version is still on the list."""
    found = rows(tmp_path, host("10.0.0.1", port(80, "http", product="Apache httpd", version="2.2.15")))
    assert found == [("10.0.0.1", 80, "OUTDATED_SERVICE")]


def test_old_samba_on_both_ports_gives_one_outdated_row_on_445(tmp_path):
    samba = {"product": "Samba smbd", "version": "3.6.25"}
    found = rows(tmp_path, host("10.0.0.1", port(139, "netbios-ssn", **samba), port(445, "microsoft-ds", **samba)))
    assert found == [("10.0.0.1", 445, "OUTDATED_SERVICE"), ("10.0.0.1", 445, "SMB_EXPOSED")]


def test_current_version_gives_no_outdated_row(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(22, "ssh", product="OpenSSH", version="9.6p1")))
    assert found == [("10.0.0.1", 22, "SSH_OPEN")]


def test_unknown_device_has_no_vendor_no_hostname_and_an_open_port(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(8888, "sun-answerbook"), vendor="", hostname=""))
    assert found == [("10.0.0.1", None, "UNKNOWN_DEVICE")]


def test_host_with_no_mac_address_at_all_counts_as_no_vendor(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(8888, "sun-answerbook"), mac=None, hostname=""))
    assert found == [("10.0.0.1", None, "UNKNOWN_DEVICE")]


@pytest.mark.parametrize("vendor, hostname", [("Acme", ""), ("", "kitchen-box")])
def test_vendor_or_hostname_identifies_a_device(tmp_path, vendor, hostname):
    assert rows(tmp_path, host("10.0.0.1", port(8888, "sun-answerbook"), vendor=vendor, hostname=hostname)) == []


def test_unknown_device_needs_an_open_port(tmp_path):
    assert rows(tmp_path, host("10.0.0.1", vendor="", hostname="")) == []


def test_unknown_device_is_reported_with_its_port_findings(tmp_path):
    found = rows(tmp_path, host("10.0.0.1", port(23, "telnet"), vendor="", hostname=""))
    assert found == [("10.0.0.1", None, "UNKNOWN_DEVICE"), ("10.0.0.1", 23, "TELNET_OPEN")]


def test_same_port_on_tcp_and_udp_gives_one_row_the_tcp_one(tmp_path):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), port(23, "telnet", proto="udp"))))
    assert [(f.port, f.proto, f.code) for f in result.findings] == [(23, "tcp", "TELNET_OPEN")]


def test_host_listed_twice_gives_each_finding_once(tmp_path):
    twice = host("10.0.0.1", port(23, "telnet"))
    assert rows(tmp_path, twice, twice) == [("10.0.0.1", 23, "TELNET_OPEN")]


def test_findings_are_sorted_by_ip_as_a_number(tmp_path):
    found = rows(tmp_path, host("10.0.0.10", port(23, "telnet")), host("10.0.0.9", port(23, "telnet")))
    assert [ip for ip, _, _ in found] == ["10.0.0.9", "10.0.0.10"]


def test_points_follow_the_severity(tmp_path):
    findings = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), port(9100, "jetdirect"),
                                                     port(21, "ftp"), port(22, "ssh")))).findings
    assert {(f.code, f.severity, f.points) for f in findings} == {
        ("TELNET_OPEN", "high", 20), ("PRINTER_RAW_EXPOSED", "low", 5), ("FTP_CLEARTEXT", "medium", 10),
        ("SSH_OPEN", "info", 0),
    }


def test_score_is_100_minus_the_points(tmp_path):
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), port(21, "ftp"))))
    assert result.score == 70


def test_score_never_goes_below_zero(tmp_path):
    hosts = [host(f"10.0.0.{n}", port(23, "telnet"), port(3389, "ms-wbt-server")) for n in range(1, 5)]
    assert analyse_file(write_scan(tmp_path, *hosts)).score == 0
