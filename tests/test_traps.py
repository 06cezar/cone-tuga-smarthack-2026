"""Shapes of nmap XML the Validation Set doesn't show but a Test Set "with new traps" (brief) may: each test states
what the brief's rules say should happen, independently of how the code does it."""
from conetuga.analysis import analyse_file
from nmap_xml import NMAP_FOOTER, NMAP_HEADER, host, port, write_scan


def write_raw(tmp_path, hosts_xml: str, name: str = "raw.xml"):
    """A scan whose <host> elements are written by hand, for shapes the builder doesn't make."""
    path = tmp_path / name
    path.write_text(NMAP_HEADER + hosts_xml + NMAP_FOOTER, encoding="utf-8")
    return path


def rows(path) -> list[tuple]:
    return [(f.ip, f.port, f.code) for f in analyse_file(path).findings]


def test_ipv6_host_is_analysed_like_any_other(tmp_path):
    path = write_raw(tmp_path, '<host><status state="up"/><address addr="fd00::5" addrtype="ipv6"/>'
                               '<hostnames><hostname name="box"/></hostnames><ports><port protocol="tcp" portid="23">'
                               '<state state="open"/><service name="telnet"/></port></ports></host>')
    assert rows(path) == [("fd00::5", 23, "TELNET_OPEN")]


def test_ipv4_and_ipv6_hosts_in_one_file_sort_without_error(tmp_path):
    ipv6 = ('<host><status state="up"/><address addr="fd00::5" addrtype="ipv6"/><hostnames><hostname name="b"/>'
            '</hostnames><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
            '</ports></host>')
    path = write_raw(tmp_path, ipv6 + host("10.0.0.1", port(23, "telnet")))
    assert rows(path) == [("10.0.0.1", 23, "TELNET_OPEN"), ("fd00::5", 23, "TELNET_OPEN")]


def test_open_port_without_a_service_gives_no_service_finding(tmp_path):
    assert rows(write_scan(tmp_path, host("10.0.0.1", port(7000)))) == []


def test_open_port_without_a_service_still_counts_for_unknown_device(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(7000), vendor="", hostname=""))
    assert rows(path) == [("10.0.0.1", None, "UNKNOWN_DEVICE")]


def test_hostname_of_only_spaces_is_no_hostname(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(7000, "afs3-callback"), vendor="", hostname="   "))
    assert rows(path) == [("10.0.0.1", None, "UNKNOWN_DEVICE")]


def test_vendor_of_only_spaces_is_no_vendor(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(7000, "afs3-callback"), vendor="  ", hostname=""))
    assert rows(path) == [("10.0.0.1", None, "UNKNOWN_DEVICE")]


def test_second_hostname_counts_when_the_first_is_empty(tmp_path):
    path = write_raw(tmp_path, '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                               '<hostnames><hostname name=""/><hostname name="kitchen"/></hostnames><ports>'
                               '<port protocol="tcp" portid="7000"><state state="open"/></port></ports></host>')
    assert rows(path) == []


def test_port_listed_twice_on_a_host_gives_one_row(tmp_path):
    assert rows(write_scan(tmp_path, host("10.0.0.1", port(23, "telnet"), port(23, "telnet")))) == [
        ("10.0.0.1", 23, "TELNET_OPEN")
    ]


def test_host_with_no_ports_element_is_read(tmp_path):
    path = write_raw(tmp_path, '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>')
    result = analyse_file(path)
    assert (result.error, result.score, [h.ip for h in result.hosts]) == ("", 100, ["10.0.0.1"])


def test_host_without_a_status_is_not_reported(tmp_path):
    """nmap always writes <status>; without it the file can't say the host was up, so it reports nothing on it."""
    path = write_raw(tmp_path, '<host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" '
                               'portid="23"><state state="open"/><service name="telnet"/></port></ports></host>')
    assert rows(path) == []


def test_title_with_surrounding_spaces_and_newlines_matches_and_is_trimmed(tmp_path):
    """The UI and the explanations show the title, so it arrives without the page's stray whitespace."""
    result = analyse_file(write_scan(tmp_path, host("10.0.0.1", port(80, "http", title="\n   Router Setup  \n"))))
    assert [(f.port, f.code) for f in result.findings] == [(80, "HTTP_ADMIN_CLEARTEXT")]
    assert result.hosts[0].ports[0].title == "Router Setup"


def test_keyword_inside_a_longer_word_matches(tmp_path):
    path = write_scan(tmp_path, host("10.0.0.1", port(80, "http", title="Configuration")))
    assert rows(path) == [("10.0.0.1", 80, "HTTP_ADMIN_CLEARTEXT")]


def test_title_in_another_script_does_not_count(tmp_path):
    """Only the http-title script gives the page title; another script's output with "admin" in it is not a title."""
    path = write_raw(tmp_path, '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                               '<hostnames><hostname name="b"/></hostnames><ports><port protocol="tcp" portid="80">'
                               '<state state="open"/><service name="http"/><script id="http-server-header" '
                               'output="admin"><elem key="title">admin</elem></script></port></ports></host>')
    assert rows(path) == []


def test_xml_in_another_encoding_is_read(tmp_path):
    path = tmp_path / "latin1.xml"
    body = NMAP_HEADER.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"') + host(
        "10.0.0.1", port(80, "http", title="Configuración"), hostname="cámara") + NMAP_FOOTER
    path.write_bytes(body.encode("iso-8859-1"))
    assert rows(path) == [("10.0.0.1", 80, "HTTP_ADMIN_CLEARTEXT")]


def test_bytes_that_are_not_valid_utf8_make_the_file_unreadable(tmp_path):
    path = tmp_path / "bad_bytes.xml"
    path.write_bytes(NMAP_HEADER.encode() + b"<host>\xff\xfe</host>" + NMAP_FOOTER.encode())
    result = analyse_file(path)
    assert (result.findings, result.score) == ([], None) and result.error


def test_hostile_markup_in_a_title_stays_plain_text(tmp_path):
    """Untrusted text (NFR-03): an escaped script tag in a title arrives as text, never as markup."""
    path = write_scan(tmp_path, host("10.0.0.1", port(80, "http", title="<script>alert(1)</script> Login")))
    result = analyse_file(path)
    assert result.hosts[0].ports[0].title == "<script>alert(1)</script> Login"
    assert [f.code for f in result.findings] == ["HTTP_ADMIN_CLEARTEXT"]


HOSTHINT = ('<hosthint><status state="up" reason="arp-response"/><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="Acme"/><hostnames></hostnames></hosthint>\n')


def test_hosthint_before_a_host_does_not_count_the_device_twice(tmp_path):
    """nmap 7.80+ writes a <hosthint> (ARP discovery) before each <host>, as in our own lab capture: only <host> counts."""
    result = analyse_file(write_raw(tmp_path, HOSTHINT + host("10.0.0.1", port(23, "telnet"))))
    assert [h.ip for h in result.hosts] == ["10.0.0.1"]
    assert [(f.ip, f.port, f.code) for f in result.findings] == [("10.0.0.1", 23, "TELNET_OPEN")]


def test_hosthint_alone_is_not_a_host(tmp_path):
    """A hint with no <host> after it (e.g. a host that went away before its port scan) reports nothing."""
    result = analyse_file(write_raw(tmp_path, HOSTHINT))
    assert (result.error, result.hosts, result.findings, result.score) == ("", [], [], 100)


def timed_out_host(attribute: str, ports_xml: str = "") -> str:
    return (f'<host {attribute}><status state="up" reason="arp-response"/><address addr="10.0.0.7" addrtype="ipv4"/>'
            f'<address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="Acme"/><hostnames><hostname name="box"/>'
            f'</hostnames><ports>{ports_xml}</ports></host>\n')


def test_a_device_nmap_gave_up_on_is_marked_not_checked(tmp_path):
    """--host-timeout: nmap writes the device with no ports. It has no findings because it wasn't checked, and the
    result says so, so nobody reads "no findings" as "safe"."""
    result = analyse_file(write_raw(tmp_path, timed_out_host('timedout="true"')))
    assert [(h.ip, h.timed_out, h.ports) for h in result.hosts] == [("10.0.0.7", True, [])]
    assert (result.findings, result.score) == ([], 100)


def test_a_device_nmap_finished_is_not_marked(tmp_path):
    result = analyse_file(write_raw(tmp_path, timed_out_host('timedout="false"') + host("10.0.0.8", port(23, "telnet"))))
    assert [h.timed_out for h in result.hosts] == [False, False]


def test_ports_nmap_wrote_before_giving_up_still_count(tmp_path):
    """If nmap wrote some ports of a device before its time ran out, the catalog still applies to them."""
    telnet = '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
    result = analyse_file(write_raw(tmp_path, timed_out_host('timedout="true"', telnet)))
    assert result.hosts[0].timed_out and [(f.port, f.code) for f in result.findings] == [(23, "TELNET_OPEN")]


def port_with_protocol(protocol: str) -> str:
    return (f'<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><hostnames><hostname name="box"/>'
            f'</hostnames><ports><port protocol="{protocol}" portid="23"><state state="open"/><service name="telnet"/>'
            f'</port></ports></host>')


def test_a_protocol_nmap_never_writes_makes_the_file_unreadable(tmp_path):
    """nmap.dtd allows only ip, tcp, udp and sctp. A hostile "[click](https://evil.example)" reached the device card
    as a clickable link (A's review of #59): now the file is an ERROR row with no findings, and the reason doesn't
    quote the hostile text back."""
    result = analyse_file(write_raw(tmp_path, port_with_protocol("[click](https://evil.example)")))
    assert (result.hosts, result.findings, result.score) == ([], [], None)
    assert "protocol" in result.error and "evil.example" not in result.error


def test_every_protocol_nmap_writes_is_read(tmp_path):
    for protocol in ("ip", "tcp", "udp", "sctp"):
        result = analyse_file(write_raw(tmp_path, port_with_protocol(protocol), name=f"{protocol}.xml"))
        assert result.error == "" and [p.proto for p in result.hosts[0].ports] == [protocol]


def test_a_protocol_in_capitals_is_read_as_nmap_writes_it(tmp_path):
    result = analyse_file(write_raw(tmp_path, port_with_protocol("TCP")))
    assert result.error == "" and [(f.proto, f.code) for f in result.findings] == [("tcp", "TELNET_OPEN")]


def test_a_closed_port_with_an_odd_protocol_is_simply_skipped(tmp_path):
    """Only open ports are read, so a closed one never makes a file unreadable."""
    closed = port_with_protocol("bogus").replace('state="open"', 'state="closed"')
    result = analyse_file(write_raw(tmp_path, closed))
    assert result.error == "" and result.hosts[0].ports == []
