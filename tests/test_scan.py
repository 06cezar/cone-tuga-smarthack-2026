"""The live scan (FR-04) behind the guardrail (FR-02): what nmap is asked to do, and that nothing reaches nmap without
the guardrail's yes (live check 4).

No test runs nmap or touches the network (tests/CLAUDE.md). The network, the Wi-Fi name, nmap's port list and nmap
itself are fakes; a run of the real nmap fails the test, and the fake nmap writes an official Validation Set file
where the real one would write its XML."""
import shutil
from pathlib import Path

import pytest

import conetuga.__main__ as cli
import conetuga.guard.scan as scan
from conetuga.analysis import analyse_file
from conetuga.guard import Network, NetworkNotFound
from conetuga.guard.scan import (ScanError, ScanRefused, live_scan, nmap_command, parse_port_list,
                                 parse_scaninfo_ports)

ROOT = Path(__file__).resolve().parent.parent
V1 = ROOT / "tests" / "fixtures" / "validation" / "scans" / "V1_home_basic.xml"
HOTSPOT = Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1")  # A's scanner on our hotspot
VENUE = Network("wlp0s20f3", "10.240.7.21", "10.240.0.0/16", "10.240.0.1")  # on the venue's "UnivBuc Free"
TOP_PORTS = [21, 22, 23, 80, 443, 445, 8080]  # stands in for nmap's top 1,000
REAL_TOP_TCP_PORTS = scan.top_tcp_ports  # kept before the fakes below replace it
# What `nmap -sT --top-ports 1000 -n -oX -` printed with nmap 7.94 and no target ("0 IP addresses ... scanned"), with
# its list of 1,000 ports shortened.
SCANINFO_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94SVN scan initiated Sat Nov  7 16:42:19 2026 as: nmap -sT -&#45;top-ports 1000 -n -oX - -->
<nmaprun scanner="nmap" args="nmap -sT -&#45;top-ports 1000 -n -oX -" start="1794062539" version="7.94SVN">
<scaninfo type="connect" protocol="tcp" numservices="10" services="1,3-4,6-7,9,13,17,19-20"/>
<verbose level="0"/>
<debugging level="0"/>
<runstats><finished time="1794062539" summary="Nmap done; 0 IP addresses (0 hosts up) scanned in 0.03 seconds"
elapsed="0.03" exit="success"/><hosts up="0" down="0" total="0"/>
</runstats>
</nmaprun>
"""


@pytest.fixture(autouse=True)
def lab(monkeypatch, tmp_path):
    """By default: on our hotspot, nmap installed, running as administrator; running the real nmap fails the test.
    Each test runs in its own folder, so the default results/ is created there, never in the project."""
    def real_nmap_is_forbidden(command):
        raise AssertionError(f"a test tried to run nmap: {command}")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan, "detect_network", lambda: HOTSPOT)
    monkeypatch.setattr(scan, "wifi_ssid", lambda interface: "RSH-ConeTuga")
    monkeypatch.setattr(scan, "_find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: list(TOP_PORTS))
    monkeypatch.setattr(scan, "_is_admin", lambda: True)
    monkeypatch.setattr(scan, "_on_windows", lambda: False)
    monkeypatch.setattr(scan, "_run_nmap", real_nmap_is_forbidden)


def fake_nmap(monkeypatch, returncode: int = 0, writes: Path | None = V1) -> list[list[str]]:
    """A stand-in for nmap: records each command and copies `writes` to the file named after -oX."""
    commands = []

    def run(command):
        commands.append(command)
        if writes is not None:
            shutil.copyfile(writes, command[command.index("-oX") + 1])
        return returncode

    monkeypatch.setattr(scan, "_run_nmap", run)
    return commands


def on_network(monkeypatch, network: Network, ssid: str) -> None:
    monkeypatch.setattr(scan, "detect_network", lambda: network)
    monkeypatch.setattr(scan, "wifi_ssid", lambda interface: ssid)


# --- what nmap is asked to do ---------------------------------------------------------------------------------

def test_nmap_command_is_exactly_the_allowed_scan():
    command = nmap_command("/usr/bin/nmap", "172.20.10.0/28", "172.20.10.13", [21, 80, 1883], Path("/r/scan.xml"))
    assert command == ["/usr/bin/nmap", "-sS", "-sU", "-sV", "--script", "http-title", "--max-rate", "100",
                       "-p", "T:21,80,1883,U:53,123,161,1900,5353", "--exclude", "172.20.10.13",
                       "--stats-every", "30s", "-oX", str(Path("/r/scan.xml")), "172.20.10.0/28"]


def test_only_the_safe_http_title_script_is_named():
    """The brief bans brute, exploit, dos, intrusive and vuln scripts; -A and -sC would add default scripts."""
    command = nmap_command("nmap", "172.20.10.0/28", "172.20.10.13", TOP_PORTS, Path("scan.xml"))
    assert command.count("--script") == 1 and command[command.index("--script") + 1] == "http-title"
    assert not {"-A", "-sC", "--script-args", "--min-rate"} & set(command)


def test_rate_is_at_most_100_packets_per_second():
    command = nmap_command("nmap", "172.20.10.0/28", "172.20.10.13", TOP_PORTS, Path("scan.xml"))
    assert int(command[command.index("--max-rate") + 1]) <= 100


def test_tcp_ports_are_nmaps_top_1000_plus_the_catalog_ports_outside_them():
    """MQTT 1883, Redis 6379 and the lab's Redis on 6380 are not in nmap's top 1,000: without them, MQTT_EXPOSED and
    DB_EXPOSED could never fire on our lab."""
    ports = scan.scan_ports("/usr/bin/nmap")
    assert ports == sorted(set(TOP_PORTS) | {1883, 6379, 6380, 27017})


def test_udp_ports_are_the_five_the_brief_names():
    command = nmap_command("nmap", "172.20.10.0/28", "172.20.10.13", [80], Path("scan.xml"))
    assert command[command.index("-p") + 1].endswith(",U:53,123,161,1900,5353")


def test_top_ports_are_asked_from_nmap_with_no_target(monkeypatch):
    """nmap prints its port list and scans nothing: the command has no target."""
    seen = []

    def run(command, **kwargs):
        seen.append(command)
        return scan.subprocess.CompletedProcess(command, 0, stdout=SCANINFO_XML, stderr=b"")

    monkeypatch.setattr(scan.subprocess, "run", run)
    assert REAL_TOP_TCP_PORTS("/usr/bin/nmap") == [1, 3, 4, 6, 7, 9, 13, 17, 19, 20]
    assert seen == [["/usr/bin/nmap", "-sT", "--top-ports", "1000", "-n", "-oX", "-"]]


def test_port_list_ranges_are_expanded():
    assert parse_port_list("1,3-4,6") == [1, 3, 4, 6]


def test_port_list_with_an_xml_entity_is_refused():
    """Read with the same safe parser as scan files (NFR-03)."""
    hostile = b'<!DOCTYPE x [<!ENTITY e "1,2">]><nmaprun><scaninfo services="&e;"/></nmaprun>'
    with pytest.raises(ScanError):
        parse_scaninfo_ports(hostile)


def test_missing_port_list_is_an_error():
    with pytest.raises(ScanError, match="no port list"):
        parse_scaninfo_ports(b"<nmaprun></nmaprun>")


# --- nothing reaches nmap without the guardrail's yes ---------------------------------------------------------

@pytest.mark.parametrize("target, confirmed, network, ssid, why", [
    (None, False, HOTSPOT, "RSH-ConeTuga", "--confirm"),
    ("8.8.8.8", True, HOTSPOT, "RSH-ConeTuga", "public"),
    ("10.240.0.0/16", True, HOTSPOT, "RSH-ConeTuga", "outside the allowed network"),
    (None, True, VENUE, "UnivBuc Free", "not on our hotspot"),
    ("10.240.0.0/16", True, VENUE, "UnivBuc Free", "not on our hotspot"),
    (None, True, HOTSPOT, "", "not on our hotspot"),
    ("100.64.0.1", True, HOTSPOT, "RSH-ConeTuga", "carrier"),
    ("router.local", True, HOTSPOT, "RSH-ConeTuga", "domain names"),
    ("172.20.10.3 -oN /tmp/x", True, HOTSPOT, "RSH-ConeTuga", "not an IP address"),
    ("172.20.0.0/16", True, HOTSPOT, "RSH-ConeTuga", "outside the allowed network"),
])
def test_nothing_reaches_nmap_without_the_guardrails_yes(monkeypatch, tmp_path, target, confirmed, network, ssid,
                                                         why):
    on_network(monkeypatch, network, ssid)
    asked = []
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: asked.append(nmap) or TOP_PORTS)
    with pytest.raises(ScanRefused, match=why):
        live_scan(target, confirmed, tmp_path)
    assert asked == [] and list(tmp_path.iterdir()) == []


def test_nmap_gets_the_guardrails_parsed_range_never_the_raw_text(monkeypatch, tmp_path):
    """D's review of #10: the guardrail accepts " 172.20.10.0/28\\n"; nmap must get "172.20.10.0/28"."""
    commands = fake_nmap(monkeypatch)
    result = live_scan(" 172.20.10.0/28\n", True, tmp_path)
    assert commands[0][-1] == result.scanned == "172.20.10.0/28"


def test_default_target_is_the_connected_subnet_without_the_scanner(monkeypatch, tmp_path):
    commands = fake_nmap(monkeypatch)
    result = live_scan(None, True, tmp_path)
    assert result.scanned == "172.20.10.0/28" and result.network == HOTSPOT and result.ssid == "RSH-ConeTuga"
    assert commands[0][commands[0].index("--exclude") + 1] == "172.20.10.13"


def test_one_device_can_be_scanned(monkeypatch, tmp_path):
    commands = fake_nmap(monkeypatch)
    assert live_scan("172.20.10.2", True, tmp_path).scanned == "172.20.10.2/32" == commands[0][-1]


def test_the_xml_lands_in_the_output_folder_with_a_time_stamped_name(monkeypatch, tmp_path):
    fake_nmap(monkeypatch)
    out = tmp_path / "results" / "new"
    result = live_scan(None, True, out)
    assert result.xml.parent == out.resolve() and result.xml.name.startswith("scan_") and result.xml.is_file()


def test_raw_scans_go_to_the_gitignored_results_folder():
    """nmap's raw XML holds real MACs and names (NFR-02): it never goes to lab/scans/ or anywhere committed."""
    assert scan.DEFAULT_OUT == Path("results")
    assert "results/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_without_root_on_linux_only_nmap_runs_through_sudo(monkeypatch, tmp_path):
    commands = fake_nmap(monkeypatch)
    monkeypatch.setattr(scan, "_is_admin", lambda: False)
    monkeypatch.setattr(scan.shutil, "which", lambda name: f"/usr/bin/{name}")
    live_scan(None, True, tmp_path)
    assert commands[0][:3] == ["/usr/bin/sudo", "--", "/usr/bin/nmap"]


def test_without_administrator_rights_on_windows_nmap_never_starts(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_on_windows", lambda: True)
    monkeypatch.setattr(scan, "_is_admin", lambda: False)
    with pytest.raises(ScanError, match="administrator"):
        live_scan(None, True, tmp_path)


def test_missing_nmap_is_a_clear_error(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_find_nmap", lambda: None)
    with pytest.raises(ScanError, match="nmap isn't installed"):
        live_scan(None, True, tmp_path)


def test_nmap_failure_is_a_clear_error(monkeypatch, tmp_path):
    fake_nmap(monkeypatch, returncode=1)
    with pytest.raises(ScanError, match="didn't finish"):
        live_scan(None, True, tmp_path)


def test_nmap_that_writes_no_file_is_an_error(monkeypatch, tmp_path):
    fake_nmap(monkeypatch, writes=None)
    with pytest.raises(ScanError, match="didn't finish"):
        live_scan(None, True, tmp_path)


# --- the command line: python -m conetuga scan [target] --confirm ------------------------------------------------

def test_cli_scan_without_confirm_is_refused_before_nmap(capsys):
    assert cli.main(["scan"]) == cli.EXIT_REFUSED
    assert "--confirm" in capsys.readouterr().err


def test_cli_refuses_a_public_ip_and_the_venue_network(capsys):
    """Live check 4, as the jury will type it."""
    assert cli.main(["scan", "8.8.8.8", "--confirm"]) == cli.EXIT_REFUSED
    assert "public internet address" in capsys.readouterr().err
    assert cli.main(["scan", "10.240.0.0/16", "--confirm"]) == cli.EXIT_REFUSED
    assert "outside the allowed network" in capsys.readouterr().err


def test_cli_on_the_venue_wifi_refuses_even_the_connected_subnet(monkeypatch, capsys):
    on_network(monkeypatch, VENUE, "UnivBuc Free")
    assert cli.main(["scan", "--confirm"]) == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "'UnivBuc Free'" in err and "RSH-ConeTuga" in err


def test_cli_scan_shows_the_analysis_of_what_nmap_wrote(monkeypatch, tmp_path, capsys):
    fake_nmap(monkeypatch)
    assert cli.main(["scan", "--confirm", "--out", str(tmp_path)]) == cli.EXIT_OK
    output = capsys.readouterr().out
    expected = analyse_file(V1)
    assert f"scor {expected.score}" in output and f"score {expected.score}" in output
    assert "  192.168.1.1:80 HTTP_ADMIN_CLEARTEXT (medium)" in output
    assert "172.20.10.0/28" in output and "rămâne pe acest calculator" in output


def test_cli_scan_with_no_network_says_so(monkeypatch, capsys):
    def no_network():
        raise NetworkNotFound("Laptopul nu este conectat la nicio rețea.\nThe laptop is not connected to any network.")

    monkeypatch.setattr(scan, "detect_network", no_network)
    assert cli.main(["scan", "--confirm"]) == cli.EXIT_ERROR
    assert "not connected to any network" in capsys.readouterr().err


def test_cli_scan_stopped_with_ctrl_c_says_so(monkeypatch, capsys):
    def interrupted(command):
        raise KeyboardInterrupt

    monkeypatch.setattr(scan, "_run_nmap", interrupted)
    assert cli.main(["scan", "--confirm"]) == cli.EXIT_ERROR
    assert "The scan was stopped." in capsys.readouterr().err


def test_cli_shows_a_hostile_wifi_name_escaped(monkeypatch, capsys):
    """Anyone can name a Wi-Fi network; its name reaches the terminal only escaped (NFR-03)."""
    on_network(monkeypatch, HOTSPOT, "Free\x1b[2J")
    assert cli.main(["scan", "--confirm"]) == cli.EXIT_REFUSED
    assert "\x1b" not in capsys.readouterr().err
