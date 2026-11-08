"""The live scan (FR-04) behind the guardrail (FR-02): what nmap is asked to do, and that nothing reaches nmap without
the guardrail's yes (live check 4).

No test runs nmap or touches the network (tests/CLAUDE.md). The network, the Wi-Fi name, nmap's port list and nmap
itself are fakes; a run of the real nmap fails the test, and the fake nmap writes an official Validation Set file
where the real one would write its XML."""
import os
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
                       "--host-timeout", "5m", "--stats-every", "30s", "-oX", str(Path("/r/scan.xml")),
                       "172.20.10.0/28"]


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


# --- the time limit: --minutes, at least 5, and the devices nmap gave up on ------------------------------------

def timed_out_copy_of_v1(folder: Path) -> Path:
    """V1 with its first device marked the way nmap marks one it gave up on (--host-timeout): <host timedout="true">."""
    text = V1.read_text(encoding="utf-8").replace("<host ", '<host timedout="true" ', 1)
    path = folder / "V1_timed_out.xml"
    path.write_text(text, encoding="utf-8")
    return path


def test_minutes_become_nmaps_time_limit_per_device(monkeypatch, tmp_path):
    commands = fake_nmap(monkeypatch)
    assert live_scan(None, True, tmp_path, minutes=12).minutes == 12
    assert commands[0][commands[0].index("--host-timeout") + 1] == "12m"


def test_the_default_limit_is_5_minutes(monkeypatch, tmp_path):
    commands = fake_nmap(monkeypatch)
    live_scan(None, True, tmp_path)
    assert commands[0][commands[0].index("--host-timeout") + 1] == "5m"


def test_fewer_than_5_minutes_stops_before_anything(monkeypatch, tmp_path):
    """NFR-07 is "a /24 under 5 minutes", and our 2-device lab already took 3.4: less would drop ordinary devices."""
    def no_network_needed():
        raise AssertionError("the limit is checked before the network")

    monkeypatch.setattr(scan, "detect_network", no_network_needed)
    with pytest.raises(ScanError, match="at least 5 minutes"):
        live_scan(None, True, tmp_path, minutes=4)
    assert list(tmp_path.iterdir()) == []


def test_cli_refuses_fewer_than_5_minutes_or_a_non_number(capsys):
    for value in ("4", "0", "-10", "abc", "5.5"):
        with pytest.raises(SystemExit) as stopped:
            cli.main(["scan", "--confirm", "--minutes", value])
        assert stopped.value.code == 2 and "at least 5" in capsys.readouterr().err, value


def test_devices_nmap_gave_up_on_are_read_from_its_xml(tmp_path):
    assert scan.timed_out_devices(timed_out_copy_of_v1(tmp_path)) == ("192.168.1.1",)
    assert scan.timed_out_devices(V1) == ()
    assert scan.timed_out_devices(ROOT / "tests" / "fixtures" / "validation" / "scans" / "V7_broken.xml") == ()


def test_cli_names_each_device_that_ran_out_of_time_and_exits_partial(monkeypatch, tmp_path, capsys):
    """Its ports and findings are missing, so "no findings" must never read as "safe" for it."""
    fake_nmap(monkeypatch, writes=timed_out_copy_of_v1(tmp_path))
    assert cli.main(["scan", "--confirm", "--minutes", "7", "--out", str(tmp_path / "out")]) == cli.EXIT_PARTIAL
    romanian, english = capsys.readouterr().err.strip().split("\n")
    assert "192.168.1.1" in english and "7 minutes" in english and "--minutes 14" in english
    assert "192.168.1.1" in romanian and "--minutes 14" in romanian


def test_cli_scan_without_timeouts_exits_ok(monkeypatch, tmp_path):
    fake_nmap(monkeypatch)
    assert cli.main(["scan", "--confirm", "--minutes", "8", "--out", str(tmp_path)]) == cli.EXIT_OK


def test_a_history_that_cant_be_written_still_shows_the_result_and_the_timeouts(monkeypatch, tmp_path, capsys):
    """A full disk or a read-only history must not hide the warning that some devices weren't checked."""
    def full_disk(result, content):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "save_scan", full_disk)
    fake_nmap(monkeypatch, writes=timed_out_copy_of_v1(tmp_path))
    assert cli.main(["scan", "--confirm", "--out", str(tmp_path / "out")]) == cli.EXIT_PARTIAL
    captured = capsys.readouterr()
    assert "score " in captured.out
    assert "couldn't be saved to the history (No space left on device)" in captured.err
    assert "192.168.1.1 didn't finish within 5 minutes" in captured.err


# --- the app's "Scanează acum" button: scan_from_app (specs/contracts.md) ----------------------------------------

# nmap's full path as scan_from_app makes it (pkexec needs one): "/usr/bin/nmap" on Linux, "C:\\usr\\bin\\nmap" on the
# Windows CI runner.
APP_NMAP = os.path.abspath("/usr/bin/nmap")


@pytest.fixture
def app_lab(monkeypatch):
    """The app as it really runs: an ordinary user, never an administrator, with pkexec installed. Every way the
    app could start nmap is a fake that fails the test unless the test replaces it."""
    def forbidden(*args, **kwargs):
        raise AssertionError("a test tried to start nmap")

    monkeypatch.setattr(scan, "_find_nmap", lambda: APP_NMAP)
    monkeypatch.setattr(scan, "_is_admin", lambda: False)
    monkeypatch.setattr(scan.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(scan, "_run_nmap_for_xml", forbidden)
    monkeypatch.setattr(scan, "_run_as_admin", forbidden)


def fake_pkexec(monkeypatch, returncode: int = 0, xml: bytes = V1.read_bytes(), errors: str = "") -> list:
    """nmap through pkexec: records the command and answers with an exit code, the XML on its output and its errors."""
    commands = []
    monkeypatch.setattr(scan, "_run_nmap_for_xml", lambda command: commands.append(command) or (returncode, xml, errors))
    return commands


def test_contract_scan_from_app(app_lab, monkeypatch, tmp_path):
    commands = fake_pkexec(monkeypatch)
    result = scan.scan_from_app(confirmed=True, out=tmp_path / "results")
    ports = "T:21,22,23,80,443,445,1883,6379,6380,8080,27017,U:53,123,161,1900,5353"
    assert commands == [["/usr/bin/pkexec", APP_NMAP, "-sS", "-sU", "-sV", "--script", "http-title",
                         "--max-rate", "100", "-p", ports, "--exclude", "172.20.10.13", "--host-timeout", "5m",
                         "--stats-every", "30s", "-oX", "-", "172.20.10.0/28"]]
    assert (result.network, result.ssid, result.scanned, result.minutes, result.timed_out) == (
        HOTSPOT, "RSH-ConeTuga", "172.20.10.0/28", 5, ())
    assert result.xml.parent == (tmp_path / "results").resolve() and result.xml.name.startswith("scan_")
    assert result.xml.read_bytes() == V1.read_bytes()
    assert analyse_file(result.xml).score == 90


def test_the_app_runs_exactly_the_cli_command_with_the_xml_on_nmaps_output(app_lab, monkeypatch, tmp_path):
    commands = fake_pkexec(monkeypatch)
    scan.scan_from_app(True, minutes=8, out=tmp_path)
    expected = nmap_command(APP_NMAP, "172.20.10.0/28", "172.20.10.13", scan.scan_ports(APP_NMAP),
                            "-", 8)
    assert commands[0][1:] == expected


@pytest.mark.parametrize("confirmed, network, ssid, why", [
    (False, HOTSPOT, "RSH-ConeTuga", "--confirm"),
    (True, VENUE, "UnivBuc Free", "not on our hotspot"),
    (True, HOTSPOT, "", "not on our hotspot"),
])
def test_nothing_reaches_nmap_from_the_app_without_the_tick_and_the_guardrails_yes(app_lab, monkeypatch, tmp_path,
                                                                                  confirmed, network, ssid, why):
    on_network(monkeypatch, network, ssid)
    asked = []
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: asked.append(nmap) or TOP_PORTS)
    with pytest.raises(ScanRefused, match=why):
        scan.scan_from_app(confirmed, out=tmp_path / "results")
    assert asked == [] and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("returncode", [scan.PKEXEC_DISMISSED, scan.PKEXEC_NO_AGENT])
def test_a_closed_or_missing_password_window_changes_nothing(app_lab, monkeypatch, tmp_path, returncode):
    fake_pkexec(monkeypatch, returncode=returncode, xml=b"")
    with pytest.raises(scan.PasswordWindowRefused, match="password window"):
        scan.scan_from_app(True, out=tmp_path / "results")
    assert list(tmp_path.iterdir()) == []


def test_without_pkexec_the_app_says_so_and_nmap_never_starts(app_lab, monkeypatch, tmp_path):
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    with pytest.raises(scan.PasswordWindowRefused, match="pkexec"):
        scan.scan_from_app(True, out=tmp_path / "results")
    assert list(tmp_path.iterdir()) == []


def test_an_nmap_failure_from_the_app_is_a_scan_error_with_nmaps_message(app_lab, monkeypatch, tmp_path):
    fake_pkexec(monkeypatch, returncode=1, xml=b"", errors="Failed to open device wlp0s20f3\n")
    with pytest.raises(ScanError, match="didn't finish the scan \\(Failed to open device wlp0s20f3\\)") as raised:
        scan.scan_from_app(True, out=tmp_path / "results")
    assert not isinstance(raised.value, scan.PasswordWindowRefused)
    assert list(tmp_path.iterdir()) == []


def test_an_app_already_running_as_administrator_runs_nmap_directly(app_lab, monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_is_admin", lambda: True)
    commands = fake_pkexec(monkeypatch)
    scan.scan_from_app(True, out=tmp_path)
    assert commands[0][0] == APP_NMAP and "/usr/bin/pkexec" not in commands[0]


def test_the_app_needs_at_least_5_minutes_too(app_lab, tmp_path):
    with pytest.raises(ScanError, match="at least 5 minutes"):
        scan.scan_from_app(True, minutes=4, out=tmp_path / "results")


def test_on_windows_the_uac_window_starts_nmap_alone_and_its_temporary_folder_is_deleted(app_lab, monkeypatch,
                                                                                         tmp_path):
    monkeypatch.setattr(scan, "_on_windows", lambda: True)
    started = []

    def uac(command):
        started.append(command)
        shutil.copyfile(V1, command[command.index("-oX") + 1])
        return 0

    monkeypatch.setattr(scan, "_run_as_admin", uac)
    result = scan.scan_from_app(True, out=tmp_path / "results")
    written = Path(started[0][started[0].index("-oX") + 1])
    assert started[0][0] == APP_NMAP and started[0][-1] == "172.20.10.0/28"
    assert not written.parent.exists()  # nmap's temporary folder is gone
    assert result.xml.read_bytes() == V1.read_bytes()


def test_on_windows_a_cancelled_uac_window_changes_nothing(app_lab, monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_on_windows", lambda: True)
    folders = []

    def cancelled(command):
        folders.append(Path(command[command.index("-oX") + 1]).parent)
        raise scan._window_refused()

    monkeypatch.setattr(scan, "_run_as_admin", cancelled)
    with pytest.raises(scan.PasswordWindowRefused):
        scan.scan_from_app(True, out=tmp_path / "results")
    assert not folders[0].exists() and list(tmp_path.iterdir()) == []


class FakeWindows:
    """shell32 and kernel32 as the UAC call sees them: ShellExecuteExW answers `accepted`, and nmap exits with 0.
    Each function is a plain function, since the real code sets `argtypes` on it as on a ctypes function."""

    def __init__(self, accepted: bool):
        self.accepted, self.info, self.closed = accepted, None, []
        for name in ("ShellExecuteExW", "WaitForSingleObject", "GetExitCodeProcess", "CloseHandle"):
            setattr(self, name, self._plain(getattr(self, f"_{name}")))

    @staticmethod
    def _plain(method):
        return lambda *args: method(*args)

    def __call__(self, name, use_last_error=False):
        return self

    def _ShellExecuteExW(self, info_pointer):
        self.info = info_pointer._obj
        if self.accepted:
            self.info.hProcess = 42
        return int(self.accepted)

    def _WaitForSingleObject(self, handle, milliseconds):
        return 0

    def _GetExitCodeProcess(self, handle, code_pointer):
        code_pointer._obj.value = 0
        return 1

    def _CloseHandle(self, handle):
        self.closed.append(handle)
        return 1


def test_the_uac_call_asks_runas_for_nmap_with_its_arguments_and_waits_for_it(monkeypatch):
    windows = FakeWindows(accepted=True)
    monkeypatch.setattr(scan.ctypes, "WinDLL", windows, raising=False)
    command = ["C:\\Program Files (x86)\\Nmap\\nmap.exe", "-sS", "-oX", "C:\\Users\\Ana Maria\\scan.xml", "10.0.0.0/28"]
    assert scan._run_as_admin(command) == 0
    info = windows.info
    assert (info.lpVerb, info.lpFile) == ("runas", command[0])
    assert info.lpParameters == '-sS -oX "C:\\Users\\Ana Maria\\scan.xml" 10.0.0.0/28'
    assert info.fMask & scan.SEE_MASK_NOCLOSEPROCESS and info.cbSize == scan.ctypes.sizeof(info)
    assert windows.closed == [42]


def test_a_refused_uac_window_raises_and_starts_nothing(monkeypatch):
    monkeypatch.setattr(scan.ctypes, "WinDLL", FakeWindows(accepted=False), raising=False)
    with pytest.raises(scan.PasswordWindowRefused):
        scan._run_as_admin(["nmap.exe", "-sS"])
