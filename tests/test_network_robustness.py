"""Mihnea's last request (A, 2026-11-08 00:12): network tests that are robust and comprehensive. The guardrail (FR-02,
live check 4) is checked on whole families of targets, not one example each; every OS branch of network detection
and of starting nmap runs on any computer. It adds to tests/test_guard.py and tests/test_scan.py without repeating
them. Nothing here touches the network or runs nmap (tests/CLAUDE.md): system commands, sockets and nmap are fakes,
and a real lookup or a real nmap fails the test."""
import errno
import socket
import subprocess
from types import SimpleNamespace

import pytest

import conetuga.guard.network as network
import conetuga.guard.scan as scan
from conetuga.guard import HOTSPOT_SSID, Network, NetworkNotFound, check_scope
from conetuga.guard.scan import ScanError, ScanRefused, live_scan

HOTSPOT_SUBNET = "172.20.10.0/28"  # the iPhone hotspot of the contract's example
HOTSPOT = Network("wlp0s20f3", "172.20.10.13", HOTSPOT_SUBNET, "172.20.10.1")  # A's scanner on our hotspot
VENUE_SSID = "UnivBuc Free"
INSIDE = "172.20.10.5"  # one of our lab devices
# An allowlist that would let everything through: the public-address rule must hold on its own, even if the
# allowlist were ever wrong (scope.py's _contains_public docstring).
EVERYTHING = ["0.0.0.0/0", "::/0"]

# Public addresses and ranges, many at the edge of a private or reserved block: one address past 10/8, 100.64/10,
# 172.16/12 or 192.168/16 is already the internet.
PUBLIC = [
    "8.8.8.8", "1.1.1.1", "8.8.8.8/32", "8.8.8.0/24",
    "9.255.255.255", "11.0.0.0",  # around 10.0.0.0/8
    "100.63.255.255", "100.128.0.0",  # around the carrier's 100.64.0.0/10
    "172.15.255.255", "172.32.0.0",  # around 172.16.0.0/12
    "192.167.255.255", "192.169.0.0",  # around 192.168.0.0/16
    "172.16.0.0/11",  # read as 172.0.0.0/11: holds 172.16/12 and public addresses
    "100.0.0.0/9",  # holds the carrier's range and public addresses
    "0.0.0.0/0", "::/0", "2000::/3", "2001:4860:4860::8888", "2606:4700:4700::1111",
]
# Not public, but not ours either: on our hotspot, only the allowlist (the hotspot's subnet) refuses them.
PRIVATE_NOT_OURS = [
    "10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255",
    "172.20.10.16",  # the next /28, right after ours
    "172.20.10.0/27", "172.20.0.0/16",  # ranges that hold ours and more
    "10.240.0.0/16",  # the venue's Wi-Fi (live check 4)
    "192.168.1.0/24",  # a typical home network
    "fd00::1", "fe80::1%eth0",  # IPv6 unique-local and link-local, never in an IPv4 allowlist
]
# Text that some tools read as an address, but that isn't an address or a range written plainly: refused as text,
# and never looked up as a name. "134744072" and "1.1" are 8.8.8.8 and 1.0.0.1 for inet_aton, the C call many
# programs use; "0x08080808" is 8.8.8.8 in hexadecimal.
NOT_PLAIN_ADDRESSES = [
    "134744072", "0x08080808", "1.1", "8.8.8", "8.8.8.8.nip.io", "172.20.10.3.", "172.20.10.0/33",
    "172.20.10.256", "+172.20.10.3", "172.20.10.3\n8.8.8.8", "１７２.20.10.3", "172.20.10.3%eth0",
]


@pytest.fixture
def no_dns(monkeypatch):
    """Any name lookup fails the test: the guardrail never resolves a name (conetuga/guard/CLAUDE.md)."""
    def forbidden(*args, **kwargs):
        raise AssertionError("the guardrail must never look up a name")

    for lookup in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, lookup, forbidden)


def english(reason: str) -> str:
    """The second line of a ScopeDecision's reason: the English sentence."""
    return reason.split("\n")[1]


# --- the guardrail on whole families of targets -------------------------------------------------------------------

@pytest.mark.parametrize("target", PUBLIC)
def test_a_public_target_is_refused_even_by_an_allowlist_that_allows_everything(target):
    decision = check_scope(target, EVERYTHING, True, HOTSPOT_SSID)
    assert not decision.allowed
    assert "public internet" in english(decision.reason)


@pytest.mark.parametrize("target", PRIVATE_NOT_OURS)
def test_a_private_target_that_isnt_ours_is_refused_by_the_allowlist(target):
    decision = check_scope(target, [HOTSPOT_SUBNET], True, HOTSPOT_SSID)
    assert not decision.allowed
    assert "outside the allowed network" in english(decision.reason)


@pytest.mark.parametrize("target", NOT_PLAIN_ADDRESSES)
def test_text_that_isnt_a_plain_address_is_refused_without_a_lookup(no_dns, target):
    decision = check_scope(target, EVERYTHING, True, HOTSPOT_SSID)
    assert not decision.allowed
    assert "not an IP address" in english(decision.reason)


@pytest.mark.parametrize("on_hotspot", [True, False])
@pytest.mark.parametrize("in_allowlist", [True, False])
@pytest.mark.parametrize("confirmed", [True, False])
def test_our_own_device_is_scanned_only_with_all_three_yeses(on_hotspot, in_allowlist, confirmed):
    """Our hotspot, the allowlist and --confirm: all 8 combinations. Only all three together allow a scan, and a
    refusal names the first gate that failed, in the order check_scope documents."""
    ssid = HOTSPOT_SSID if on_hotspot else VENUE_SSID
    allowlist = [HOTSPOT_SUBNET] if in_allowlist else ["192.168.1.0/24"]
    decision = check_scope(INSIDE, allowlist, confirmed, ssid)
    assert decision.allowed == (on_hotspot and in_allowlist and confirmed)
    if not on_hotspot:
        assert "not on our hotspot" in english(decision.reason)
    elif not in_allowlist:
        assert "outside the allowed network" in english(decision.reason)
    elif not confirmed:
        assert "--confirm" in english(decision.reason)


# --- nothing reaches nmap without the guardrail's yes ---------------------------------------------------------------

@pytest.fixture
def lab(monkeypatch, tmp_path):
    """On our hotspot, nmap installed, running as administrator; asking nmap anything is recorded, running it fails
    the test. Each test runs in its own folder, so a results/ folder could only appear there."""
    asked = []

    def real_nmap_is_forbidden(command):
        raise AssertionError(f"a test tried to run nmap: {command}")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan, "detect_network", lambda: HOTSPOT)
    monkeypatch.setattr(scan, "wifi_ssid", lambda interface: HOTSPOT_SSID)
    monkeypatch.setattr(scan, "_find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: asked.append(nmap) or [22, 80])
    monkeypatch.setattr(scan, "_is_admin", lambda: True)
    monkeypatch.setattr(scan, "_on_windows", lambda: False)
    monkeypatch.setattr(scan, "_run_nmap", real_nmap_is_forbidden)
    return asked


@pytest.mark.parametrize("target", PUBLIC + PRIVATE_NOT_OURS + NOT_PLAIN_ADDRESSES)
def test_a_refused_target_never_reaches_nmap(lab, no_dns, tmp_path, target):
    with pytest.raises(ScanRefused):
        live_scan(target, True, tmp_path)
    assert lab == [] and list(tmp_path.iterdir()) == []


def test_on_linux_without_root_or_sudo_nmap_never_starts(lab, monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_is_admin", lambda: False)
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    with pytest.raises(ScanError, match="sudo is missing"):
        live_scan(INSIDE, True, tmp_path)


# --- the OS branches that start nmap (the real functions, with the system calls faked) ------------------------------

REAL_TOP_TCP_PORTS = scan.top_tcp_ports
REAL_IS_ADMIN = scan._is_admin
REAL_RUN_NMAP = scan._run_nmap
REAL_FIND_NMAP = scan._find_nmap


@pytest.mark.parametrize("failure", [FileNotFoundError(errno.ENOENT, "No such file"),
                                     subprocess.CalledProcessError(1, ["nmap"]),
                                     subprocess.TimeoutExpired(["nmap"], 30)])
def test_nmap_that_cant_give_its_port_list_is_a_clear_error(monkeypatch, failure):
    def fails(*args, **kwargs):
        raise failure

    monkeypatch.setattr(scan.subprocess, "run", fails)
    with pytest.raises(ScanError) as raised:
        REAL_TOP_TCP_PORTS("/usr/bin/nmap")
    assert "nmap nu și-a dat lista de porturi" in str(raised.value) and "didn't give its port list" in str(raised.value)


@pytest.mark.parametrize("euid, admin", [(0, True), (1000, False)])
def test_on_linux_administrator_means_root(monkeypatch, euid, admin):
    monkeypatch.setattr(scan, "_on_windows", lambda: False)
    monkeypatch.setattr(scan.os, "geteuid", lambda: euid, raising=False)  # Windows has no geteuid
    assert REAL_IS_ADMIN() is admin


@pytest.mark.parametrize("answer, admin", [(1, True), (0, False)])
def test_on_windows_administrator_is_what_windows_says(monkeypatch, answer, admin):
    shell32 = SimpleNamespace(IsUserAnAdmin=lambda: answer)
    monkeypatch.setattr(scan, "_on_windows", lambda: True)
    monkeypatch.setattr(scan, "ctypes", SimpleNamespace(windll=SimpleNamespace(shell32=shell32)))
    assert REAL_IS_ADMIN() is admin


@pytest.mark.parametrize("platform, windows", [("win32", True), ("linux", False), ("darwin", False)])
def test_the_os_is_read_from_sys_platform(monkeypatch, platform, windows):
    monkeypatch.setattr(scan.sys, "platform", platform)
    assert scan._on_windows() is windows


def test_nmap_runs_in_this_terminal_with_the_command_unchanged_and_no_shell(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 3)

    monkeypatch.setattr(scan.subprocess, "run", run)
    command = ["sudo", "--", "/usr/bin/nmap", "-sS", "172.20.10.0/28"]
    assert REAL_RUN_NMAP(command) == 3
    assert calls == [(command, {})]  # a list, never a shell string


def test_nmap_is_found_on_the_path(monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    assert REAL_FIND_NMAP() == "/usr/bin/nmap"


# --- network detection: the branches tests/test_guard.py doesn't reach ---------------------------------------------

WINDOWS_ONE_WIFI = (
    "    Name                   : Wi-Fi\r\n"
    "    State                  : connected\r\n"
    "    SSID                   : RSH-ConeTuga\r\n"
)


def test_windows_gives_no_wifi_name_for_an_interface_it_doesnt_list():
    assert network.parse_windows_ssid(WINDOWS_ONE_WIFI, "Ethernet 2") == ""


class FakeSocket:
    """socket.socket for the route probe: `connect` sends nothing for UDP, so no real socket is needed."""

    def __init__(self, connect_error: OSError | None = None):
        self.connect_error = connect_error

    def __call__(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, address):
        if self.connect_error:
            raise self.connect_error

    def getsockname(self):
        return ("172.20.10.3", 50000)


def test_the_local_address_comes_from_the_route_probe(monkeypatch):
    monkeypatch.setattr(network.socket, "socket", FakeSocket())
    assert network._local_ip() == "172.20.10.3"


def test_no_route_at_all_is_a_clear_error_in_both_languages(monkeypatch):
    monkeypatch.setattr(network.socket, "socket", FakeSocket(OSError(errno.ENETUNREACH, "Network is unreachable")))
    with pytest.raises(NetworkNotFound) as raised:
        network._local_ip()
    message = str(raised.value)
    assert "nu este conectat la nicio rețea" in message and "Network is unreachable" in message
    assert len(message.split("\n")) == 2


@pytest.mark.parametrize("windows", [True, False])
def test_a_system_command_runs_as_a_list_and_its_bytes_are_read_safely(monkeypatch, windows):
    """Linux runs the command in the C locale (its words never translated); a byte that isn't text never crashes."""
    calls = []

    def run(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b"default via 172.20.10.1 \xff\n", stderr=b"")

    monkeypatch.setattr(network, "_on_windows", lambda: windows)
    monkeypatch.setattr(network.subprocess, "run", run)
    assert network._run(["ip", "route", "show", "default"]) == "default via 172.20.10.1 �\n"
    env = calls[0]["env"]
    assert (env is None) if windows else (env["LC_ALL"] == "C")
    assert calls[0]["check"] is True and calls[0]["timeout"] > 0


def test_a_system_command_that_hangs_is_a_clear_error(monkeypatch):
    def hangs(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(network.subprocess, "run", hangs)
    with pytest.raises(NetworkNotFound, match="failed"):
        network._run(["nmcli", "-t", "-f", "active,ssid,device", "dev", "wifi"])
