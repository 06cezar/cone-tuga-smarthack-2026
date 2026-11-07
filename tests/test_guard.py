"""The scope guardrail (FR-02, live check 4) and network detection (FR-01).

No test uses the network or runs nmap: the OS commands' outputs are saved below, as printed on real laptops (MACs
masked), and replayed through `network._run`, so both the Linux and the Windows branch run on any computer."""
import errno
import socket
from types import SimpleNamespace

import pytest

import conetuga.guard.network as network
from conetuga.guard import (HOTSPOT_SSID, Network, NetworkNotFound, ScopeDecision, check_scope, detect_network,
                            wifi_ssid)

# The contract's example network (an iPhone hotspot), and the venue's Wi-Fi as the jury will see it (live check 4).
HOTSPOT_SUBNET = "172.20.10.0/28"
VENUE_SSID = "UnivBuc Free"
VENUE_SUBNET = "10.240.0.0/16"


def scope(target: str, confirmed: bool = True, ssid: str = HOTSPOT_SSID,
          allowlist: tuple[str, ...] = (HOTSPOT_SUBNET,)) -> ScopeDecision:
    """check_scope with the contract's setting: on our hotspot, allowlist = the hotspot's subnet."""
    return check_scope(target, list(allowlist), confirmed, ssid)


# --- check_scope (FR-02) ---------------------------------------------------------------------------------------

def test_contract_check_scope():
    """Every example of the check_scope contract in specs/contracts.md."""
    for refused in ["8.8.8.8", "100.64.0.1", "192.168.1.0/24", "172.20.0.0/16", "router.local"]:
        assert scope(refused).allowed is False, refused
    assert scope(HOTSPOT_SUBNET, confirmed=False).allowed is False
    assert scope(HOTSPOT_SUBNET, confirmed=True).allowed is True
    for target in ["8.8.8.8", "192.168.1.0/24", HOTSPOT_SUBNET]:
        assert scope(target, ssid="Venue-WiFi").allowed is False, target


def test_public_ip_is_refused():
    decision = scope("8.8.8.8")
    assert not decision.allowed and "publică" in decision.reason and "public" in decision.reason


def test_one_address_is_shown_without_a_prefix():
    assert scope("8.8.8.8").reason.startswith("8.8.8.8 este")


def test_public_range_is_refused():
    assert not scope("45.33.32.0/24").allowed


def test_public_ipv6_address_is_refused():
    decision = scope("2001:4860:4860::8888")
    assert not decision.allowed and "public" in decision.reason


def test_carrier_shared_range_is_refused_although_python_calls_it_not_public():
    for target in ["100.64.0.1", "100.127.255.254", "100.64.0.0/10"]:
        decision = scope(target)
        assert not decision.allowed and "100.64.0.0/10" in decision.reason, target


def test_venue_network_is_refused_while_we_are_on_our_hotspot():
    """Live check 4: the venue network is private too, but it isn't ours; the allowlist decides."""
    for target in [VENUE_SUBNET, "10.240.3.7"]:
        decision = scope(target)
        assert not decision.allowed and "afara" in decision.reason and "outside" in decision.reason, target


def test_every_target_is_refused_on_the_venue_wifi():
    """On the venue's Wi-Fi its subnet is "the connected subnet": the SSID check is what refuses it."""
    for target in [VENUE_SUBNET, "10.240.3.7", HOTSPOT_SUBNET]:
        decision = scope(target, ssid=VENUE_SSID, allowlist=(VENUE_SUBNET,))
        assert not decision.allowed and HOTSPOT_SSID in decision.reason, target


def test_every_target_is_refused_when_the_interface_is_not_on_wifi():
    decision = scope(HOTSPOT_SUBNET, ssid="")
    assert not decision.allowed and "none" in decision.reason


def test_hotspot_name_must_match_exactly():
    for ssid in ["rsh-conetuga", "RSH-ConeTuga ", "RSH-ConeTuga2", "RSH-ConeTuga-5G"]:
        assert not scope(HOTSPOT_SUBNET, ssid=ssid).allowed, ssid


def test_range_larger_than_our_subnet_is_refused():
    for target in ["172.20.0.0/16", "172.20.10.0/27", "172.16.0.0/12"]:
        assert not scope(target).allowed, target


def test_whole_internet_range_is_refused():
    for target in ["0.0.0.0/0", "0.0.0.0/1", "::/0"]:
        assert not scope(target).allowed, target


def test_domain_name_is_refused_without_a_dns_lookup(monkeypatch):
    def no_dns(*args, **kwargs):
        raise AssertionError("the guardrail must never look up a name")

    for lookup in ["getaddrinfo", "gethostbyname", "gethostbyname_ex"]:
        monkeypatch.setattr(socket, lookup, no_dns)
    for target in ["router.local", "scanme.nmap.org", "localhost", ""]:
        decision = scope(target)
        assert not decision.allowed and "domeniu" in decision.reason and "domain" in decision.reason, target


def test_target_that_smuggles_nmap_options_or_lists_is_refused():
    for target in ["172.20.10.3 -oN /tmp/x", "-iL targets.txt", "172.20.10.3,8.8.8.8", "172.20.10.1-5",
                   "172.20.10.*", "172.20.10.3 8.8.8.8"]:
        assert not scope(target).allowed, target


def test_loopback_and_link_local_are_refused():
    for target in ["127.0.0.1", "169.254.10.1", "fe80::1", "::ffff:172.20.10.3"]:
        assert not scope(target).allowed, target


def test_octal_looking_address_is_refused():
    """"010.0.0.1" is 8.0.0.1 for some tools and 10.0.0.1 for others: an ambiguous target is never scanned."""
    assert not scope("010.0.0.1").allowed


def test_live_scan_needs_confirm():
    decision = scope(HOTSPOT_SUBNET, confirmed=False)
    assert not decision.allowed and "--confirm" in decision.reason


def test_one_device_on_our_subnet_is_allowed_with_confirm():
    assert scope("172.20.10.5").allowed


def test_host_bits_in_a_range_mean_the_whole_range():
    """As in nmap, 172.20.10.13/28 is the /28 that holds .13."""
    decision = scope("172.20.10.13/28")
    assert decision.allowed and HOTSPOT_SUBNET in decision.reason


def test_spaces_around_the_target_are_ignored():
    assert scope(" 172.20.10.5 ").allowed


def test_empty_allowlist_refuses_everything():
    assert not scope("172.20.10.5", allowlist=()).allowed


def test_allowlist_entry_that_is_not_a_range_allows_nothing():
    assert not scope("172.20.10.5", allowlist=("router.local",)).allowed


def test_reason_is_one_romanian_line_then_one_english_line():
    for decision in [scope("8.8.8.8"), scope(HOTSPOT_SUBNET, confirmed=False), scope(HOTSPOT_SUBNET)]:
        romanian, english = decision.reason.split("\n")
        assert romanian and english and romanian != english


def test_hostile_wifi_name_is_shown_escaped():
    """Anyone can name a Wi-Fi network; its name reaches the terminal only escaped (NFR-03)."""
    decision = scope(HOTSPOT_SUBNET, ssid="Free\x1b[2J\nWiFi")
    assert not decision.allowed and "\x1b" not in decision.reason and len(decision.reason.split("\n")) == 2


# --- detect_network (FR-01) -------------------------------------------------------------------------------------

def address(ip: str, netmask: str) -> SimpleNamespace:
    """One IPv4 entry of psutil.net_if_addrs()."""
    return SimpleNamespace(family=socket.AF_INET, address=ip, netmask=netmask)


# A's scanner laptop on our hotspot (Ubuntu 24.04): Docker bridges and libvirt's virbr0 come first in the list.
LINUX_INTERFACES = {
    "lo": [address("127.0.0.1", "255.0.0.0")],
    "docker0": [address("172.17.0.1", "255.255.0.0")],
    "br-d7eaf2818e01": [address("172.18.0.1", "255.255.0.0")],
    "virbr0": [address("192.168.122.1", "255.255.255.0")],
    "wlp0s20f3": [address("172.20.10.13", "255.255.255.240")],
}
LINUX_DEFAULT_ROUTE = "default via 172.20.10.1 dev wlp0s20f3 proto dhcp src 172.20.10.13 metric 600 \n"
LINUX_WIFI_LIST = "no:UnivBuc Free:wlp0s20f3\nyes:RSH-ConeTuga:wlp0s20f3\nno:DIRECT-xx-HP Printer:wlp0s20f3\n"

# The contract's example: a Windows laptop on an iPhone hotspot.
WINDOWS_INTERFACES = {
    "vEthernet (WSL)": [address("172.29.160.1", "255.255.240.0")],
    "Wi-Fi": [address("172.20.10.3", "255.255.255.240")],
    "Loopback Pseudo-Interface 1": [address("127.0.0.1", "255.0.0.0")],
}
WINDOWS_DEFAULT_ROUTE = "Wi-Fi|172.20.10.1\r\n"
WINDOWS_WIFI_INTERFACES = (
    "\r\nThere is 1 interface on the system:\r\n\r\n"
    "    Name                   : Wi-Fi\r\n"
    "    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r\n"
    "    GUID                   : 00000000-0000-4000-8000-000000000000\r\n"
    "    Physical address       : 3c:a9:f4:xx:xx:xx\r\n"
    "    State                  : connected\r\n"
    "    SSID                   : RSH-ConeTuga\r\n"
    "    AP BSSID               : 5a:2b:7e:xx:xx:xx\r\n"
    "    Network type           : Infrastructure\r\n"
    "    Authentication         : WPA2-Personal\r\n"
    "    Profile                : RSH-ConeTuga\r\n"
    "\r\n    Hosted network status  : Not available\r\n\r\n"
)


def fake_os(monkeypatch, windows: bool, local_ip: str, interfaces: dict, outputs: dict[str, str]) -> None:
    """Replays a laptop: its OS, the address the route probe finds, its interfaces, and each command's output."""
    monkeypatch.setattr(network, "_on_windows", lambda: windows)
    monkeypatch.setattr(network, "_local_ip", lambda: local_ip)
    monkeypatch.setattr(network.psutil, "net_if_addrs", lambda: interfaces)
    monkeypatch.setattr(network, "_run", lambda command, encoding="utf-8": outputs[command[0]])


def test_contract_detect_network(monkeypatch):
    """The contract's example: on an iPhone hotspot, Network("Wi-Fi", "172.20.10.3", "172.20.10.0/28", ...)."""
    fake_os(monkeypatch, True, "172.20.10.3", WINDOWS_INTERFACES, {"powershell": WINDOWS_DEFAULT_ROUTE})
    assert detect_network() == Network("Wi-Fi", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")


def test_detect_network_follows_the_default_route_past_docker_and_virbr0(monkeypatch):
    """A's scanner laptop on our hotspot (A's 15:09 message): the Wi-Fi card, not the first interface."""
    fake_os(monkeypatch, False, "172.20.10.13", LINUX_INTERFACES, {"ip": LINUX_DEFAULT_ROUTE})
    assert detect_network() == Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1")


def test_detect_network_takes_the_gateway_of_the_interface_in_use(monkeypatch):
    """With a cable and Wi-Fi both up, the gateway comes from the interface the route probe found."""
    interfaces = {**LINUX_INTERFACES, "enp3s0": [address("192.168.0.20", "255.255.255.0")]}
    routes = "default via 192.168.0.1 dev enp3s0 proto dhcp metric 100\n" + LINUX_DEFAULT_ROUTE
    fake_os(monkeypatch, False, "172.20.10.13", interfaces, {"ip": routes})
    assert detect_network().gateway == "172.20.10.1"


def test_windows_takes_the_gateway_of_the_interface_in_use(monkeypatch):
    interfaces = {**WINDOWS_INTERFACES, "Ethernet": [address("192.168.0.20", "255.255.255.0")]}
    routes = "Ethernet|192.168.0.1\r\n" + WINDOWS_DEFAULT_ROUTE
    fake_os(monkeypatch, True, "172.20.10.3", interfaces, {"powershell": routes})
    assert detect_network().gateway == "172.20.10.1"


def test_android_hotspot_subnet_is_detected_not_hard_coded(monkeypatch):
    interfaces = {"wlan0": [address("192.168.43.57", "255.255.255.0")]}
    routes = "default via 192.168.43.1 dev wlan0 proto dhcp src 192.168.43.57 metric 600\n"
    fake_os(monkeypatch, False, "192.168.43.57", interfaces, {"ip": routes})
    assert detect_network() == Network("wlan0", "192.168.43.57", "192.168.43.0/24", "192.168.43.1")


def test_no_network_raises_network_not_found(monkeypatch):
    class UnreachableSocket:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def connect(self, address):
            raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(network.socket, "socket", UnreachableSocket)
    with pytest.raises(NetworkNotFound, match="not connected to any network"):
        detect_network()


def test_address_on_no_interface_raises_network_not_found(monkeypatch):
    fake_os(monkeypatch, False, "10.9.8.7", LINUX_INTERFACES, {"ip": LINUX_DEFAULT_ROUTE})
    with pytest.raises(NetworkNotFound, match="10.9.8.7"):
        detect_network()


def test_interface_without_a_gateway_raises_network_not_found(monkeypatch):
    """E.g. a VPN that took the route: its subnet must never become the allowlist."""
    interfaces = {**LINUX_INTERFACES, "tun0": [address("10.8.0.6", "255.255.255.0")]}
    fake_os(monkeypatch, False, "10.8.0.6", interfaces, {"ip": LINUX_DEFAULT_ROUTE})
    with pytest.raises(NetworkNotFound, match="tun0"):
        detect_network()


def test_windows_route_with_no_next_hop_is_not_a_gateway(monkeypatch):
    fake_os(monkeypatch, True, "172.20.10.3", WINDOWS_INTERFACES, {"powershell": "Wi-Fi|0.0.0.0\r\n"})
    with pytest.raises(NetworkNotFound, match="Wi-Fi"):
        detect_network()


def test_missing_system_command_raises_network_not_found():
    with pytest.raises(NetworkNotFound, match="conetuga-no-such-command"):
        network._run(["conetuga-no-such-command"])


# --- wifi_ssid: the Wi-Fi name that check_scope compares with RSH-ConeTuga ----------------------------------------

def test_linux_wifi_name_of_the_interface(monkeypatch):
    fake_os(monkeypatch, False, "", {}, {"nmcli": LINUX_WIFI_LIST})
    assert wifi_ssid("wlp0s20f3") == HOTSPOT_SSID


def test_linux_interface_not_on_wifi_has_no_wifi_name(monkeypatch):
    """A laptop on our hotspot and on the venue's cable: the cable's subnet never passes as the hotspot."""
    fake_os(monkeypatch, False, "", {}, {"nmcli": LINUX_WIFI_LIST})
    assert wifi_ssid("enp3s0") == ""


def test_linux_wifi_name_with_a_colon():
    assert network.parse_linux_ssid("no:x:wlan0\nyes:Cafe\\:Bar\\\\1:wlan0\n", "wlan0") == "Cafe:Bar\\1"


def test_windows_wifi_name_of_the_interface(monkeypatch):
    fake_os(monkeypatch, True, "", {}, {"netsh": WINDOWS_WIFI_INTERFACES})
    assert wifi_ssid("Wi-Fi") == HOTSPOT_SSID


def test_windows_disconnected_interface_has_no_wifi_name():
    output = "\r\nThere is 1 interface on the system:\r\n\r\n    Name : Wi-Fi\r\n    State : disconnected\r\n\r\n"
    assert network.parse_windows_ssid(output, "Wi-Fi") == ""


def test_windows_wifi_name_with_translated_labels():
    """netsh's labels are translated on a Romanian Windows; only "SSID" stays the same."""
    output = "\r\nExistă 1 interfață în sistem:\r\n\r\n    Nume   : Wi-Fi\r\n    Stare  : conectat\r\n" \
             "    SSID   : RSH-ConeTuga\r\n    BSSID  : 5a:2b:7e:xx:xx:xx\r\n\r\n"
    assert network.parse_windows_ssid(output, "Wi-Fi") == HOTSPOT_SSID


def test_windows_wifi_name_belongs_to_its_own_interface():
    output = "\r\n    Name : Wi-Fi 2\r\n    SSID : UnivBuc Free\r\n\r\n    Name : Wi-Fi\r\n    State : disconnected\r\n"
    assert network.parse_windows_ssid(output, "Wi-Fi") == ""


def test_wifi_name_is_empty_when_the_command_fails(monkeypatch):
    """No nmcli or no Wi-Fi service: we can't prove we're on the hotspot, so check_scope will refuse."""
    def failing_run(command, encoding="utf-8"):
        raise NetworkNotFound("no Wi-Fi tool")

    for windows in (False, True):
        monkeypatch.setattr(network, "_on_windows", lambda windows=windows: windows)
        monkeypatch.setattr(network, "_run", failing_run)
        assert wifi_ssid("wlan0") == ""
