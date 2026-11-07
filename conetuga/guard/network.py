"""Network detection (FR-01): the active interface, its address, subnet and gateway, and its Wi-Fi name, found with
no manual input. The subnet is the guardrail's default allowlist, and the UI shows it (contract "detect_network").

"Active" means the interface the default route leaves through: the scanner laptops also have Docker bridges and
libvirt's virbr0, so the first interface in a list would be wrong. The subnet is never hard-coded: iPhone hotspots
usually give 172.20.10.0/28, Android ones vary by model.

This is the only OS-specific code in the project (CLAUDE.md). Every system command goes through `_run`, so the tests
replay saved command outputs for both branches, on any computer and without a network."""
import ipaddress
import os
import socket
import subprocess
import sys
from dataclasses import dataclass

import psutil

# Connecting a UDP socket sends nothing: the OS only picks the route to this address, which tells us our own address
# on the interface the default route uses. 192.0.2.1 is TEST-NET-1 (RFC 5737): never a real host.
ROUTE_PROBE = ("192.0.2.1", 9)
COMMAND_TIMEOUT_SECONDS = 10  # these commands answer in well under a second; a hung one must not hang the tool

LINUX_ROUTE_COMMAND = ["ip", "route", "show", "default"]
# --rescan no: read the list NetworkManager already has, without asking the Wi-Fi card to look for networks.
LINUX_WIFI_COMMAND = ["nmcli", "-t", "-f", "ACTIVE,SSID,DEVICE", "device", "wifi", "list", "--rescan", "no"]
LINUX_ACTIVE = "yes"
# One "<interface>|<gateway>" line per IPv4 default route; UTF-8 so a non-English interface name survives.
WINDOWS_ROUTE_COMMAND = [
    "powershell", "-NoProfile", "-NonInteractive", "-Command",
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | "
    "ForEach-Object { $_.InterfaceAlias + '|' + $_.NextHop }",
]
WINDOWS_WIFI_COMMAND = ["netsh", "wlan", "show", "interfaces"]
WINDOWS_ON_LINK = "0.0.0.0"  # Get-NetRoute's next hop for a route with no gateway
WINDOWS_CONSOLE_ENCODING = "oem"  # netsh writes in the console's OEM code page, not UTF-8


@dataclass(frozen=True)
class Network:
    """The network the laptop uses now, e.g. Network("Wi-Fi", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")."""

    interface: str
    ip: str
    subnet: str  # CIDR, e.g. "172.20.10.0/28": the guardrail's default allowlist
    gateway: str


class NetworkNotFound(Exception):
    """No usable network: the message says why, in Romanian and English, in words a user can act on."""


def detect_network() -> Network:
    """The interface the default route uses, with its IPv4 address, subnet and gateway. Raises NetworkNotFound when
    the laptop has no active network; a half-found network is never returned, because its subnet would be wrong."""
    ip = _local_ip()
    interface, netmask = _interface_with_address(ip)
    subnet = str(ipaddress.ip_interface(f"{ip}/{netmask}").network)
    if _on_windows():
        gateway = parse_windows_gateway(_run(WINDOWS_ROUTE_COMMAND), interface)
    else:
        gateway = parse_linux_gateway(_run(LINUX_ROUTE_COMMAND), interface)
    if not gateway:
        raise NetworkNotFound(
            f"Interfața {interface!r} nu are un gateway (ruta implicită nu trece prin ea).\n"
            f"The interface {interface!r} has no gateway (the default route doesn't go through it)."
        )
    return Network(interface=interface, ip=ip, subnet=subnet, gateway=gateway)


def wifi_ssid(interface: str) -> str:
    """The Wi-Fi network (SSID) that `interface` is connected to, or "" when it isn't connected to Wi-Fi or the name
    can't be read. Asked per interface on purpose: the SSID must belong to the interface whose subnet we would scan,
    or a laptop on our hotspot and on the venue's cable could pass the check for the venue's subnet."""
    try:
        if _on_windows():
            return parse_windows_ssid(_run(WINDOWS_WIFI_COMMAND, WINDOWS_CONSOLE_ENCODING), interface)
        return parse_linux_ssid(_run(LINUX_WIFI_COMMAND), interface)
    except NetworkNotFound:
        return ""  # no Wi-Fi tool or no Wi-Fi service: not on our hotspot, so check_scope refuses


def parse_linux_gateway(output: str, interface: str) -> str:
    """The gateway of `interface` in `ip route show default`, e.g. from
    "default via 172.20.10.1 dev wlp0s20f3 proto dhcp src 172.20.10.13 metric 600"; "" when it has none."""
    for line in output.splitlines():
        words = line.split()
        fields = dict(zip(words, words[1:]))
        if words[:1] == ["default"] and fields.get("dev") == interface and "via" in fields:
            return fields["via"]
    return ""


def parse_windows_gateway(output: str, interface: str) -> str:
    """The gateway of `interface` in WINDOWS_ROUTE_COMMAND's "<interface>|<gateway>" lines; "" when it has none."""
    for line in output.splitlines():
        alias, _, next_hop = line.strip().rpartition("|")
        if alias == interface and next_hop and next_hop != WINDOWS_ON_LINK:
            return next_hop
    return ""


def parse_linux_ssid(output: str, interface: str) -> str:
    """The SSID that `interface` is connected to, from nmcli's terse "ACTIVE:SSID:DEVICE" lines; "" when none."""
    for line in output.splitlines():
        fields = _split_nmcli_terse(line)
        if len(fields) == 3 and fields[0] == LINUX_ACTIVE and fields[2] == interface:
            return fields[1]
    return ""


def parse_windows_ssid(output: str, interface: str) -> str:
    """The SSID that `interface` is connected to, from `netsh wlan show interfaces`; "" when none. netsh's labels
    are translated on a Romanian Windows, so a block's first "label : value" line is taken as the interface name,
    and only the "SSID" label (never translated) is read; netsh prints it only for a connected interface. A blank
    line ends one interface's block; splitlines() also handles Windows' "\\r\\n"."""
    name, ssid = "", ""
    for line in output.splitlines() + [""]:
        label, colon, value = line.partition(":")
        if not line.strip():
            if name == interface:
                return ssid
            name, ssid = "", ""
        elif colon and value.strip():
            if not name:
                name = value.strip()
            elif label.strip() == "SSID":
                ssid = value.strip()
    return ""


def _split_nmcli_terse(line: str) -> list[str]:
    """Split one line of `nmcli -t` output on ":". nmcli writes a ":" inside a value as "\\:" and a "\\" as "\\\\",
    and anyone can name a Wi-Fi network "a:b"."""
    fields, current, escaped = [], [], False
    for char in line.rstrip("\r\n"):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _local_ip() -> str:
    """Our IPv4 address on the interface the default route uses (see ROUTE_PROBE: no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(ROUTE_PROBE)
            return probe.getsockname()[0]
    except OSError as exc:
        raise NetworkNotFound(
            f"Laptopul nu este conectat la nicio rețea ({exc.strerror or exc}). Conectează-l la hotspotul echipei.\n"
            f"The laptop is not connected to any network ({exc.strerror or exc}). Connect it to the team's hotspot."
        ) from exc


def _interface_with_address(ip: str) -> tuple[str, str]:
    """The name and IPv4 netmask of the interface that holds `ip`."""
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET and address.address == ip and address.netmask:
                return name, address.netmask
    raise NetworkNotFound(
        f"Nicio interfață de rețea nu are adresa {ip}.\n"
        f"No network interface holds the address {ip}."
    )


def _on_windows() -> bool:
    """The one place that asks which OS we run on, so the tests can run both branches on any computer."""
    return sys.platform == "win32"


def _run(command: list[str], encoding: str = "utf-8") -> str:
    """The text a system command prints. Any failure becomes NetworkNotFound, never a traceback. On Linux the command
    runs in the C locale, so its words ("default", "yes") are never translated."""
    environment = {**os.environ, "LC_ALL": "C"} if not _on_windows() else None
    try:
        completed = subprocess.run(command, capture_output=True, check=True, timeout=COMMAND_TIMEOUT_SECONDS,
                                   env=environment)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkNotFound(
            f"Comanda {command[0]!r} nu a mers ({exc}).\n"
            f"The command {command[0]!r} failed ({exc})."
        ) from exc
    return completed.stdout.decode(encoding, errors="replace")
