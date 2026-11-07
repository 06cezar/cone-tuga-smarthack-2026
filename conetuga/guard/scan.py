"""The live scan (FR-04): nmap on our hotspot's subnet, started by a person with --confirm, then the same analysis.

Every live scan goes through `live_scan`, and `live_scan` always asks the guardrail first (`check_scope`, FR-02), on
the network it detects itself: no caller can reach nmap without it. Claude never runs it; a team member does, on our
hotspot only (rules of engagement).

What nmap does is fixed here and nowhere else (rules of engagement, conetuga/guard/CLAUDE.md):
- a SYN scan of nmap's own top 1,000 TCP ports plus the catalog's ports outside them, UDP 53, 123, 161, 1900 and
  5353, version detection, and the "safe" http-title script, without which no page title is recorded;
- at most 100 packets per second; nmap finds the live hosts first (ARP on our subnet) and scans ports only on them,
  which keeps a /24 under 5 minutes (NFR-07);
- the scanner itself is left out: nmap lists it with no MAC, which would be a false UNKNOWN_DEVICE;
- at most `--minutes` (5 or more) per device; a device nmap gives up on is named, since its findings are missing.
No other script is named: the brief bans brute, exploit, dos, intrusive and vuln scripts. The version scripts that
-sV runs by itself are part of the standard capture (`nmap -sS -sU -sV -oX`), so they stay."""
import ctypes
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import defusedxml.ElementTree as SafeET

from conetuga.guard.network import Network, detect_network, wifi_ssid
from conetuga.guard.scope import _parse_target, check_scope

TOP_TCP_PORTS = 1000  # FR-04: "at least the top 1,000 TCP ports", as nmap ranks them
# Catalog services whose usual port isn't in nmap's top 1,000 (MQTT 1883, Redis 6379, MongoDB 27017), and the lab's
# Redis on 6380: the catalog decides by service, so a service is found only on a port that is scanned.
EXTRA_TCP_PORTS = (1883, 6379, 6380, 27017)
UDP_PORTS = (53, 123, 161, 1900, 5353)  # FR-04
MAX_PACKETS_PER_SECOND = 100  # rules of engagement: "rate-limited scans (<= 100 packets/second)"
SAFE_SCRIPT = "http-title"  # NSE category "safe"; HTTP_ADMIN_CLEARTEXT needs the page title it records
PROGRESS_EVERY = "30s"  # nmap says how far it is, so a person doesn't take a 3-minute scan for a hung one
DEFAULT_OUT = Path("results")  # gitignored: nmap's raw XML holds real MACs and names (NFR-02)
SCAN_FILE_NAME = "scan_%Y%m%d-%H%M%S.xml"  # one file per scan, in time order
PORT_LIST_TIMEOUT_SECONDS = 30  # nmap prints its port list in a fraction of a second
# How long nmap may spend on one device (--host-timeout), chosen with --minutes. 5 is the floor, NFR-07's "a /24 under
# 5 minutes": our 2-device lab took 3.4 minutes, ~3 of them in version detection waiting on silent ports, so less
# would drop ordinary devices. nmap skips a device that runs out of time, so the scan names every one it skipped.
MIN_MINUTES = 5
DEFAULT_MINUTES = MIN_MINUTES


@dataclass(frozen=True)
class LiveScan:
    """What one live scan did. `xml` is nmap's raw file, with real MACs and names: it stays on this computer."""

    network: Network
    ssid: str
    scanned: str  # the range nmap scanned, exactly as the guardrail parsed it, e.g. "172.20.10.0/28"
    xml: Path
    minutes: int  # nmap's time limit per device
    timed_out: tuple[str, ...] = ()  # devices nmap gave up on: their ports and findings are missing from `xml`


class ScanRefused(Exception):
    """The guardrail said no. The message is its reason: one Romanian line, then one English line."""


class ScanError(Exception):
    """The scan couldn't run or finish (no nmap, no administrator rights, nmap failed). Romanian line, English line."""


def live_scan(target: str | None, confirmed: bool, out: Path = DEFAULT_OUT,
              minutes: int = DEFAULT_MINUTES) -> LiveScan:
    """Scans `target` (None: the subnet we're connected to), giving nmap at most `minutes` per device, and returns
    where nmap wrote its XML. Raises ScanRefused unless the guardrail allows the target, NetworkNotFound with no
    network, and ScanError when nmap can't run or `minutes` is under MIN_MINUTES."""
    if minutes < MIN_MINUTES:
        raise ScanError(
            f"Scanarea are nevoie de cel puțin {MIN_MINUTES} minute pe dispozitiv "
            f"(--minutes {MIN_MINUTES} sau mai mult).\n"
            f"The scan needs at least {MIN_MINUTES} minutes per device (--minutes {MIN_MINUTES} or more)."
        )
    network = detect_network()
    ssid = wifi_ssid(network.interface)
    target = network.subnet if target is None else target
    decision = check_scope(target, [network.subnet], confirmed, ssid)
    if not decision.allowed:
        raise ScanRefused(decision.reason)
    scanned = str(_parse_target(target))  # the range the guardrail approved, never the raw text
    nmap = _find_nmap()
    if nmap is None:
        raise ScanError(
            "nmap nu este instalat: sudo apt install nmap (Linux) sau instalatorul de pe nmap.org (Windows).\n"
            "nmap isn't installed: sudo apt install nmap (Linux) or the nmap.org installer (Windows)."
        )
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)  # created by us, not by nmap running as root, so we can delete it later
    xml = (out / datetime.now().strftime(SCAN_FILE_NAME)).resolve()
    command = _with_admin_rights(nmap_command(nmap, scanned, network.ip, scan_ports(nmap), xml, minutes))
    if _run_nmap(command) != 0 or not xml.is_file():
        raise ScanError(
            "nmap nu a terminat scanarea; mesajul lui este mai sus.\n"
            "nmap didn't finish the scan; its message is above."
        )
    return LiveScan(network=network, ssid=ssid, scanned=scanned, xml=xml, minutes=minutes,
                    timed_out=timed_out_devices(xml))


def nmap_command(nmap: str, scanned: str, scanner_ip: str, tcp_ports: list[int], xml: Path,
                 minutes: int = DEFAULT_MINUTES) -> list[str]:
    """The one nmap command a live scan runs. `scanned` is the guardrail's parsed range, so it can't carry options."""
    ports = f"T:{_join(tcp_ports)},U:{_join(UDP_PORTS)}"
    return [nmap, "-sS", "-sU", "-sV", "--script", SAFE_SCRIPT, "--max-rate", str(MAX_PACKETS_PER_SECOND),
            "-p", ports, "--exclude", scanner_ip, "--host-timeout", f"{minutes}m", "--stats-every", PROGRESS_EVERY,
            "-oX", str(xml), scanned]


def timed_out_devices(xml: Path) -> tuple[str, ...]:
    """The addresses of the devices nmap gave up on (<host timedout="true">): it writes no port of theirs, so an
    empty list of findings for them means "not finished", never "safe". An unreadable file names none here; the
    analysis reports it as an error."""
    try:
        root = SafeET.parse(xml).getroot()
    except Exception:  # truncated or hostile XML: analyse_file gives the clear error
        return ()
    devices = []
    for host in root.iter("host"):
        if host.get("timedout") == "true":
            address = next((a.get("addr", "") for a in host.iterfind("address")
                            if a.get("addrtype") in ("ipv4", "ipv6")), "")
            devices.append(address or "?")
    return tuple(devices)


def scan_ports(nmap: str) -> list[int]:
    """The TCP ports a live scan covers: nmap's top 1,000 plus EXTRA_TCP_PORTS, sorted."""
    return sorted(set(top_tcp_ports(nmap)) | set(EXTRA_TCP_PORTS))


def top_tcp_ports(nmap: str) -> list[int]:
    """The installed nmap's own 1,000 most common TCP ports. nmap is asked with no target, so it sends nothing: it
    only writes the list into its XML header. This avoids building the list by hand, and nmap can't take
    --top-ports and a UDP port list in the same scan."""
    try:
        completed = subprocess.run([nmap, "-sT", "--top-ports", str(TOP_TCP_PORTS), "-n", "-oX", "-"],
                                   capture_output=True, check=True, timeout=PORT_LIST_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError(
            f"nmap nu și-a dat lista de porturi ({exc}).\n"
            f"nmap didn't give its port list ({exc})."
        ) from exc
    return parse_scaninfo_ports(completed.stdout)


def parse_scaninfo_ports(xml: bytes) -> list[int]:
    """The ports in nmap's <scaninfo services="1,3-4,..."> header, read with the same safe parser as scan files."""
    try:
        info = SafeET.fromstring(xml).find("scaninfo")
        ports = parse_port_list(info.get("services", "")) if info is not None else []
    except Exception as exc:  # anything unexpected from nmap ends in a clear error, never a traceback
        raise ScanError(
            f"Lista de porturi a lui nmap nu poate fi citită ({exc}).\n"
            f"nmap's port list can't be read ({exc})."
        ) from exc
    if not ports:
        raise ScanError(
            "nmap nu a dat nicio listă de porturi.\n"
            "nmap gave no port list."
        )
    return ports


def parse_port_list(text: str) -> list[int]:
    """nmap's compact port list, e.g. "1,3-4,6" -> [1, 3, 4, 6]."""
    ports = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        ports.extend(range(int(first), int(last or first) + 1))
    return ports


def _join(ports) -> str:
    return ",".join(str(port) for port in ports)


def _with_admin_rights(command: list[str]) -> list[str]:
    """-sS and -sU send raw packets, which needs administrator rights. On Linux only nmap gets them, through sudo
    (it asks for the password in the terminal), and our own code stays an ordinary user. On Windows there is no sudo:
    the terminal itself must be an administrator one."""
    if _is_admin():
        return command
    if _on_windows():
        raise ScanError(
            "Scanarea live are nevoie de un terminal deschis ca administrator (clic dreapta, Run as administrator).\n"
            "A live scan needs a terminal opened as administrator (right-click, Run as administrator)."
        )
    sudo = shutil.which("sudo")
    if sudo is None:
        raise ScanError(
            "Scanarea live are nevoie de drepturi de administrator, iar sudo lipsește.\n"
            "A live scan needs administrator rights, and sudo is missing."
        )
    return [sudo, "--", *command]


def _find_nmap() -> str | None:
    return shutil.which("nmap")


def _is_admin() -> bool:
    if _on_windows():
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def _on_windows() -> bool:
    return sys.platform == "win32"


def _run_nmap(command: list[str]) -> int:
    """Runs nmap in this terminal, so the person sees its progress and sudo can ask for the password."""
    return subprocess.run(command).returncode
