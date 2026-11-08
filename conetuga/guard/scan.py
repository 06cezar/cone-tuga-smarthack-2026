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
The app's "Scanează acum" button (`scan_from_app`) runs the same command behind the same guardrail; only nmap gets
administrator rights, through the system's own password window (pkexec on Linux, UAC on Windows).
No other script is named: the brief bans brute, exploit, dos, intrusive and vuln scripts. The version scripts that
-sV runs by itself are part of the standard capture (`nmap -sS -sU -sV -oX`), so they stay."""
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
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
XML_TO_OUTPUT = "-"  # nmap's -oX - : the XML comes on its output, so no file is left owned by root (scan_from_app)
# pkexec's own exit codes when it gives no rights: 126, the person closed its password window or isn't an
# administrator; 127, no window could open (no polkit agent).
PKEXEC_DISMISSED = 126
PKEXEC_NO_AGENT = 127
# ShellExecuteExW (shellapi.h): keep the process handle so we can wait for nmap and read its exit code, and finish
# the launch before returning; nmap's window starts minimised, so the person can open it to watch the progress.
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_SHOWMINNOACTIVE = 7
WAIT_FOREVER = 0xFFFFFFFF  # INFINITE: nmap's own --host-timeout is what bounds the wait
NMAP_ERROR_CHARACTERS = 300  # the end of nmap's error output shown with a failure, enough for its last message


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


class PasswordWindowRefused(ScanError):
    """scan_from_app: the system's password window was cancelled or couldn't open, so nmap never ran. The app
    shows the terminal command instead. Romanian line, English line."""


def live_scan(target: str | None, confirmed: bool, out: Path = DEFAULT_OUT,
              minutes: int = DEFAULT_MINUTES) -> LiveScan:
    """Scans `target` (None: the subnet we're connected to), giving nmap at most `minutes` per device, and returns
    where nmap wrote its XML. Raises ScanRefused unless the guardrail allows the target, NetworkNotFound with no
    network, and ScanError when nmap can't run or `minutes` is under MIN_MINUTES."""
    _check_minutes(minutes)
    network, ssid, scanned, nmap = _approved(target, confirmed)
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


def scan_from_app(confirmed: bool, minutes: int = DEFAULT_MINUTES, out: Path = DEFAULT_OUT) -> LiveScan:
    """The live scan behind the app's "Scanează acum" button: the connected subnet, the same guardrail and the same
    nmap command as `live_scan`, but the rights for nmap come from the system's own password window (pkexec on Linux,
    UAC on Windows), since the app has no terminal to type a password into and never runs as administrator itself
    (NFR-04). `confirmed` is the page's tick. Raises what `live_scan` raises, and PasswordWindowRefused when the
    window is cancelled or can't open; no error leaves a file behind."""
    _check_minutes(minutes)
    network, ssid, scanned, nmap = _approved(None, confirmed)
    nmap = os.path.abspath(nmap)  # pkexec runs only a program named by its full path, with an emptied environment
    ports = scan_ports(nmap)
    if _is_admin():
        content = _xml_from_output(nmap_command(nmap, scanned, network.ip, ports, XML_TO_OUTPUT, minutes))
    elif _on_windows():
        content = _xml_through_uac(nmap, scanned, network.ip, ports, minutes)
    else:
        content = _xml_through_pkexec(nmap_command(nmap, scanned, network.ip, ports, XML_TO_OUTPUT, minutes))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    xml = (out / datetime.now().strftime(SCAN_FILE_NAME)).resolve()
    xml.write_bytes(content)  # written by us, an ordinary user, so the person can read and delete it
    return LiveScan(network=network, ssid=ssid, scanned=scanned, xml=xml, minutes=minutes,
                    timed_out=timed_out_devices(xml))


def nmap_command(nmap: str, scanned: str, scanner_ip: str, tcp_ports: list[int], xml: Path | str,
                 minutes: int = DEFAULT_MINUTES) -> list[str]:
    """The one nmap command a live scan runs. `scanned` is the guardrail's parsed range, so it can't carry options.
    `xml` is where nmap writes its XML; XML_TO_OUTPUT ("-") sends it to nmap's output instead."""
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


def _approved(target: str | None, confirmed: bool) -> tuple[Network, str, str, str]:
    """The guardrail's yes, the same for the CLI and the app: the network, its Wi-Fi name, the range it approved
    (parsed, never the raw text) and nmap's path. Raises ScanRefused, NetworkNotFound, or ScanError with no nmap."""
    network = detect_network()
    ssid = wifi_ssid(network.interface)
    target = network.subnet if target is None else target
    decision = check_scope(target, [network.subnet], confirmed, ssid)
    if not decision.allowed:
        raise ScanRefused(decision.reason)
    scanned = str(_parse_target(target))
    nmap = _find_nmap()
    if nmap is None:
        raise ScanError(
            "nmap nu este instalat: sudo apt install nmap (Linux) sau instalatorul de pe nmap.org (Windows).\n"
            "nmap isn't installed: sudo apt install nmap (Linux) or the nmap.org installer (Windows)."
        )
    return network, ssid, scanned, nmap


def _check_minutes(minutes: int) -> None:
    if minutes < MIN_MINUTES:
        raise ScanError(
            f"Scanarea are nevoie de cel puțin {MIN_MINUTES} minute pe dispozitiv "
            f"(--minutes {MIN_MINUTES} sau mai mult).\n"
            f"The scan needs at least {MIN_MINUTES} minutes per device (--minutes {MIN_MINUTES} or more)."
        )


def _xml_from_output(command: list[str]) -> bytes:
    """Runs nmap (already with its rights) and returns the XML it printed with -oX -."""
    returncode, xml, errors = _run_nmap_for_xml(command)
    if returncode != 0 or not xml.strip():
        raise _nmap_failed(errors)
    return xml


def _xml_through_pkexec(command: list[str]) -> bytes:
    """Linux: Ubuntu's own password window (pkexec) gives the rights to nmap alone, for this one run."""
    pkexec = shutil.which("pkexec")
    if pkexec is None:
        raise PasswordWindowRefused(
            "Fereastra de parolă a sistemului (pkexec) lipsește; rulează scanarea din terminal.\n"
            "The system's password window (pkexec) is missing; run the scan from the terminal."
        )
    returncode, xml, errors = _run_nmap_for_xml([pkexec, *command])
    if returncode in (PKEXEC_DISMISSED, PKEXEC_NO_AGENT):
        raise _window_refused()
    if returncode != 0 or not xml.strip():
        raise _nmap_failed(errors)
    return xml


def _xml_through_uac(nmap: str, scanned: str, scanner_ip: str, ports: list[int], minutes: int) -> bytes:
    """Windows: the UAC window gives the rights to nmap.exe alone. An elevated nmap can't hand its output back to
    us, so it writes the XML into a new temporary folder of ours, which is deleted once the file is read."""
    folder = Path(tempfile.mkdtemp(prefix="conetuga-scan-"))
    try:
        xml = folder / "scan.xml"
        command = nmap_command(nmap, scanned, scanner_ip, ports, xml, minutes)
        if _run_as_admin(command) != 0 or not xml.is_file():
            raise _nmap_failed("")
        return xml.read_bytes()
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _window_refused() -> PasswordWindowRefused:
    return PasswordWindowRefused(
        "Fereastra de parolă a fost închisă sau nu s-a putut deschide, deci nmap nu a pornit.\n"
        "The password window was closed or couldn't open, so nmap didn't start."
    )


def _nmap_failed(errors: str) -> ScanError:
    last = " ".join(errors.split())[-NMAP_ERROR_CHARACTERS:]
    detail = f" ({last})" if last else ""
    return ScanError(
        f"nmap nu a terminat scanarea{detail}.\n"
        f"nmap didn't finish the scan{detail}."
    )


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


def _run_nmap_for_xml(command: list[str]) -> tuple[int, bytes, str]:
    """Runs nmap (through pkexec, or already with its rights) and returns its exit code, the XML it printed and the
    text of its errors. A list of arguments, never a shell: no text can become an option."""
    completed = subprocess.run(command, capture_output=True)
    return completed.returncode, completed.stdout, completed.stderr.decode("utf-8", errors="replace")


def _run_as_admin(command: list[str]) -> int:
    """Windows: starts `command` (nmap.exe and its arguments) through the UAC window, waits for it and returns its
    exit code. Raises PasswordWindowRefused when the person says no or the window can't open."""
    from ctypes import wintypes  # Windows-only names, loaded only on the Windows branch

    class ShellExecuteInfo(ctypes.Structure):  # SHELLEXECUTEINFOW, shellapi.h
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    info = ShellExecuteInfo(fMask=SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC, lpVerb="runas", lpFile=command[0],
                            lpParameters=subprocess.list2cmdline(command[1:]), nShow=SW_SHOWMINNOACTIVE)
    info.cbSize = ctypes.sizeof(info)
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        raise _window_refused()  # the person said no (ERROR_CANCELLED), or no window could open
    try:
        kernel32.WaitForSingleObject(info.hProcess, WAIT_FOREVER)
        exit_code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
        return exit_code.value
    finally:
        kernel32.CloseHandle(info.hProcess)
