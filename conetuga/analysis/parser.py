"""Read an nmap XML file into hosts and their open ports, treating every byte of it as hostile (NFR-03).

The whole file is parsed at once with defusedxml, never with a recovering or streaming parser: a truncated file
must give no hosts at all, because any finding from its first half would be an extra row in findings.csv."""
import ipaddress
import re
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET

from conetuga.analysis.devices import guess_device_type
from conetuga.analysis.models import Host, Port

# A /24 scan with -sV and http-title is a few hundred kilobytes; anything far larger is not a scan of a small
# network, and refusing it keeps a hostile file from exhausting memory.
MAX_SCAN_BYTES = 20 * 1024 * 1024

NMAP_ROOT_TAG = "nmaprun"
OPEN_STATE = "open"  # "open|filtered", "filtered" and "closed" are not open (brief: "only for ports in state open")
UP_STATE = "up"
IP_ADDRESS_TYPES = ("ipv4", "ipv6")  # in order of preference when a host has both
MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
MAC_VISIBLE_BYTES = 3  # the vendor part (OUI) stays visible; the device part is hidden (NFR-02)
MAC_HIDDEN = "xx"


class ScanReadError(Exception):
    """The file can't be read as an nmap scan. The message says why, in words a user can act on."""


def parse_scan(path: Path) -> list[Host]:
    """All hosts that were up, with their open ports. Raises ScanReadError for anything that isn't a readable scan."""
    root = _read_root(path)
    try:
        return [host for element in root.iter("host") if (host := _parse_host(element)) is not None]
    except ScanReadError:
        raise
    except Exception as exc:  # hostile input can break any assumption; it must become an error row, never a crash
        raise ScanReadError(f"the scan file has an unexpected structure ({exc})") from exc


def mask_mac(mac: str) -> str:
    """'50:C7:BF:39:0C:8C' -> '50:C7:BF:xx:xx:xx'. Anything that isn't a MAC is hidden completely."""
    if not MAC_PATTERN.match(mac):
        return ":".join([MAC_HIDDEN] * 6)
    parts = mac.upper().split(":")
    return ":".join(parts[:MAC_VISIBLE_BYTES] + [MAC_HIDDEN] * (6 - MAC_VISIBLE_BYTES))


def _read_root(path: Path) -> Element:
    """The <nmaprun> element of the file, after the size check and a safe parse."""
    try:
        size = path.stat().st_size
        if size > MAX_SCAN_BYTES:
            raise ScanReadError(f"the file is too large to be a scan ({size} bytes, limit {MAX_SCAN_BYTES})")
        data = path.read_bytes()
    except OSError as exc:
        raise ScanReadError(f"the file can't be opened ({exc.strerror or exc})") from exc
    if not data.strip():
        raise ScanReadError("the file is empty")
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # ParseError for broken XML, DefusedXmlException for entities (XXE) and the like
        raise ScanReadError(f"the file is not complete, valid XML ({exc})") from exc
    if root.tag != NMAP_ROOT_TAG:
        raise ScanReadError(f"the file is XML but not an nmap scan (root element <{root.tag}>)")
    return root


def _parse_host(element: Element) -> Host | None:
    """One <host>, or None when it wasn't up or has no IP address to report findings on."""
    status = element.find("status")
    if status is None or status.get("state") != UP_STATE:
        return None
    ip = _ip_address(element)
    if not ip:
        return None
    mac, vendor = _mac_and_vendor(element)
    hostname = _first_hostname(element)
    ports = [port for port_element in element.iterfind("ports/port") if (port := _parse_port(port_element))]
    return Host(
        ip=ip,
        mac_masked=mask_mac(mac) if mac else "",
        vendor=vendor,
        hostname=hostname,
        device_type=guess_device_type(vendor=vendor, hostname=hostname, mac=mac, ports=ports),
        ports=ports,
    )


def _ip_address(element: Element) -> str:
    """The host's IP address as nmap wrote it, "" when it has none. A malformed address makes the file unreadable:
    findings are sorted by IP as a number, and a fake address must not crash that."""
    addresses = {a.get("addrtype"): a.get("addr", "") for a in element.iterfind("address")}
    ip = next((addresses[kind] for kind in IP_ADDRESS_TYPES if addresses.get(kind)), "")
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ScanReadError(f"a host has an address that is not an IP address ({ip!r})") from exc
    return ip


def _mac_and_vendor(element: Element) -> tuple[str, str]:
    for address in element.iterfind("address"):
        if address.get("addrtype") == "mac":
            return address.get("addr", ""), address.get("vendor", "").strip()
    return "", ""


def _first_hostname(element: Element) -> str:
    names = (h.get("name", "").strip() for h in element.iterfind("hostnames/hostname"))
    return next((name for name in names if name), "")


def _parse_port(element: Element) -> Port | None:
    """One <port>, or None when it isn't open."""
    state = element.find("state")
    if state is None or state.get("state") != OPEN_STATE:
        return None
    try:
        number = int(element.get("portid", ""))
    except ValueError as exc:
        raise ScanReadError(f"a port number is not a number ({element.get('portid')!r})") from exc
    service = element.find("service")
    return Port(
        port=number,
        proto=element.get("protocol", "").lower(),
        service=_attribute(service, "name"),
        product=_attribute(service, "product"),
        version=_attribute(service, "version"),
        ssl=_attribute(service, "tunnel") == "ssl",
        title=_http_title(element),
    )


def _attribute(element: Element | None, name: str) -> str:
    """An attribute of an element that may be missing (a port with no <service>), "" when absent."""
    return element.get(name, "") if element is not None else ""


def _http_title(port_element: Element) -> str:
    """The page title from the http-title script's <elem key="title">, never its `output` text: on a redirect nmap
    writes "Did not follow redirect to .../login" there, and that is not a title."""
    for script in port_element.iterfind("script"):
        if script.get("id") == "http-title":
            title = script.find("elem[@key='title']")
            return (title.text or "").strip() if title is not None else ""
    return ""
