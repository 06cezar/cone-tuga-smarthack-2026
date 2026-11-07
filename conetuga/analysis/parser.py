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
# The only protocols nmap writes on a <port> (nmap.dtd: <!ENTITY % port_protocols "(ip|tcp|udp|sctp)">). Anything else
# is not nmap output, and it would reach the UI as page text (a hostile "[click](https://...)" became a link).
PORT_PROTOCOLS = ("ip", "tcp", "udp", "sctp")
OPEN_STATE = "open"  # "open|filtered", "filtered" and "closed" are not open (brief: "only for ports in state open")
UP_STATE = "up"
NMAP_TRUE = "true"  # how nmap writes a true boolean attribute (nmap.dtd, %attr_bool: "true" or "false")
IP_ADDRESS_TYPES = ("ipv4", "ipv6")  # in order of preference when a host has both
MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
# A MAC written inside other text (a banner, a page title, a hostname, an error): six hex pairs joined by ":" or "-"
# (mixed too: a hostile banner may mix them to slip past), or Cisco's three dotted groups of four. Twelve hex digits
# with no separator are left alone: they can't be told from a Docker container ID or a hash, and masking them would
# invent MACs.
MAC_IN_TEXT = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}"
                         r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])")
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


def mask_macs_in(text: str) -> str:
    """Every MAC inside a piece of scan text masked like mask_mac: "vsftpd AA:BB:CC:11:22:33" -> "vsftpd
    AA:BB:CC:xx:xx:xx". Every string read from the file goes through it, so no banner, title, hostname, vendor or
    error message carries a full MAC into a finding's evidence, an explanation or the UI (NFR-02)."""
    return MAC_IN_TEXT.sub(lambda match: mask_mac(_colon_form(match.group(0))), text)


def _colon_form(mac: str) -> str:
    """"aa-bb-cc-11-22-33" or "aabb.cc11.2233" -> "aa:bb:cc:11:22:33"."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac)
    return ":".join(digits[i:i + 2] for i in range(0, len(digits), 2))


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
        timed_out=element.get("timedout") == NMAP_TRUE,
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
            return address.get("addr", ""), mask_macs_in(address.get("vendor", "").strip())
    return "", ""


def _first_hostname(element: Element) -> str:
    names = (mask_macs_in(h.get("name", "").strip()) for h in element.iterfind("hostnames/hostname"))
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
    proto = element.get("protocol", "").lower()
    if proto not in PORT_PROTOCOLS:
        # The value isn't quoted back: it is hostile text, and the error reason is shown on the page.
        raise ScanReadError(f"a port has a protocol nmap never writes (only {', '.join(PORT_PROTOCOLS)})")
    service = element.find("service")
    return Port(
        port=number,
        proto=proto,
        service=_attribute(service, "name"),
        product=_attribute(service, "product"),
        version=_attribute(service, "version"),
        ssl=_attribute(service, "tunnel") == "ssl",
        title=_http_title(element),
    )


def _attribute(element: Element | None, name: str) -> str:
    """An attribute of an element that may be missing (a port with no <service>), "" when absent; MACs inside it
    masked (a hostile banner can carry one)."""
    return mask_macs_in(element.get(name, "")) if element is not None else ""


def _http_title(port_element: Element) -> str:
    """The page title from the http-title script's <elem key="title">, never its `output` text: on a redirect nmap
    writes "Did not follow redirect to .../login" there, and that is not a title."""
    for script in port_element.iterfind("script"):
        if script.get("id") == "http-title":
            title = script.find("elem[@key='title']")
            return mask_macs_in((title.text or "").strip()) if title is not None else ""
    return ""
