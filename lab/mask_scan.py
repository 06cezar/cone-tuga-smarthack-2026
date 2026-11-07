"""Mask a raw lab capture before it goes into the repo: the MAC addresses and hostnames of our own devices stay on the
scanning laptop (NFR-02), while everything the analysis reads stays the same.

- MAC: the vendor part (first 3 bytes) and the `vendor` attribute stay, because device rules read them (UNKNOWN_DEVICE
  needs "no vendor"). The device part becomes 00:00:<last byte of the IPv4 address>: a valid MAC, distinct per device,
  and the same in every scan of the lab.
- Hostname: a non-empty name becomes `lab-host-<last byte of the IPv4 address>`; an empty one stays empty, because
  "no hostname" is half of the UNKNOWN_DEVICE rule. History matches devices by IP + hostname, and both stay stable.
- After writing, the copy is analysed next to the raw file: if findings or score differ, the copy is deleted.

Usage, on the scanning laptop from the repo root:
    python lab/mask_scan.py results/scan_01.xml results/masked/scan_01.xml
"""
import argparse
import ipaddress
import re
import sys
from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # so `python lab/mask_scan.py` can use the analyser for its self-check
from conetuga.analysis import analyse_file  # noqa: E402

MAX_SCAN_BYTES = 20 * 1024 * 1024  # the analyser's own limit (conetuga/analysis/parser.py); a lab scan is far smaller
NMAP_ROOT_TAG = "nmaprun"
MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
MAC_VISIBLE_BYTES = 3  # the vendor part (OUI), as in the analyser's own masking
MASKED_MAC_FILLER = ["00", "00"]  # bytes 4 and 5 of a masked MAC; byte 6 is the device number
NEUTRAL_HOSTNAME = "lab-host-{}"  # filled with the device number
XML_HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'  # what nmap writes; ElementTree drops it


class MaskError(Exception):
    """The capture can't be masked safely. The message says why."""


def mask_scan(raw: Path, masked: Path) -> int:
    """Write the masked copy of `raw` to `masked` and check it analyses the same. Returns the number of hosts."""
    raw, masked = Path(raw), Path(masked)
    if raw.resolve() == masked.resolve():
        raise MaskError("the masked copy must not overwrite the raw capture")
    root = _read_nmap_root(raw)
    hosts = root.findall("host")
    for host in hosts:
        device = _device_number(host)
        for address in host.iterfind("address"):
            if address.get("addrtype") == "mac":
                address.set("addr", _masked_mac(address.get("addr", ""), device))
        for hostname in host.iterfind("hostnames/hostname"):
            if hostname.get("name", "").strip():
                hostname.set("name", NEUTRAL_HOSTNAME.format(device))
    masked.parent.mkdir(parents=True, exist_ok=True)
    masked.write_text(XML_HEAD + ElementTree.tostring(root, encoding="unicode") + "\n", encoding="utf-8",
                      newline="\n")
    _check_same_analysis(raw, masked)
    return len(hosts)


def _read_nmap_root(path: Path) -> Element:
    """The <nmaprun> element, after a size check and a safe parse (the file is outside text, NFR-03)."""
    try:
        size = path.stat().st_size
        if size > MAX_SCAN_BYTES:
            raise MaskError(f"{path.name} is too large to be a lab scan ({size} bytes)")
        data = path.read_bytes()
    except OSError as exc:
        raise MaskError(f"{path} can't be opened ({exc.strerror or exc})") from exc
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # broken XML, or entities (XXE) refused by defusedxml
        raise MaskError(f"{path.name} is not complete, valid XML ({exc})") from exc
    if root.tag != NMAP_ROOT_TAG:
        raise MaskError(f"{path.name} is XML but not an nmap scan (root element <{root.tag}>)")
    return root


def _device_number(host: Element) -> int:
    """The last byte of the host's IPv4 address: stable across scans of the same lab, unique within the subnet."""
    for address in host.iterfind("address"):
        if address.get("addrtype") == "ipv4":
            try:
                return ipaddress.IPv4Address(address.get("addr", "")).packed[-1]
            except ipaddress.AddressValueError as exc:
                raise MaskError(f"a host has an IPv4 address that isn't one ({address.get('addr')!r})") from exc
    raise MaskError("a host has no IPv4 address, so it can't get a stable masked MAC and name")


def _masked_mac(mac: str, device: int) -> str:
    if not MAC_PATTERN.match(mac):
        raise MaskError(f"a MAC address is not in the usual form ({mac!r})")
    return ":".join(mac.upper().split(":")[:MAC_VISIBLE_BYTES] + MASKED_MAC_FILLER + [f"{device:02X}"])


def _check_same_analysis(raw: Path, masked: Path) -> None:
    """The copy must give exactly the raw file's findings and score; otherwise it is deleted (C asked for this check)."""
    before, after = analyse_file(raw), analyse_file(masked)
    if before.error or after.error or _finding_rows(before) != _finding_rows(after) or before.score != after.score:
        masked.unlink(missing_ok=True)
        raise MaskError(f"the masked copy doesn't analyse like {raw.name} "
                        f"(raw: {before.score} {before.error}; masked: {after.score} {after.error}); nothing written")


def _finding_rows(result) -> list[tuple]:
    """The findings without the file name, which differs between the raw file and its copy."""
    return [(f.ip, f.port, f.code, f.severity) for f in result.findings]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mask MACs and hostnames in a lab capture before it is committed.")
    parser.add_argument("raw", type=Path, help="the raw capture, e.g. results/scan_01.xml (stays on this laptop)")
    parser.add_argument("masked", type=Path, help="where to write the masked copy, e.g. results/masked/scan_01.xml")
    args = parser.parse_args(argv)
    try:
        count = mask_scan(args.raw, args.masked)
    except MaskError as exc:
        print(f"Not masked: {exc}", file=sys.stderr)
        return 1
    print(f"Masked {count} host(s): {args.raw} -> {args.masked} (same findings and score as the raw file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
