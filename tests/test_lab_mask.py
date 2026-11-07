"""A masked lab capture hides our MACs and hostnames but gives exactly the same findings and score (C asked for this,
lab/COMMS.md 13:58). It is checked on the Validation Set, which has MACs and hostnames, so it runs in CI without our
raw captures (those never leave the scanning laptop)."""
import importlib.util
import re
from pathlib import Path

import defusedxml.ElementTree as SafeET
import pytest

from conetuga.analysis import analyse_file

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
BROKEN = SCANS / "V7_broken.xml"
READABLE = sorted(p for p in SCANS.glob("*.xml") if p != BROKEN)

_spec = importlib.util.spec_from_file_location("mask_scan", ROOT / "lab" / "mask_scan.py")
mask_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mask_scan)


def masked_copy(raw: Path, folder: Path) -> Path:
    masked = folder / raw.name
    mask_scan.mask_scan(raw, masked)
    return masked


def hosts_of(path: Path) -> dict[str, tuple[str, str, list[str]]]:
    """IP -> (MAC, vendor, hostnames), read straight from the XML."""
    hosts = {}
    for host in SafeET.parse(path).getroot().iter("host"):
        addresses = {a.get("addrtype"): a for a in host.iterfind("address")}
        mac = addresses.get("mac")
        hosts[addresses["ipv4"].get("addr")] = (
            "" if mac is None else mac.get("addr"),
            "" if mac is None else mac.get("vendor", ""),
            [h.get("name") for h in host.iterfind("hostnames/hostname")],
        )
    return hosts


@pytest.mark.parametrize("raw", READABLE, ids=lambda p: p.name)
def test_masked_copy_gives_the_same_findings_and_score(raw, tmp_path):
    before, after = analyse_file(raw), analyse_file(masked_copy(raw, tmp_path))
    assert after.findings == before.findings
    assert after.score == before.score


@pytest.mark.parametrize("raw", READABLE, ids=lambda p: p.name)
def test_masked_copy_keeps_vendor_and_hides_device_part_of_mac_and_hostnames(raw, tmp_path):
    before, after = hosts_of(raw), hosts_of(masked_copy(raw, tmp_path))
    assert after.keys() == before.keys()
    for ip, (mac, vendor, names) in before.items():
        masked_mac, masked_vendor, masked_names = after[ip]
        last_byte = f"{int(ip.rsplit('.', 1)[1]):02X}"
        assert masked_mac == mac[:8] + ":00:00:" + last_byte
        assert masked_vendor == vendor
        assert masked_names == [f"lab-host-{int(ip.rsplit('.', 1)[1])}" for _ in names]


def test_same_device_keeps_the_same_masked_mac_and_name_across_scans(tmp_path):
    """V6a and V6b show the same devices with different MACs; history matches by IP + hostname, so both must agree."""
    before = hosts_of(masked_copy(SCANS / "V6a_before.xml", tmp_path))
    after = hosts_of(masked_copy(SCANS / "V6b_after.xml", tmp_path))
    assert before == after


WINDOWS_NAME = "DESKTOP-LAB01"  # a made-up Windows computer name


def with_windows_details(text: str) -> str:
    """V3's NAS as nmap shows a Windows machine on 445: the computer name in the service's hostname and extrainfo, a raw
    fingerprint, and an nbstat host script with the name, a user and the full MAC."""
    service = f'hostname="{WINDOWS_NAME}" extrainfo="workgroup: {WINDOWS_NAME}" servicefp="SF:r({WINDOWS_NAME})" '
    text, services = re.subn(r'(portid="445">.*?<service )', rf"\g<1>{service}", text, count=1, flags=re.S)
    nbstat = (f'<hostscript><script id="nbstat" output="NetBIOS name: {WINDOWS_NAME}, NetBIOS user: ana, '
              'NetBIOS MAC: 00:11:32:4f:6e:ac (Synology)"/></hostscript>')
    text, scripts = re.subn(r'(portid="445">.*?</port>\s*</ports>)', rf"\g<1>{nbstat}", text, count=1, flags=re.S)
    assert services == scripts == 1, "V3 no longer has the NAS on 445 this test edits"
    return text


def test_masked_copy_drops_names_nmap_writes_outside_hostnames(tmp_path):
    """A's and D's review of PR #12: SMB on 445 put the Windows computer name in <service hostname=...>."""
    raw = tmp_path / "raw" / "V3_small_office.xml"
    raw.parent.mkdir()
    raw.write_text(with_windows_details((SCANS / raw.name).read_text(encoding="utf-8")), encoding="utf-8")
    masked = masked_copy(raw, tmp_path)
    text = masked.read_text(encoding="utf-8").upper()
    assert WINDOWS_NAME not in text
    assert "00:11:32:4F:6E:AC" not in text
    assert "NBSTAT" not in text
    assert analyse_file(masked).findings == analyse_file(SCANS / raw.name).findings


def test_copy_that_still_names_a_device_is_refused_and_nothing_is_written(tmp_path):
    """The last check (D's request): an original hostname left anywhere, here in a page title, deletes the copy."""
    raw = tmp_path / "raw" / "V1_home_basic.xml"
    raw.parent.mkdir()
    text = (SCANS / raw.name).read_text(encoding="utf-8")
    raw.write_text(text.replace('<elem key="title">Router Login', '<elem key="title">ROUTER.lan Login'),
                   encoding="utf-8")
    with pytest.raises(mask_scan.MaskError, match="still contains"):
        mask_scan.mask_scan(raw, tmp_path / raw.name)
    assert not (tmp_path / raw.name).exists()


def test_broken_capture_is_refused_and_nothing_is_written(tmp_path):
    with pytest.raises(mask_scan.MaskError):
        mask_scan.mask_scan(BROKEN, tmp_path / BROKEN.name)
    assert not (tmp_path / BROKEN.name).exists()


def test_masking_never_overwrites_the_raw_capture(tmp_path):
    raw = tmp_path / "scan.xml"
    raw.write_bytes((SCANS / "V1_home_basic.xml").read_bytes())
    with pytest.raises(mask_scan.MaskError):
        mask_scan.mask_scan(raw, raw)
