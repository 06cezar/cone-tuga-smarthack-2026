"""Our own hotspot lab as test fixtures (NFR-10): the before/after captures show the score going up, the fixed findings
gone and nothing new. This backs live check 6 ("a before/after from your own hotspot lab with the score improving")
and the brief's lab rules (5+ catalog codes, 2+ findings fixed and rescanned).

The captures in lab/scans/ were made on RSH-ConeTuga on 2026-11-07 and masked with lab/mask_scan.py; the numbers below
are the ones measured there (lab/README.md)."""
import re
from pathlib import Path

import defusedxml.ElementTree as SafeET
import pytest

from conetuga.analysis import analyse_file
from conetuga.history import diff

LAB_SCANS = Path(__file__).resolve().parents[1] / "lab" / "scans"
CAPTURES = ("scan_01.xml", "scan_02.xml", "scan_03.xml")  # before, after fix 1, after fix 2
TARGETS_LAPTOP = "172.20.10.2"
MEASURED_SCORES = {"scan_01.xml": 0, "scan_02.xml": 50, "scan_03.xml": 70}
FIXED = {  # what each fix switched off on the targets laptop
    ("scan_01.xml", "scan_02.xml"): {  # fix 1: the fake telnet and FTP stopped
        (TARGETS_LAPTOP, 21, "FTP_CLEARTEXT"),
        (TARGETS_LAPTOP, 21, "OUTDATED_SERVICE"),
        (TARGETS_LAPTOP, 2323, "TELNET_OPEN"),
    },
    ("scan_02.xml", "scan_03.xml"): {  # fix 2: the Redis container stopped
        (TARGETS_LAPTOP, 6380, "DB_EXPOSED"),
    },
}
BRIEF_MIN_CODES = 5  # brief, page 5: "At least 5 different finding types from the official catalog"
BRIEF_MIN_FIXED = 2  # brief, page 5: "Fix at least two findings in your lab, rescan, and keep both files"
MASKED_MAC = re.compile(r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:00:00:[0-9A-F]{2}$")
NEUTRAL_HOSTNAME = re.compile(r"^lab-host-\d+$")


def result(name: str):
    return analyse_file(LAB_SCANS / name)


def finding_keys(name: str) -> set[tuple]:
    return {(f.ip, f.port, f.code) for f in result(name).findings}


@pytest.mark.parametrize("name", CAPTURES)
def test_lab_capture_is_read_with_its_measured_score(name):
    lab = result(name)
    assert lab.error == ""
    assert lab.score == MEASURED_SCORES[name]


def test_lab_score_goes_up_with_every_fix():
    scores = [result(name).score for name in CAPTURES]
    assert scores == sorted(scores) and scores[0] < scores[-1]


@pytest.mark.parametrize(("before", "after"), FIXED.keys())
def test_each_fix_removes_exactly_what_was_switched_off_and_adds_nothing(before, after):
    assert finding_keys(before) - finding_keys(after) == FIXED[before, after]
    assert finding_keys(after) - finding_keys(before) == set()


@pytest.mark.parametrize(("before", "after"), FIXED.keys())
def test_history_shows_the_fixes_as_resolved_with_no_change_alert(before, after):
    """What the UI's history shows for our lab, through D's `diff` (contract "diff")."""
    change = diff(result(before), result(after))
    assert {(f.ip, f.port, f.code) for f in change.resolved_findings} == FIXED[before, after]
    assert (change.score_before, change.score_after) == (MEASURED_SCORES[before], MEASURED_SCORES[after])
    assert change.new_devices == change.removed_devices == change.opened_ports == []


def test_lab_meets_the_brief_variety_and_fix_counts():
    assert len({code for _, _, code in finding_keys(CAPTURES[0])}) >= BRIEF_MIN_CODES
    assert len(finding_keys(CAPTURES[0]) - finding_keys(CAPTURES[-1])) >= BRIEF_MIN_FIXED


@pytest.mark.parametrize("name", CAPTURES)
def test_lab_capture_holds_only_masked_macs_and_neutral_hostnames(name):
    """NFR-02: what went into the repo is the masked copy, never the raw capture."""
    root = SafeET.parse(LAB_SCANS / name).getroot()
    assert root.find("hosthint") is None
    macs = [a.get("addr") for a in root.iter("address") if a.get("addrtype") == "mac"]
    assert macs and all(MASKED_MAC.match(mac) for mac in macs)
    names = [h.get("name") for h in root.iter("hostname")]
    assert all(NEUTRAL_HOSTNAME.match(name) for name in names)
    assert all(s.get("hostname") is None for s in root.iter("service"))
