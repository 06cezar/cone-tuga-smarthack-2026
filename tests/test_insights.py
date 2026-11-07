"""The opt-in statistics store (conetuga/insights, contract "insights"): the contract's example, what it keeps on disk
(only code counts and the opt-in, NFR-02), reading that never creates anything, and every way a store can fail, with
the answers on the safe side. Every test has its own history folder (tests/conftest.py)."""
import os
import re
import sqlite3
import stat
from dataclasses import replace
from pathlib import Path

import pytest

import conetuga.insights.store as store
from conetuga.analysis import analyse_file
from conetuga.history import delete_history, digest_of
from conetuga.insights import (STATUS_OFF, STATUS_ON, STATUS_UNAVAILABLE, is_enabled, record, set_enabled, status,
                               top_codes)

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
LAB = Path(__file__).resolve().parents[1] / "lab" / "scans"
READABLE_SCANS = sorted(p for p in [*SCANS.glob("V[1-6]*.xml"), *LAB.glob("*.xml")])


def scan(path: Path):
    """(result, scan_id) as the UI has them: analyse_file's result and the history's digest of the file."""
    return analyse_file(path), digest_of(path.read_bytes())


def test_contract_insights():
    """The example in specs/contracts.md, step by step."""
    seen: set[str] = set()
    assert set_enabled(True) is True
    assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is True
    assert record(*scan(SCANS / "V4_legacy.xml"), seen) is True
    assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is False
    assert top_codes(2) == [("HTTP_ADMIN_CLEARTEXT", 3), ("CAMERA_STREAM_EXPOSED", 1)]
    assert status() == STATUS_ON
    delete_history()
    seen.clear()
    assert status() == STATUS_OFF and top_codes(2) == []
    assert set_enabled(True) is True
    assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is True


# --- Opt-in ---

def test_statistics_are_off_until_the_person_turns_them_on():
    assert (status(), is_enabled()) == (STATUS_OFF, False)


def test_nothing_is_counted_or_written_while_off():
    seen: set[str] = set()
    assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is False
    assert seen == set() and not store.store_path().exists()


def test_turning_statistics_off_stops_counting():
    seen: set[str] = set()
    set_enabled(True)
    record(*scan(SCANS / "V1_home_basic.xml"), seen)
    assert set_enabled(False) is True and status() == STATUS_OFF
    assert record(*scan(SCANS / "V4_legacy.xml"), seen) is False
    assert top_codes(5) == [("HTTP_ADMIN_CLEARTEXT", 1)]


# --- Counting ---

def test_a_scan_counts_once_per_session():
    seen: set[str] = set()
    set_enabled(True)
    result, scan_id = scan(SCANS / "V4_legacy.xml")
    assert [record(result, scan_id, seen) for _ in range(3)] == [True, False, False]
    assert scan_id in seen and dict(top_codes(10))["TELNET_OPEN"] == 1


def test_a_new_session_counts_the_same_scan_again():
    """`seen` lives only as long as the session (the contract's "across sessions")."""
    set_enabled(True)
    for _ in range(2):
        record(*scan(SCANS / "V4_legacy.xml"), set())
    assert dict(top_codes(10))["TELNET_OPEN"] == 2


def test_an_unreadable_scan_is_not_counted():
    seen: set[str] = set()
    set_enabled(True)
    assert record(*scan(SCANS / "V7_broken.xml"), seen) is False
    assert seen == set() and top_codes(5) == []


def test_a_scan_without_findings_counts_and_adds_nothing():
    seen: set[str] = set()
    set_enabled(True)
    result, scan_id = scan(SCANS / "V6b_after.xml")
    assert record(result, scan_id, seen) is True and scan_id in seen and top_codes(5) == []


def test_only_catalog_codes_are_counted():
    seen: set[str] = set()
    set_enabled(True)
    result, scan_id = scan(SCANS / "V1_home_basic.xml")
    odd = replace(result, findings=[*result.findings, replace(result.findings[0], code="NOT_A_CATALOG_CODE")])
    record(odd, scan_id, seen)
    assert top_codes(5) == [("HTTP_ADMIN_CLEARTEXT", 1)]


def test_top_codes_are_most_found_first_ties_by_code_and_at_most_n():
    seen: set[str] = set()
    set_enabled(True)
    for path in READABLE_SCANS:
        record(*scan(path), seen)
    top = top_codes(4)
    assert len(top) == 4
    assert top == sorted(top, key=lambda row: (-row[1], row[0]))
    assert top_codes(100) == sorted(top_codes(100), key=lambda row: (-row[1], row[0]))


def test_top_codes_needs_n_of_at_least_one():
    with pytest.raises(ValueError):
        top_codes(0)


# --- What is on disk (NFR-02) ---

def test_the_store_holds_only_code_counts_and_the_opt_in():
    seen: set[str] = set()
    set_enabled(True)
    for path in READABLE_SCANS:
        record(*scan(path), seen)
    with sqlite3.connect(store.store_path()) as connection:
        tables = {name: [column[1] for column in connection.execute(f"PRAGMA table_info({name})")]
                  for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        settings = connection.execute("SELECT key, value FROM settings").fetchall()
    assert tables == {"settings": ["key", "value"], "counts": ["code", "count"]}
    assert settings == [("enabled", "1")]


def test_no_scan_detail_reaches_the_store_file():
    """Every IP, MAC (raw, masked, with ":" or "-" or none), hostname, vendor, file name and scan digest of the scans
    recorded is looked for in the raw bytes of the store file: none is there."""
    seen: set[str] = set()
    set_enabled(True)
    secrets: set[str] = set()
    for path in READABLE_SCANS:
        result, scan_id = scan(path)
        record(result, scan_id, seen)
        raw = path.read_text(encoding="utf-8")
        macs = re.findall(r'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', raw)
        secrets |= {scan_id, path.name, path.stem, *re.findall(r'addr="([0-9.]+)" addrtype="ipv4"', raw)}
        secrets |= {form for mac in macs for form in (mac, mac.replace(":", "-"), mac.replace(":", ""))}
        secrets |= {h.mac_masked for h in result.hosts if h.mac_masked}
        secrets |= {h.hostname for h in result.hosts if h.hostname} | {h.vendor for h in result.hosts if h.vendor}
    content = store.store_path().read_bytes()
    found = sorted(s for s in secrets if s.encode("utf-8") in content)
    assert len(secrets) > 50 and found == []


# --- Reading never creates anything ---

def test_reading_never_creates_the_folder_or_the_file():
    assert (status(), is_enabled(), top_codes(3)) == (STATUS_OFF, False, [])
    assert not store.store_path().parent.exists()


def test_reading_a_store_that_vanished_after_the_check_creates_nothing():
    """The file can disappear between `exists()` and opening it ("Șterge istoricul meu" in another tab): reading
    opens it read-only, so SQLite raises instead of creating an empty file."""
    missing = store.store_path()
    missing.parent.mkdir(parents=True)
    with pytest.raises(sqlite3.OperationalError):
        store._open_for_reading(missing)
    assert not missing.exists()


def test_deleting_the_history_deletes_the_statistics():
    seen: set[str] = set()
    set_enabled(True)
    record(*scan(SCANS / "V2_smart_home.xml"), seen)
    delete_history()
    assert not store.store_path().exists() and (status(), top_codes(5)) == (STATUS_OFF, [])


# --- A store that can't be read or written: never overwritten, never raises, answers on the safe side ---

def test_a_corrupt_store_is_unavailable_and_never_overwritten():
    path = store.store_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"this is not an SQLite database, and it must stay exactly as it is")
    before = path.read_bytes()
    seen: set[str] = set()
    assert (status(), is_enabled(), top_codes(3)) == (STATUS_UNAVAILABLE, False, [])
    assert set_enabled(True) is False
    assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is False and seen == set()
    assert path.read_bytes() == before


def test_a_folder_that_cant_be_created_makes_writes_fail_while_status_says_off(tmp_path, monkeypatch):
    """A file where the history folder should be (works the same on Windows and Linux): reading has nothing to read
    ("off"), but the write fails. So the UI must look at set_enabled's answer, not at status() before it."""
    blocker = tmp_path / "a-file-not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(blocker / "history"))
    assert status() == STATUS_OFF
    assert set_enabled(True) is False
    assert status() == STATUS_OFF


def test_a_read_only_store_file_makes_writes_fail_while_status_says_on():
    seen: set[str] = set()
    set_enabled(True)
    path = store.store_path()
    os.chmod(path, stat.S_IREAD)
    try:
        assert status() == STATUS_ON
        assert record(*scan(SCANS / "V2_smart_home.xml"), seen) is False and seen == set()
        assert set_enabled(False) is False
        assert status() == STATUS_ON and top_codes(3) == []
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_a_full_disk_makes_writes_fail_and_the_scan_can_be_counted_later(monkeypatch):
    """SQLite's "database or disk is full" on a write: False, nothing in `seen`, so once there is room again the same
    scan in the same session still counts."""
    seen: set[str] = set()
    set_enabled(True)
    real_open = store._open_for_writing

    def disk_full():
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "_open_for_writing", disk_full)
    result, scan_id = scan(SCANS / "V2_smart_home.xml")
    assert status() == STATUS_ON
    assert record(result, scan_id, seen) is False and seen == set()
    assert set_enabled(False) is False
    monkeypatch.setattr(store, "_open_for_writing", real_open)
    assert record(result, scan_id, seen) is True and top_codes(1) == [("HTTP_ADMIN_CLEARTEXT", 2)]
