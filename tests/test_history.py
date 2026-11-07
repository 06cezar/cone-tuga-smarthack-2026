"""History (FR-10, FR-13, NFR-02): the before/after diff on the Validation Set, device matching by IP + hostname,
and the local store, which keeps each scan once and deletes everything in one action."""
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from conetuga.history import delete_history, diff, load_history, save_scan

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    """Every test gets its own empty history folder, never the real .history/."""
    folder = tmp_path / "history"
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(folder))
    return folder


def scan(name: str):
    return analyse_file(SCANS / name)


def test_contract_diff():
    change = diff(scan("V6a_before.xml"), scan("V6b_after.xml"))
    assert sorted((f.ip, f.port, f.code) for f in change.resolved_findings) == [
        ("192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT"), ("192.168.1.1", 1900, "UPNP_EXPOSED"),
        ("192.168.1.30", 23, "TELNET_OPEN")]
    assert (change.score_before, change.score_after) == (60, 100)
    assert change.new_devices == [] and change.removed_devices == []
    assert [(h.ip, p.port, p.proto) for h, p in change.opened_ports] == [("192.168.1.1", 443, "tcp")]
    assert sorted((h.ip, p.port) for h, p in change.closed_ports) == [
        ("192.168.1.1", 80), ("192.168.1.1", 1900), ("192.168.1.30", 23)]


def test_same_scan_has_no_changes():
    change = diff(scan("V2_smart_home.xml"), scan("V2_smart_home.xml"))
    assert (change.new_devices, change.removed_devices, change.opened_ports, change.closed_ports,
            change.resolved_findings) == ([], [], [], [], [])


def test_a_new_mac_alone_is_not_a_new_device():
    before = scan("V6a_before.xml")
    after = replace(before, hosts=[replace(h, mac_masked="AA:BB:CC:xx:xx:xx") for h in before.hosts])
    change = diff(before, after)
    assert change.new_devices == [] and change.removed_devices == []


def test_a_new_hostname_on_the_same_ip_is_a_different_device():
    before = scan("V6a_before.xml")
    after = replace(before, hosts=[replace(h, hostname="intruder") if h.ip == "192.168.1.20" else h
                                   for h in before.hosts])
    change = diff(before, after)
    assert [h.hostname for h in change.new_devices] == ["intruder"]
    assert [h.hostname for h in change.removed_devices] == ["laptop-ioana"]


def test_a_new_device_and_its_findings_show_up():
    change = diff(scan("V6b_after.xml"), scan("V6a_before.xml"))  # reversed: the fixed problems come back
    assert change.resolved_findings == []
    assert sorted((h.ip, p.port) for h, p in change.opened_ports) == [
        ("192.168.1.1", 80), ("192.168.1.1", 1900), ("192.168.1.30", 23)]


def test_a_broken_file_cannot_be_compared():
    with pytest.raises(ValueError):
        diff(scan("V7_broken.xml"), scan("V6b_after.xml"))


def test_saved_scans_come_back_oldest_first():
    for minute, name in ((1, "V6a_before.xml"), (2, "V6b_after.xml")):
        assert save_scan(scan(name), (SCANS / name).read_bytes(), now=datetime(2026, 11, 7, 16, minute))
    records = load_history()
    assert [r.file for r in records] == ["V6a_before.xml", "V6b_after.xml"]
    assert records[0].result == scan("V6a_before.xml")  # the stored result is exactly the analysis


def test_the_same_file_is_stored_once():
    content = (SCANS / "V1_home_basic.xml").read_bytes()
    assert save_scan(scan("V1_home_basic.xml"), content) is True
    assert save_scan(scan("V1_home_basic.xml"), content) is False
    assert len(load_history()) == 1


def test_a_broken_file_is_not_stored():
    assert save_scan(scan("V7_broken.xml"), (SCANS / "V7_broken.xml").read_bytes()) is False
    assert load_history() == []


def test_stored_records_hold_no_raw_mac(history_in_tmp):
    name = "V6a_before.xml"
    save_scan(scan(name), (SCANS / name).read_bytes())
    text = "".join(p.read_text(encoding="utf-8") for p in history_in_tmp.iterdir())
    assert "xx:xx:xx" in text
    assert "50:C7:BF:88" not in text.upper()  # V6a's router MAC, beyond its vendor part


def test_delete_my_history_leaves_nothing(history_in_tmp):
    save_scan(scan("V1_home_basic.xml"), (SCANS / "V1_home_basic.xml").read_bytes())
    delete_history()
    assert not history_in_tmp.exists()
    assert load_history() == []


def test_a_damaged_record_is_skipped(history_in_tmp):
    save_scan(scan("V1_home_basic.xml"), (SCANS / "V1_home_basic.xml").read_bytes())
    (history_in_tmp / "broken.json").write_text("{not json", encoding="utf-8")
    assert [r.file for r in load_history()] == ["V1_home_basic.xml"]


def fake_live_scan(monkeypatch, scan_file: Path) -> None:
    """`scan --confirm` on our hotspot with a fake nmap that copies `scan_file` to where nmap writes its XML."""
    import shutil

    import conetuga.guard.scan as scan
    from conetuga.guard import Network

    monkeypatch.setattr(scan, "detect_network",
                        lambda: Network("wlp0s20f3", "172.20.10.13", "172.20.10.0/28", "172.20.10.1"))
    monkeypatch.setattr(scan, "wifi_ssid", lambda interface: "RSH-ConeTuga")
    monkeypatch.setattr(scan, "_find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(scan, "top_tcp_ports", lambda nmap: [80])
    monkeypatch.setattr(scan, "_is_admin", lambda: True)

    def fake_nmap(command):
        shutil.copyfile(scan_file, command[command.index("-oX") + 1])
        return 0

    monkeypatch.setattr(scan, "_run_nmap", fake_nmap)


def test_live_scans_reach_the_history_and_compare(monkeypatch, tmp_path, capsys):
    import conetuga.__main__ as cli

    monkeypatch.chdir(tmp_path)  # the raw XML goes to results/ here, not into the repo
    for name in ("V6a_before.xml", "V6b_after.xml"):
        fake_live_scan(monkeypatch, SCANS / name)
        assert cli.main(["scan", "--confirm"]) == 0
    assert "saved to the history" in capsys.readouterr().out
    records = load_history()
    assert [r.result.score for r in records] == [60, 100]
    change = diff(records[0].result, records[1].result)
    assert len(change.resolved_findings) == 3


def test_a_live_scan_stores_masked_macs_only(monkeypatch, tmp_path, history_in_tmp):
    import conetuga.__main__ as cli

    monkeypatch.chdir(tmp_path)
    fake_live_scan(monkeypatch, SCANS / "V6a_before.xml")
    cli.main(["scan", "--confirm"])
    # Read as bytes: the history folder also holds SQLite files (the findings log, the statistics), and the check
    # covers them too.
    stored = b"".join(p.read_bytes() for p in history_in_tmp.iterdir() if p.is_file())
    assert b"xx:xx:xx" in stored and b"50:C7:BF:88" not in stored.upper()


def test_scans_saved_in_the_same_second_keep_their_order():
    same_second = datetime(2026, 11, 7, 20, 40, 0)
    for name in ("V6b_after.xml", "V6a_before.xml", "V1_home_basic.xml"):  # not in name order on purpose
        save_scan(scan(name), (SCANS / name).read_bytes(), now=same_second)
    assert [r.file for r in load_history()] == ["V6b_after.xml", "V6a_before.xml", "V1_home_basic.xml"]
