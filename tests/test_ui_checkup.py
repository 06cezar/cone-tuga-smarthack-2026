"""Acasă in Simple mode as a checkup (ui/checkup.py): the things to fix, the biggest gain first, only the next one
open; a tick raises the estimated score from A's standard_score; every device is a tile with its details (FR-03).
Advanced mode keeps Cone's device list."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from ui.checkup import done_key, tasks_of
from ui.view import devices_by_risk

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def run(scan: str = "V2_smart_home.xml"):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value(scan).run()
    assert not app.exception
    return app


def tasks(app):
    return [e for e in app.expander if e.label[:1].isdigit() or e.label.startswith("✅ ")]


def test_the_biggest_gain_comes_first():
    result = analyse_file(SCANS / "V2_smart_home.xml")
    order = [finding.points for _device, finding in tasks_of(devices_by_risk(result, "ro"))]
    assert order == sorted(order, reverse=True) and order[0] == 20


def test_only_the_next_task_is_open():
    app = run()
    assert [t.proto.expanded for t in tasks(app)] == [True] + [False] * (len(tasks(app)) - 1)
    assert tasks(app)[0].label.startswith("1. 📷 ") and tasks(app)[0].label.endswith("+20 puncte")


def test_a_tick_raises_the_estimated_score_and_opens_the_next_task():
    app = run()
    assert "0 din 5 făcute · scor estimat: 40/100" in app.get("progress")[0].proto.text
    app.checkbox[0].check().run()
    assert "1 din 5 făcute · scor estimat: 60/100" in app.get("progress")[0].proto.text
    assert tasks(app)[0].label.startswith("✅ 1.") and tasks(app)[1].proto.expanded


def test_ticking_everything_says_to_scan_again():
    app = run()
    for i in range(len(app.checkbox)):
        app.checkbox[i].check()
    app.run()
    assert any("Scanează din nou ca să vezi scorul adevărat" in s.value for s in app.success)
    assert "5 din 5 făcute · scor estimat: 100/100" in app.get("progress")[0].proto.text


def test_every_device_is_a_tile_with_its_details():
    app = run()
    text = "\n".join(m.value for m in app.markdown)
    for host in analyse_file(SCANS / "V2_smart_home.xml").hosts:
        assert f"IP {host.ip} " in text
        assert not host.mac_masked or host.mac_masked.replace(":", "\\:") in text


def test_a_clean_scan_has_nothing_to_fix():
    app = run("V6b_after.xml")
    assert any("Nu ai nimic de reparat" in s.value for s in app.success)


def test_advanced_mode_keeps_the_device_list():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    app.toggle[0].set_value(True).run()
    assert not app.get("progress") and all("puncte" in e.label for e in app.expander)


def test_the_task_keys_differ_between_findings():
    result = analyse_file(SCANS / "V3_small_office.xml")
    keys = [done_key(finding) for finding in result.findings]
    assert len(set(keys)) == len(keys)
