"""Cone's technical audit (ui/summary.py), after the dark mock-up: one row per device, the riskiest first, with its
address, masked MAC, ports, services, findings by severity and references; a search box over every column; every
piece of scan text escaped (NFR-03)."""
import dataclasses
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from ui.summary import audit_rows, matches, short_reference, table_html
from ui.view import devices_by_risk

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds
HOSTILE = "<img src=x onerror=alert(1)>"


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def devices(scan: str = "V2_smart_home.xml"):
    return devices_by_risk(analyse_file(SCANS / scan), "ro")


def run(advanced: bool):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    if advanced:
        app.toggle[0].set_value(True).run()
    assert not app.exception
    return app


def test_one_row_per_device_the_riskiest_first_with_its_details():
    rows = audit_rows(devices(), "ro")
    assert [row["ip"] for row in rows][0] == "192.168.1.40" and len(rows) == 4
    camera = rows[0]
    assert camera["mac"].endswith("xx:xx:xx") and "554/tcp" in camera["ports"] and "rtsp" in camera["services"]
    assert ("high", "CAMERA_STREAM_EXPOSED", "Risc mare") in camera["findings"]
    assert any(reference.startswith("OWASP IoT") for reference in camera["references"])


def test_references_are_short_enough_for_a_chip():
    assert short_reference("CIS Controls v8.1 4.8") == "CIS v8.1 4.8"


def test_the_search_looks_in_every_column():
    rows = audit_rows(devices(), "ro")
    assert [row["ip"] for row in rows if matches(row, "mqtt")] == ["192.168.1.41"]
    assert len([row for row in rows if matches(row, "")]) == len(rows)
    assert not [row for row in rows if matches(row, "nothing-like-this")]


def test_scan_text_never_becomes_html():
    hostile = dataclasses.replace(devices()[0], name=HOSTILE)
    page = table_html(audit_rows([hostile], "en"), "en")
    assert HOSTILE not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


def test_advanced_acasa_shows_the_audit_and_simple_mode_does_not():
    advanced = "\n".join(m.value for m in run(advanced=True).markdown)
    assert "Audit tehnic al dispozitivelor" in advanced and 'class="ct-table"' in advanced
    assert "**4** dispozitive scanate · **5** probleme · scor **40/100**" in advanced
    simple = "\n".join(m.value for m in run(advanced=False).markdown)
    assert "Audit tehnic al dispozitivelor" not in simple
