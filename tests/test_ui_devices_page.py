"""The Dispozitive page (FE-D3): every device of the scan picked on Acasă, riskiest first, filters by status and type,
a choice of order, Tuga's words in Simple mode and Cone's evidence in Advanced mode, "Neverificat" for a device nmap
gave up on, and scan text escaped. The page is run on its own with the scan Acasă would remember (ui/state.py)."""
from pathlib import Path

import pytest

from nmap_xml import host, port, write_scan

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
V1 = SCANS / "V1_home_basic.xml"
V2 = SCANS / "V2_smart_home.xml"  # router.lan .1, ipcam .40 (the riskiest), smarthub .41, living-room-tv .50
APP = str(ROOT / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def show(scan: Path | None, language: str = "Română", advanced: bool = False) -> AppTest:
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\n")
    if scan is not None:
        script += ("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
                   f"from ui.state import remember_scan\nremember_scan(analyse_file(Path({str(scan)!r})))\n")
    script += "from ui.pages import devices\ndevices.render()"
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def labels(app: AppTest) -> list[str]:
    return [section.label for section in app.expander]


def text_of(app: AppTest) -> str:
    parts = [*app.title, *app.markdown, *app.info, *app.warning, *app.error]
    return "\n".join(str(part.value) for part in parts) + "\n" + "\n".join(labels(app))


@pytest.mark.parametrize("language, words", [("Română", "pagina Acasă"), ("English", "the Home page")])
def test_without_a_scan_the_page_says_where_to_pick_one(language, words):
    app = show(None, language)
    assert words in app.info[0].value
    assert not app.expander


def test_every_device_is_listed_riskiest_first():
    app = show(V2)
    names = labels(app)
    assert len(names) == 4
    assert "ipcam" in names[0] and "⛔" in names[0]  # the camera: high risk, with an icon and words (NFR-08)
    assert "Afișate: 4 din 4 dispozitive." in text_of(app)


def test_simple_mode_tuga_explains_with_no_evidence():
    text = text_of(show(V2))
    assert "🐢 **Tuga:**" in text and "🐇" not in text
    assert "Ce a văzut nmap" not in text


def test_advanced_mode_cone_shows_the_evidence_and_the_rule():
    text = text_of(show(V2, "English", advanced=True))
    assert "🐇 **Cone:**" in text and "🐢" not in text
    assert "What nmap saw (the evidence)" in text
    assert "554/tcp" in text and "`CAMERA_STREAM_EXPOSED`" in text


def test_the_status_filter_keeps_only_the_matching_devices():
    app = show(V2)
    app.multiselect(key="devices_status_filter").set_value(["high"]).run()
    assert not app.exception
    names = labels(app)
    assert len(names) == 1 and "ipcam" in names[0]
    assert "Afișate: 1 din 4 dispozitive." in text_of(app)


def test_the_type_filter_keeps_only_that_type():
    app = show(V2)
    app.multiselect(key="devices_type_filter").set_value(["router"]).run()
    assert not app.exception
    names = labels(app)
    assert len(names) == 1 and "router\\.lan" in names[0]  # escaped like every hostname


def test_filters_that_match_nothing_say_so():
    app = show(V2)
    app.multiselect(key="devices_status_filter").set_value(["low"]).run()
    assert not app.expander
    assert "Niciun dispozitiv nu se potrivește" in text_of(app)


def test_sorting_by_address_puts_the_router_first():
    app = show(V2)
    app.selectbox(key="devices_sort").set_value("ip").run()
    assert not app.exception
    assert "192.168.1.1 " in labels(app)[0]


def test_a_device_nmap_gave_up_on_is_not_checked_rather_than_safe(tmp_path):
    """No open port and no finding, because nmap stopped early (<host timedout="true">): "❔ Neverificat", not "✅"."""
    scan = write_scan(tmp_path, host("10.0.0.7", hostname="slow-box"))
    scan.write_text(scan.read_text(encoding="utf-8").replace("<host>", '<host timedout="true">', 1), encoding="utf-8")
    app = show(scan)
    assert "❔" in labels(app)[0] and "✅" not in labels(app)[0]
    assert any("Neverificat" in warning.value for warning in app.warning)


def test_a_timed_out_device_with_findings_shows_them_and_the_warning(tmp_path):
    """V1's router marked timed out still has the finding nmap wrote: at least that bad, and "not checked" said."""
    scan = tmp_path / "V1_timed_out.xml"
    scan.write_text(V1.read_text(encoding="utf-8").replace("<host ", '<host timedout="true" ', 1), encoding="utf-8")
    app = show(scan)
    assert "⚠️" in labels(app)[0]  # HTTP_ADMIN_CLEARTEXT, medium
    assert any("Neverificat" in warning.value for warning in app.warning)


def test_a_broken_scan_shows_the_error_not_a_crash():
    app = show(SCANS / "V7_broken.xml")
    assert app.error and "V7\\_broken" in app.error[0].value
    assert not app.expander


def test_a_hostile_hostname_is_shown_as_plain_text(tmp_path):
    scan = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet"), hostname="evil*[click](http://x.example)"))
    names = labels(show(scan))
    assert "evil\\*\\[click\\]\\(http\\:" in names[0]


def test_the_page_is_in_the_menu_and_acasa_points_to_it():
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    assert "pagina **Dispozitive**" in "\n".join(m.value for m in app.markdown)
