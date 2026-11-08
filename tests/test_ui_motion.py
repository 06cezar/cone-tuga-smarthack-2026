"""The animated score (ui/motion.py): it shows the real score and counts, loads nothing from outside, respects
"reduce motion", and carries no scan text."""
import re
from pathlib import Path

from conetuga.analysis import analyse_file
from ui.motion import score_motion_html, severity_counts

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"


def test_counts_follow_the_findings():
    assert severity_counts(analyse_file(SCANS / "V3_small_office.xml")) == {"high": 2, "medium": 1, "low": 1,
                                                                            "info": 2}


def test_the_page_shows_the_real_score_and_its_words():
    page = score_motion_html(analyse_file(SCANS / "V2_smart_home.xml"), "ro")
    assert 'id="n">40<' in page and "Roșu" in page and 'aria-label="40/100 Roșu"' in page


def test_nothing_is_loaded_from_outside():
    page = score_motion_html(analyse_file(SCANS / "V2_smart_home.xml"), "en")
    assert not re.search(r"(src|href)\s*=|https?://|@import", page)


def test_reduce_motion_draws_the_final_state():
    page = score_motion_html(analyse_file(SCANS / "V1_home_basic.xml"), "en")
    assert "prefers-reduced-motion: reduce" in page and "animation: none" in page


def test_no_scan_text_reaches_the_animation():
    result = analyse_file(SCANS / "V2_smart_home.xml")
    page = score_motion_html(result, "ro", dark=True)
    for host in result.hosts:
        assert host.ip not in page and (not host.hostname or host.hostname not in page)
