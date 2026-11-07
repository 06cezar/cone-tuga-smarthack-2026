"""The first screen's content (ui/view.py), checked on the Validation Set: the riskiest device and its first fix come
first, the traffic light always has words, and scan text can't turn into Markdown."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from ui.view import (GREEN_FROM, LANGUAGES, YELLOW_FROM, devices_by_risk, headline, light, md, score_line,
                     severity_label)

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"


def view(name: str, lang: str = "ro"):
    return devices_by_risk(analyse_file(SCANS / name), lang)


def test_the_riskiest_device_comes_first():
    devices = view("V2_smart_home.xml")
    assert devices[0].host.ip == "192.168.1.40"  # the camera: RTSP open (high) and its admin page (medium)
    assert [d.risk for d in devices] == sorted((d.risk for d in devices), reverse=True)


def test_headline_names_the_device_and_its_first_step_in_both_languages():
    for lang, words in (("ro", ("Cel mai periculos", "Fă asta întâi")), ("en", ("Most dangerous", "Do this first"))):
        devices = view("V4_legacy.xml", lang)
        top = devices[0]
        line = headline(devices, lang)
        assert line.startswith(f"{words[0]}: {top.name} (192.168.1.1)")
        assert f"{words[1]}: {top.findings[0].explanation.steps[0]}" in line


def test_the_first_step_belongs_to_the_riskiest_finding_of_that_device():
    top = view("V4_legacy.xml")[0]  # the old router: telnet (high), SNMP and its admin page (medium)
    assert top.findings[0].finding.code == "TELNET_OPEN"
    assert [f.finding.points for f in top.findings] == sorted((f.finding.points for f in top.findings), reverse=True)


def test_a_clean_scan_says_nothing_is_dangerous():
    assert headline(view("V6b_after.xml"), "ro") == "Nu am găsit nimic periculos în această scanare."
    assert headline(view("V6b_after.xml", "en"), "en") == "We found nothing dangerous in this scan."


def test_every_device_is_listed_with_its_findings():
    result = analyse_file(SCANS / "V3_small_office.xml")
    devices = devices_by_risk(result, "en")
    assert sorted(d.host.ip for d in devices) == sorted(h.ip for h in result.hosts)
    assert sum(len(d.findings) for d in devices) == len(result.findings)


def test_device_without_hostname_is_named_by_its_type():
    unknown = next(d for d in view("V4_legacy.xml", "en") if d.host.ip == "192.168.1.99")
    assert unknown.name == "Unknown device"


@pytest.mark.parametrize("score, colour", [(100, "green"), (GREEN_FROM, "green"), (GREEN_FROM - 1, "yellow"),
                                           (YELLOW_FROM, "yellow"), (YELLOW_FROM - 1, "red"), (0, "red")])
def test_traffic_light_thresholds(score, colour):
    assert light(score) == colour


@pytest.mark.parametrize("lang", LANGUAGES)
def test_traffic_light_and_severity_always_have_words(lang):
    for score in (100, 60, 10):
        icon, word, sentence = score_line(score, lang)
        assert icon and word.strip() and sentence.strip()
    for severity in ("high", "medium", "low", "info"):
        assert len(severity_label(severity, lang).split(" ", 1)[1]) > 3


@pytest.mark.parametrize("hostile", ["[click](javascript:alert(1))", "<script>alert(1)</script>", ":red[fake]",
                                     "**bold** _x_ `code`", "$x^2$", "# heading", "a\nb\rc"])
def test_scan_text_cannot_become_markdown(hostile):
    safe = md(hostile)
    assert "\n" not in safe and "\r" not in safe
    for char in "[]()<>*_`$#:":
        assert all(safe[i - 1] == "\\" for i, c in enumerate(safe) if c == char), (hostile, safe)
