"""The first screen's content (ui/view.py), checked on the Validation Set: the riskiest device and its first fix come
first, the traffic light always has words, and scan text can't turn into Markdown."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from nmap_xml import host, port, write_scan
from ui.view import (GREEN_FROM, LANGUAGES, YELLOW_FROM, devices_by_risk, headline, light, md, same_network,
                     score_line, severity_label)

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"
LAB = Path(__file__).resolve().parents[1] / "lab" / "scans"


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


def scan_of(folder: Path, name: str, *devices: tuple[str, str]):
    """A scan whose devices are (ip, hostname) pairs, each with one open port: what the history matches devices on."""
    return analyse_file(write_scan(folder, *(host(ip, port(22, "ssh"), hostname=name_) for ip, name_ in devices),
                                   name=name))


def test_same_network_compares_when_devices_were_only_added(tmp_path):
    """The review of #35: one device, then three with the old one still there. The two new devices must be flagged,
    so the history compares on its own (a 50% threshold hid them)."""
    before = scan_of(tmp_path, "a.xml", ("10.0.0.1", "router"))
    after = scan_of(tmp_path, "b.xml", ("10.0.0.1", "router"), ("10.0.0.2", "tv"), ("10.0.0.3", "cam"))
    assert same_network(before, after)


def test_same_network_compares_when_devices_were_only_removed(tmp_path):
    before = scan_of(tmp_path, "a.xml", ("10.0.0.1", "router"), ("10.0.0.2", "tv"), ("10.0.0.3", "cam"))
    after = scan_of(tmp_path, "b.xml", ("10.0.0.1", "router"))
    assert same_network(before, after)


def test_same_network_doesnt_pair_two_small_networks_sharing_one_device(tmp_path):
    """The review of #35: two networks of two devices with one IP + hostname in common were compared wrongly."""
    one = scan_of(tmp_path, "a.xml", ("10.0.0.1", "router"), ("10.0.0.2", "tv"))
    other = scan_of(tmp_path, "b.xml", ("10.0.0.1", "router"), ("10.0.0.7", "nas"))
    assert not same_network(one, other)


def test_same_network_on_the_shipped_scans():
    pairs = {("V6a_before.xml", "V6b_after.xml"): True, ("V1_home_basic.xml", "V2_smart_home.xml"): False,
             ("V2_smart_home.xml", "V3_small_office.xml"): False}
    for (a, b), expected in pairs.items():
        assert same_network(analyse_file(SCANS / a), analyse_file(SCANS / b)) is expected, (a, b)
    assert same_network(analyse_file(LAB / "scan_01.xml"), analyse_file(LAB / "scan_03.xml"))
    assert not same_network(analyse_file(LAB / "scan_03.xml"), analyse_file(SCANS / "V1_home_basic.xml"))


def test_same_network_never_pairs_a_broken_or_empty_scan(tmp_path):
    good = analyse_file(SCANS / "V1_home_basic.xml")
    assert not same_network(analyse_file(SCANS / "V7_broken.xml"), good)
    empty = analyse_file(write_scan(tmp_path, name="empty.xml"))
    assert not same_network(empty, good) and not same_network(good, empty)
