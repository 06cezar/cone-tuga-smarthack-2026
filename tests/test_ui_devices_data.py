"""Data for the Dispozitive page (FE-A4, ui/view.py): each device's status, the filters by status and device type, and
the sort orders, checked on the Validation Set. Pure functions: the page only shows what they return."""
from dataclasses import replace
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from conetuga.explain import device_label
from ui.view import (STATUSES, devices_by_risk, device_status, filter_devices, sort_devices, status_options,
                     type_options)

SCANS = Path(__file__).parent / "fixtures" / "validation" / "scans"


def devices(name: str, lang: str = "ro"):
    return devices_by_risk(analyse_file(SCANS / name), lang)


def ips(views) -> list[str]:
    return [d.host.ip for d in views]


def test_status_is_the_worst_severity_of_the_device():
    """V3: the PC (RDP) and the server (database) are high, the NAS (SMB, plus SSH for information) medium, the
    printer low."""
    status = {d.host.ip: device_status(d) for d in devices("V3_small_office.xml")}
    assert status == {"192.168.1.30": "high", "192.168.1.40": "high", "192.168.1.20": "medium", "192.168.1.10": "low"}


def test_a_checked_device_without_findings_has_no_problems():
    status = {d.host.ip: device_status(d) for d in devices("V1_home_basic.xml")}
    assert status == {"192.168.1.1": "medium", "192.168.1.20": "none", "192.168.1.35": "none"}


def test_a_device_nmap_gave_up_on_is_not_checked_rather_than_problem_free():
    laptop = next(d for d in devices("V1_home_basic.xml") if d.host.ip == "192.168.1.20")
    assert device_status(replace(laptop, host=replace(laptop.host, timed_out=True))) == "unchecked"


def test_filter_by_status():
    assert ips(filter_devices(devices("V3_small_office.xml"), statuses={"high"})) == ["192.168.1.30", "192.168.1.40"]
    assert ips(filter_devices(devices("V1_home_basic.xml"), statuses={"none"})) == ["192.168.1.20", "192.168.1.35"]


def test_filter_by_device_type():
    assert ips(filter_devices(devices("V3_small_office.xml"), types={"printer", "nas"})) == ["192.168.1.20",
                                                                                            "192.168.1.10"]


def test_both_filters_together():
    found = filter_devices(devices("V3_small_office.xml"), statuses={"high"}, types={"server"})
    assert ips(found) == ["192.168.1.40"]


def test_no_filter_keeps_every_device_in_the_order_given():
    views = devices("V2_smart_home.xml")
    assert filter_devices(views) == views


def test_a_filter_can_leave_nothing():
    assert filter_devices(devices("V6b_after.xml"), statuses={"high"}) == []


def test_unknown_status_is_refused():
    with pytest.raises(ValueError):
        filter_devices(devices("V1_home_basic.xml"), statuses={"dangerous"})


def test_sort_by_risk_is_the_first_screen_order():
    views = devices("V2_smart_home.xml")
    assert sort_devices(list(reversed(views)), "risk", "ro") == views


def test_sort_by_ip_is_by_number_not_text():
    """192.168.1.100 comes after 192.168.1.35; sorted as text it would come before."""
    views = devices("V1_home_basic.xml")
    moved = [replace(views[0], host=replace(views[0].host, ip="192.168.1.100")), *views[1:]]
    assert ips(sort_devices(moved, "ip", "ro")) == ["192.168.1.20", "192.168.1.35", "192.168.1.100"]


def test_sort_by_name_ignores_case():
    """"alpha" comes before "Beta" and "beta-2", whatever their capitals (sorted by code point, "B" < "a")."""
    views = devices("V1_home_basic.xml")
    named = [replace(view, name=name) for view, name in zip(views, ["beta-2", "alpha", "Beta"])]
    assert [d.name for d in sort_devices(named, "name", "en")] == ["alpha", "Beta", "beta-2"]


def test_sort_by_type_follows_the_labels_people_read_in_each_language():
    for lang in ("ro", "en"):
        labels = [device_label(d.host.device_type, lang)
                  for d in sort_devices(devices("V3_small_office.xml", lang), "type", lang)]
        assert labels == sorted(labels, key=str.casefold) and len(labels) == 4


def test_within_one_type_the_riskiest_device_comes_first():
    """V3 has no two devices of one type, so two computers are made from its PC (high) and printer (low)."""
    views = devices("V3_small_office.xml")
    pc = next(d for d in views if d.host.ip == "192.168.1.30")
    printer_as_pc = next(replace(d, host=replace(d.host, device_type="computer")) for d in views
                         if d.host.ip == "192.168.1.10")
    assert ips(sort_devices([printer_as_pc, pc], "type", "en")) == ["192.168.1.30", "192.168.1.10"]


def test_sorting_twice_gives_the_same_order():
    views = devices("V5_nonstandard_ports.xml")
    for key in ("risk", "ip", "name", "type"):
        assert sort_devices(views, key, "en") == sort_devices(list(reversed(views)), key, "en")


def test_unknown_sort_is_refused():
    with pytest.raises(ValueError):
        sort_devices(devices("V1_home_basic.xml"), "colour", "ro")


def test_status_options_cover_every_status_with_an_icon_and_words():
    """Colour is never the only signal (NFR-08): every option is an icon, a space, then words."""
    for lang in ("ro", "en"):
        options = status_options(lang)
        assert [value for value, _ in options] == list(STATUSES)
        for _, label in options:
            icon, words = label.split(" ", 1)
            assert not icon.isalnum() and any(char.isalpha() for char in words)


def test_type_options_offer_only_the_types_in_the_scan_sorted_by_label():
    assert {value for value, _ in type_options(devices("V1_home_basic.xml", "en"), "en")} == {"router", "computer",
                                                                                              "phone"}
    for name in ("V2_smart_home.xml", "V3_small_office.xml", "V5_nonstandard_ports.xml"):
        for lang in ("ro", "en"):
            labels = [label for _, label in type_options(devices(name, lang), lang)]
            assert labels == sorted(labels, key=str.casefold), (name, lang)
