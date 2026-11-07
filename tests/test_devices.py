"""The device-type guess (FR-03): a label for people from services, vendor, hostname and products."""
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from conetuga.analysis.devices import (
    DEVICE_CAMERA, DEVICE_COMPUTER, DEVICE_NAS, DEVICE_PHONE, DEVICE_PRINTER, DEVICE_ROUTER, DEVICE_SERVER,
    DEVICE_SMART_HOME, DEVICE_TV, DEVICE_UNKNOWN, guess_device_type,
)
from conetuga.analysis.models import Port

SCANS = Path(__file__).resolve().parent / "fixtures" / "validation" / "scans"


def tcp(number: int, service: str, product: str = "") -> Port:
    return Port(port=number, proto="tcp", service=service, product=product, version="", ssl=False, title="")


def guess(vendor="", hostname="", mac="", ports=()):
    return guess_device_type(vendor=vendor, hostname=hostname, mac=mac, ports=list(ports))


def test_video_stream_means_a_camera():
    assert guess(vendor="Acme", ports=[tcp(554, "rtsp")]) == DEVICE_CAMERA


def test_raw_printing_port_means_a_printer():
    assert guess(ports=[tcp(9100, "jetdirect")]) == DEVICE_PRINTER


def test_specific_kind_wins_over_a_broad_one():
    """A camera with a web page and SSH is still a camera, not a server."""
    assert guess(ports=[tcp(22, "ssh"), tcp(80, "http"), tcp(554, "rtsp")]) == DEVICE_CAMERA


def test_router_from_its_hostname():
    assert guess(vendor="TP-Link", hostname="router.lan", ports=[tcp(80, "http")]) == DEVICE_ROUTER


def test_remote_desktop_means_a_computer():
    assert guess(ports=[tcp(3389, "ms-wbt-server")]) == DEVICE_COMPUTER


def test_database_means_a_server():
    assert guess(ports=[tcp(5432, "postgresql")]) == DEVICE_SERVER


def test_private_random_mac_with_no_open_ports_is_probably_a_phone():
    assert guess(mac="DA:A1:19:00:00:01") == DEVICE_PHONE


def test_private_mac_with_open_ports_is_not_assumed_to_be_a_phone():
    assert guess(mac="02:1A:7D:00:00:01", ports=[tcp(8888, "sun-answerbook")]) == DEVICE_UNKNOWN


def test_nothing_known_gives_unknown():
    assert guess(mac="00:11:22:33:44:55") == DEVICE_UNKNOWN


# --- More realistic devices (one sign each), and the brief's own description of the Validation Set networks ---


@pytest.mark.parametrize("ports, hostname, expected", [
    ([tcp(135, "msrpc", "Microsoft Windows RPC"), tcp(9100, "jetdirect")], "", DEVICE_COMPUTER),
    ([tcp(2179, "vmrdp")], "", DEVICE_COMPUTER),
    ([], "DESKTOP-4F2K1QX", DEVICE_COMPUTER),
    ([tcp(7000, "rtsp", "AirTunes rtspd")], "Anas-MacBook-Air", DEVICE_COMPUTER),
])
def test_signs_of_a_computer_win_over_printer_camera_and_tv_signs(ports, hostname, expected):
    """A printer never runs Windows RPC, and a Mac's AirPlay receiver isn't a TV: our lab laptop with a fake printer
    port, or any recent Mac, stays a computer."""
    assert guess(hostname=hostname, ports=ports) == expected


@pytest.mark.parametrize("ports, vendor, hostname", [
    ([tcp(7000, "rtsp", "AirTunes rtspd")], "", ""),             # Apple TV: AirPlay speaks RTSP, not a camera
    ([tcp(8008, "http", "Google Chromecast httpd")], "Google", ""),
    ([tcp(8009, "googlecast")], "", ""),
    ([tcp(8001, "http", "Samsung SmartTV")], "", ""),
    ([], "Roku", ""),
    ([tcp(3000, "http", "LG webOS TV")], "", ""),
])
def test_tvs_and_streaming_boxes(ports, vendor, hostname):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_TV


@pytest.mark.parametrize("vendor, hostname, ports", [
    ("Reolink", "", [tcp(80, "http")]),
    ("", "front-doorbell", [tcp(443, "http")]),
    ("", "", [tcp(80, "http", "Dahua DVR httpd")]),
])
def test_cameras_recorders_and_doorbells(vendor, hostname, ports):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_CAMERA


@pytest.mark.parametrize("vendor, hostname, ports", [
    ("Xerox", "", [tcp(80, "http")]),
    ("", "hp-laserjet-m404", [tcp(80, "http")]),
    ("", "", [tcp(631, "ipp", "CUPS")]),
])
def test_printers(vendor, hostname, ports):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_PRINTER


@pytest.mark.parametrize("vendor, hostname, ports", [
    ("", "", [tcp(5000, "http", "Synology DiskStation httpd")]),
    ("", "", [tcp(80, "http", "TrueNAS web UI")]),
    ("QNAP Systems", "", [tcp(445, "microsoft-ds")]),
])
def test_network_storage(vendor, hostname, ports):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_NAS


@pytest.mark.parametrize("vendor, hostname, ports", [
    ("", "", [tcp(53, "domain", "dnsmasq")]),                    # answers DNS for the network
    ("", "", [tcp(5000, "upnp", "MiniUPnP")]),
    ("MikroTik", "", [tcp(8291, "unknown")]),
    ("", "fritz.box", [tcp(80, "http")]),
    ("", "", [tcp(21, "ftp"), tcp(53, "domain")]),               # a phone sharing its connection, as in our lab
])
def test_routers_and_network_gear(vendor, hostname, ports):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_ROUTER


@pytest.mark.parametrize("hostname, ports", [
    ("", [tcp(62078, "tcpwrapped")]),                           # an iPhone's sync port, whatever nmap calls it
    ("", [tcp(62078, "iphone-sync")]),
    ("android-5f3c2a", []),
    ("Redmi-Note-12", []),
])
def test_phones_and_tablets(hostname, ports):
    assert guess(hostname=hostname, ports=ports) == DEVICE_PHONE


@pytest.mark.parametrize("vendor, hostname, ports", [
    ("Sonos, Inc.", "", [tcp(1400, "http")]),
    ("Signify Netherlands", "", [tcp(80, "http")]),
    ("", "philips-hue", [tcp(80, "http")]),
    ("", "echo-dot", []),
    ("", "living-room-thermostat", []),
    ("", "", [tcp(80, "http", "ESPHome web server")]),
    ("", "", [tcp(8123, "http", "Home Assistant")]),
])
def test_smart_home_devices(vendor, hostname, ports):
    assert guess(vendor=vendor, hostname=hostname, ports=ports) == DEVICE_SMART_HOME


def test_mail_server_is_a_server():
    assert guess(ports=[tcp(25, "smtp", "Postfix smtpd")]) == DEVICE_SERVER


BRIEF_DEVICES = {
    # The brief's Validation Set table, column "Network" (specs/00-brief.md), in IP order.
    "V1_home_basic.xml": ["router", "computer", "phone"],                       # router, laptop, phone
    "V2_smart_home.xml": ["router", "camera", "smart-home", "tv"],              # router, IP camera, smart hub, smart TV
    "V3_small_office.xml": ["printer", "nas", "computer", "server"],            # printer, NAS, Windows PC, Linux server
    "V4_legacy.xml": ["router", "server", "unknown"],                           # old router, old server, unknown device
}


@pytest.mark.parametrize("file, expected", BRIEF_DEVICES.items())
def test_validation_set_devices_get_the_kinds_the_brief_names(file, expected):
    assert [host.device_type for host in analyse_file(SCANS / file).hosts] == expected


def test_nas_that_also_answers_dns_is_still_a_nas():
    """Synology and others can run a DNS server; the storage signs say more than the DNS one."""
    assert guess(ports=[tcp(5000, "http", "Synology DiskStation httpd"), tcp(53, "domain")]) == DEVICE_NAS


def test_phone_sharing_its_connection_is_the_router_of_that_network():
    """Our hotspot phone in the live scan: it answers DNS for the network and has the iPhone sync port. For the
    people reading the UI, its role on this network (the router) matters more than what it is."""
    assert guess(ports=[tcp(53, "domain"), tcp(62078, "tcpwrapped")]) == DEVICE_ROUTER
