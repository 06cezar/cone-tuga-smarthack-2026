"""The device-type guess (FR-03): a label for people from services, vendor, hostname and products."""
from conetuga.analysis.devices import (
    DEVICE_CAMERA, DEVICE_COMPUTER, DEVICE_PHONE, DEVICE_PRINTER, DEVICE_ROUTER, DEVICE_SERVER, DEVICE_UNKNOWN,
    guess_device_type,
)
from conetuga.analysis.models import Port


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
