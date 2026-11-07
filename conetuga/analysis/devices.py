"""Guess what kind of device a host is (FR-03), from what the scan shows: services, MAC vendor, hostname, products.

Only a label for people: it never changes a finding or a score. The first rule that matches wins, so the more
specific kinds (camera, printer) come before the broad ones (computer, server). The UI and the explanations
translate the labels; the values are the DEVICE_* constants below."""
from dataclasses import dataclass

from conetuga.analysis.models import Port

DEVICE_CAMERA = "camera"
DEVICE_PRINTER = "printer"
DEVICE_NAS = "nas"
DEVICE_ROUTER = "router"
DEVICE_TV = "tv"
DEVICE_SMART_HOME = "smart-home"
DEVICE_COMPUTER = "computer"
DEVICE_SERVER = "server"
DEVICE_PHONE = "phone"
DEVICE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class DeviceRule:
    """A device kind and the signs of it; any one sign is enough. Words match as parts of the text, ignoring case."""

    device_type: str
    services: frozenset[str] = frozenset()
    vendor_words: tuple[str, ...] = ()
    hostname_words: tuple[str, ...] = ()
    product_words: tuple[str, ...] = ()


DEVICE_RULES = (
    DeviceRule(DEVICE_CAMERA, frozenset({"rtsp"}), ("hikvision", "dahua", "axis", "reolink", "foscam", "uniview"),
               ("cam", "nvr", "dvr"), ("camera",)),
    DeviceRule(DEVICE_PRINTER, frozenset({"jetdirect", "ipp", "printer"}), ("brother", "canon", "epson", "kyocera"),
               ("print",), ("printer", "cups")),
    DeviceRule(DEVICE_NAS, frozenset(), ("synology", "qnap", "buffalo", "western digital"), ("nas",)),
    # Router, access point or other network gear. Vendors that also make plugs or laptops (TP-Link, Asus) are left
    # out: for them the hostname or the product has to say it.
    DeviceRule(DEVICE_ROUTER, frozenset(), ("ubiquiti", "mikrotik", "cisco", "aruba", "zyxel"),
               ("router", "gateway", "modem", "access-point"), ("router",)),
    DeviceRule(DEVICE_TV, frozenset({"googlecast"}), ("roku",), ("tv",), ("chromecast", "roku", "smart tv")),
    DeviceRule(DEVICE_SMART_HOME, frozenset({"mqtt"}), ("espressif", "tuya", "shelly", "sonoff"),
               ("plug", "hub", "bulb", "switch", "sensor")),
    DeviceRule(DEVICE_COMPUTER, frozenset({"ms-wbt-server", "vnc"}), (),
               ("laptop", "desktop", "desk-", "-pc", "pc-", "macbook", "workstation")),
    DeviceRule(DEVICE_PHONE, frozenset(), (), ("iphone", "ipad", "galaxy", "android", "pixel", "phone")),
    DeviceRule(DEVICE_SERVER, frozenset({"ssh", "mysql", "postgresql", "redis", "mongodb", "ftp", "telnet", "http"}),
               (), ("srv", "server", "db")),
)

# A MAC whose first byte has the "locally administered" bit set (second hex digit 2, 6, A or E) is a random one:
# phones and laptops use them for privacy. With no open ports, such a device is most likely a phone.
LOCALLY_ADMINISTERED_BIT = 0x02


def guess_device_type(*, vendor: str, hostname: str, mac: str, ports: list[Port]) -> str:
    """One of the DEVICE_* labels; DEVICE_UNKNOWN when nothing in the scan points to a kind."""
    services = {port.service for port in ports}
    products = " ".join(port.product for port in ports).casefold()
    vendor, hostname = vendor.casefold(), hostname.casefold()
    for rule in DEVICE_RULES:
        if (
            services & rule.services
            or _contains_any(vendor, rule.vendor_words)
            or _contains_any(hostname, rule.hostname_words)
            or _contains_any(products, rule.product_words)
        ):
            return rule.device_type
    if not ports and _is_locally_administered(mac):
        return DEVICE_PHONE
    return DEVICE_UNKNOWN


def _contains_any(text: str, words: tuple[str, ...]) -> bool:
    return bool(text) and any(word in text for word in words)


def _is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & LOCALLY_ADMINISTERED_BIT)
    except ValueError:
        return False
