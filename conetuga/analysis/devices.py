"""Guess what kind of device a host is (FR-03), from what the scan shows: services, MAC vendor, hostname, products and
a few port numbers that only one kind of device uses.

Only a label for people: it never changes a finding or a score. The first rule that matches wins, so the order is
the logic:
- computer first: Windows RPC, remote desktop or a "DESKTOP-..." name never come from a printer, camera or TV, so a
  laptop that also offers a printer port (our own lab) or an AirPlay receiver (any recent Mac) is still a computer;
- TV before camera: Apple TVs and Macs speak RTSP for AirPlay ("AirTunes rtspd"), which isn't a camera stream;
- the specific kinds (camera, printer, NAS) before the broad ones (router, phone, smart home, server).
The UI and the explanations translate the labels (`data/explanations.toml`, [device_types]); the values are the
DEVICE_* constants below, the list `specs/contracts.md` names."""
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
    """A device kind and the signs of it; any one sign is enough. Words match as parts of the text, ignoring case.
    `ports` are port numbers that point to one kind of device whatever service name nmap gives them (an iPhone's
    62078 often shows as "tcpwrapped"): a label may use them, a finding never does."""

    device_type: str
    services: frozenset[str] = frozenset()
    vendor_words: tuple[str, ...] = ()
    hostname_words: tuple[str, ...] = ()
    product_words: tuple[str, ...] = ()
    ports: frozenset[int] = frozenset()


DEVICE_RULES = (
    # Windows: RPC (135), remote desktop, Hyper-V's console; macOS and Linux desktops by their usual names. Windows
    # names new PCs "DESKTOP-XXXXXXX" or "LAPTOP-XXXXXXX".
    DeviceRule(DEVICE_COMPUTER, frozenset({"msrpc", "ms-wbt-server", "vmrdp", "vnc"}), (),
               ("laptop", "desktop", "desk-", "-pc", "pc-", "macbook", "imac", "mac-mini", "thinkpad", "workstation"),
               ("microsoft windows rpc", "microsoft terminal services", "macos", "mac os x")),
    # TVs and streaming boxes: Chromecast, AirPlay receivers (Apple TV), Roku, Fire TV, Samsung, LG and Sony TVs.
    DeviceRule(DEVICE_TV, frozenset({"googlecast", "airplay"}), ("roku",),
               ("tv", "chromecast", "roku", "firestick"),
               ("chromecast", "roku", "smart tv", "smarttv", "airtunes", "airplay", "apple tv", "webos", "bravia",
                "fire tv", "kodi", "plex")),
    # Cameras, video recorders and doorbells: an RTSP video stream or a camera maker.
    DeviceRule(DEVICE_CAMERA, frozenset({"rtsp"}),
               ("hikvision", "dahua", "axis", "reolink", "foscam", "uniview", "ezviz", "amcrest", "wyze", "hanwha"),
               ("cam", "nvr", "dvr", "doorbell"), ("camera", "dvr", "nvr")),
    DeviceRule(DEVICE_PRINTER, frozenset({"jetdirect", "ipp", "ipps", "printer"}),
               ("brother", "canon", "epson", "kyocera", "xerox", "lexmark", "ricoh", "zebra", "konica"),
               ("print", "laserjet", "officejet", "deskjet"), ("printer", "cups", "laserjet", "officejet", "jetdirect")),
    DeviceRule(DEVICE_NAS, frozenset(), ("synology", "qnap", "buffalo", "western digital", "asustor", "terramaster"),
               ("nas", "diskstation"), ("diskstation", "synology", "qnap", "truenas", "freenas", "unraid",
                                        "openmediavault")),
    # Router, access point or other network gear, including a phone sharing its connection: it answers DNS for the
    # network or runs the router's UPnP daemon. Vendors that also make plugs or laptops (TP-Link, Asus) are left out:
    # for them the hostname or the product has to say it.
    DeviceRule(DEVICE_ROUTER, frozenset({"domain"}), ("ubiquiti", "mikrotik", "cisco", "aruba", "zyxel", "arris",
                                                       "sagemcom", "technicolor"),
               ("router", "gateway", "modem", "access-point", "fritz.box", "openwrt"),
               ("router", "dnsmasq", "miniupnp", "openwrt", "dd-wrt", "routeros", "fritz")),
    # Phones and tablets: the iPhone's sync service (62078) or the usual names.
    DeviceRule(DEVICE_PHONE, frozenset({"iphone-sync"}), (),
               ("iphone", "ipad", "galaxy", "android", "pixel", "phone", "redmi", "oneplus"),
               ("apple iphone",), frozenset({62078})),
    # Smart home: an IoT message broker, an IoT chip or plug maker, speakers, lights, thermostats, vacuum robots.
    DeviceRule(DEVICE_SMART_HOME, frozenset({"mqtt"}),
               ("espressif", "tuya", "shelly", "sonoff", "sonos", "philips lighting", "signify", "nest labs",
                "ecobee", "lifx"),
               ("plug", "hub", "bulb", "switch", "sensor", "echo", "alexa", "sonos", "hue", "nest", "thermostat",
                "vacuum", "roborock"),
               ("sonos", "philips hue", "home assistant", "homebridge", "esphome", "tasmota", "zigbee")),
    DeviceRule(DEVICE_SERVER, frozenset({"ssh", "mysql", "postgresql", "redis", "mongodb", "ms-sql-s", "oracle-tns",
                                         "ftp", "telnet", "http", "smtp", "imap", "pop3", "ldap", "nfs"}),
               (), ("srv", "server", "db")),
)

# A MAC whose first byte has the "locally administered" bit set (second hex digit 2, 6, A or E) is a random one:
# phones and laptops use them for privacy. With no open ports, such a device is most likely a phone.
LOCALLY_ADMINISTERED_BIT = 0x02


def guess_device_type(*, vendor: str, hostname: str, mac: str, ports: list[Port]) -> str:
    """One of the DEVICE_* labels; DEVICE_UNKNOWN when nothing in the scan points to a kind."""
    services = {port.service for port in ports}
    numbers = {port.port for port in ports}
    products = " ".join(port.product for port in ports).casefold()
    vendor, hostname = vendor.casefold(), hostname.casefold()
    for rule in DEVICE_RULES:
        if (
            services & rule.services
            or numbers & rule.ports
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
