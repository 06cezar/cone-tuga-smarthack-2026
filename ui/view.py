"""What the first screen shows, built only from analyse_file's result and explain() (specs/contracts.md).

Pure functions with no Streamlit, so tests/test_ui_view.py checks them on the Validation Set. The UI never computes a
finding or a score: it only orders what analyse_file returned, so a person sees the riskiest device first."""
import ipaddress
from dataclasses import dataclass

from conetuga.analysis import FileResult, Finding, Host
from conetuga.analysis.catalog import load_catalog
from conetuga.explain import Explanation, device_label, explain
from conetuga.history import diff

LANGUAGES = ("ro", "en")

# Traffic light on the standard score (0-100). The thresholds are ours, not the brief's: a score of 80 or more means
# at most a couple of medium findings; under 50, at least one high-risk door is open. Always shown with an icon and a
# word, never by colour alone (NFR-08).
GREEN_FROM = 80
YELLOW_FROM = 50

LIGHT_ICON = {"green": "🟢", "yellow": "🟡", "red": "🔴"}
SEVERITY_ICON = {"high": "⛔", "medium": "⚠️", "low": "🔹", "info": "💬"}

TEXT = {
    "ro": {
        "most_dangerous": "Cel mai periculos",
        "do_first": "Fă asta întâi",
        "nothing_urgent": "Nu am găsit nimic periculos în această scanare.",
        "light_green": "Verde",
        "light_yellow": "Galben",
        "light_red": "Roșu",
        "sentence_green": "Rețeaua arată bine. Verifică din când în când.",
        "sentence_yellow": "Câteva uși sunt deschise. Repară-le pe rând, de sus în jos.",
        "sentence_red": "Sunt uși periculoase deschise. Începe cu primul pas de mai sus.",
        "severity_high": "Risc mare",
        "severity_medium": "Risc mediu",
        "severity_low": "Risc mic",
        "severity_info": "Doar informativ",
        "status_none": "✅ Fără probleme",
        "status_unchecked": "❔ Neverificat (nmap a renunțat la el)",
    },
    "en": {
        "most_dangerous": "Most dangerous",
        "do_first": "Do this first",
        "nothing_urgent": "We found nothing dangerous in this scan.",
        "light_green": "Green",
        "light_yellow": "Yellow",
        "light_red": "Red",
        "sentence_green": "Your network looks good. Check it again from time to time.",
        "sentence_yellow": "A few doors are open. Fix them one at a time, from the top.",
        "sentence_red": "Dangerous doors are open. Start with the first step above.",
        "severity_high": "High risk",
        "severity_medium": "Medium risk",
        "severity_low": "Low risk",
        "severity_info": "For your information",
        "status_none": "✅ No problems",
        "status_unchecked": "❔ Not checked (nmap gave up on it)",
    },
}

# The Dispozitive page's filters (FE-A4). A device's status is its worst severity, most severe first in the catalog's
# own order (by points), or one of these two when it has no finding: nmap gave up on it (Host.timed_out, so "no
# findings" means "not checked"), or it was checked and has none.
_SEVERITY_POINTS = load_catalog().severity_points
SEVERITY_ORDER = tuple(sorted(_SEVERITY_POINTS, key=_SEVERITY_POINTS.get, reverse=True))
STATUS_UNCHECKED = "unchecked"
STATUS_NONE = "none"
STATUSES = (*SEVERITY_ORDER, STATUS_UNCHECKED, STATUS_NONE)
SORT_KEYS = ("risk", "ip", "name", "type")  # risk first is the page's default, as on the first screen

# Characters that Streamlit's Markdown would read as formatting, links, HTML, maths ($) or colour directives (:red[...]).
MARKDOWN_SPECIAL = set("\\`*_{}[]()#+-.!|<>~=$:")


@dataclass(frozen=True)
class FindingView:
    finding: Finding
    explanation: Explanation


@dataclass(frozen=True)
class DeviceView:
    host: Host
    name: str  # what a person reads: "ipcam — Cameră video", or only the device-type label when there's no hostname
    risk: int  # the points of its findings, added up: used only to put the riskiest device first
    findings: list[FindingView]  # riskiest first


def devices_by_risk(result: FileResult, lang: str) -> list[DeviceView]:
    """Every device of the scan, riskiest first (ties: by IP as a number), each with its explained findings."""
    devices = [_device_view(host, result.findings, lang) for host in result.hosts]
    return sorted(devices, key=lambda device: (-device.risk, _ip_order(device.host.ip)))


def headline(devices: list[DeviceView], lang: str) -> str:
    """The sentence at the top: "Cel mai periculos: <device>. Fă asta întâi: <step>" (ui/CLAUDE.md). Scan text inside
    is not escaped here: the page escapes it when it shows it."""
    text = TEXT[lang]
    if not devices or devices[0].risk == 0:
        return text["nothing_urgent"]
    top = devices[0]
    first_step = top.findings[0].explanation.steps[0]
    return f"{text['most_dangerous']}: {top.name} ({top.host.ip}). {text['do_first']}: {first_step}"


def light(score: int) -> str:
    """"green", "yellow" or "red" for a standard score."""
    if score >= GREEN_FROM:
        return "green"
    if score >= YELLOW_FROM:
        return "yellow"
    return "red"


def score_line(score: int, lang: str) -> tuple[str, str, str]:
    """The icon, the colour word and the sentence that go with the score."""
    colour = light(score)
    return LIGHT_ICON[colour], TEXT[lang][f"light_{colour}"], TEXT[lang][f"sentence_{colour}"]


def severity_label(severity: str, lang: str) -> str:
    """Icon and words for a severity, e.g. "⛔ Risc mare": colour is never the only signal."""
    return f"{SEVERITY_ICON[severity]} {TEXT[lang][f'severity_{severity}']}"


def same_network(earlier: FileResult, current: FileResult) -> bool:
    """Whether the history may compare the two scans on its own: they share at least one device, and every device of
    one of them is also in the other (devices were only added or only removed between them), by the key `diff`
    matches devices on (IP + hostname).

    A scan file can't prove which network it is, so this is a deliberately narrow rule, not a guess at "the same
    network": one shared router (V1 and V2), or a device that left while another arrived, isn't enough. In those
    cases the page compares nothing by itself and lets the person pick any earlier scan, so the rule can neither
    invent a "new device" alert nor hide one (a review of #35 found a 50% threshold did both)."""
    if earlier.error or earlier.score is None:
        return False
    change = diff(earlier, current)
    shared = len(current.hosts) - len(change.new_devices)
    return shared > 0 and (not change.new_devices or not change.removed_devices)


def md(text: str) -> str:
    """Scan text (hostnames, vendors, page titles, versions) made safe for st.markdown: every formatting character
    is backslash-escaped and line breaks become spaces, so a hostile banner shows as plain text (NFR-03)."""
    flat = " ".join(str(text).split())
    return "".join(f"\\{char}" if char in MARKDOWN_SPECIAL else char for char in flat)


def _device_view(host: Host, findings: list[Finding], lang: str) -> DeviceView:
    own = [f for f in findings if f.ip == host.ip]
    ordered = sorted(own, key=lambda f: -f.points)  # stable: equal points keep analyse_file's order
    views = [FindingView(f, explain(f, host, lang)) for f in ordered]
    return DeviceView(host=host, name=device_name(host, lang), risk=sum(f.points for f in own), findings=views)


def device_name(host: Host, lang: str) -> str:
    """"ipcam — Cameră video", or only the device-type label when the scan shows no hostname (not escaped)."""
    label = device_label(host.device_type, lang)
    return f"{host.hostname} — {label}" if host.hostname else label


def _ip_order(ip: str) -> tuple[int, int]:
    address = ipaddress.ip_address(ip)
    return address.version, int(address)


def device_status(device: DeviceView) -> str:
    """The device's worst severity ("high", "medium", ...), STATUS_UNCHECKED when it has no finding because nmap gave
    up on it, or STATUS_NONE when it was checked and has none. A timed-out device with findings nmap did write shows
    the worst of them: at least that bad."""
    severities = {view.finding.severity for view in device.findings}
    worst = next((severity for severity in SEVERITY_ORDER if severity in severities), None)
    if worst:
        return worst
    return STATUS_UNCHECKED if device.host.timed_out else STATUS_NONE


def filter_devices(devices: list[DeviceView], statuses: set[str] | None = None,
                   types: set[str] | None = None) -> list[DeviceView]:
    """The devices whose status is in `statuses` and whose device type is in `types`; None means no filter on that
    one. Keeps the order it was given. Raises ValueError for a status that isn't in STATUSES."""
    unknown = (statuses or set()) - set(STATUSES)
    if unknown:
        raise ValueError(f"unknown device status: {sorted(unknown)}")
    return [d for d in devices
            if (statuses is None or device_status(d) in statuses)
            and (types is None or d.host.device_type in types)]


def sort_devices(devices: list[DeviceView], by: str, lang: str) -> list[DeviceView]:
    """The devices in the order the person picked: "risk" (riskiest first, as on the first screen), "ip" (as a
    number), "name" or "type" (alphabetically, as the person reads them in `lang`; riskiest first within a type).
    Ties always fall back to the IP, so the order is the same on every run."""
    if by not in SORT_KEYS:
        raise ValueError(f"unknown sort {by!r}; choose from {SORT_KEYS}")
    keys = {
        "risk": lambda d: (-d.risk, _ip_order(d.host.ip)),
        "ip": lambda d: _ip_order(d.host.ip),
        "name": lambda d: (d.name.casefold(), _ip_order(d.host.ip)),
        "type": lambda d: (device_label(d.host.device_type, lang).casefold(), -d.risk, _ip_order(d.host.ip)),
    }
    return sorted(devices, key=keys[by])


def status_options(lang: str) -> list[tuple[str, str]]:
    """(value, label) for the status filter, most severe first, always with an icon and words (NFR-08)."""
    text = TEXT[lang]
    return ([(severity, severity_label(severity, lang)) for severity in SEVERITY_ORDER]
            + [(STATUS_UNCHECKED, text["status_unchecked"]), (STATUS_NONE, text["status_none"])])


def type_options(devices: list[DeviceView], lang: str) -> list[tuple[str, str]]:
    """(value, label) for the device-type filter: only the types this scan has, sorted as the person reads them."""
    present = {d.host.device_type for d in devices}
    return sorted(((t, device_label(t, lang)) for t in present), key=lambda option: option[1].casefold())
