"""What the first screen shows, built only from analyse_file's result and explain() (specs/contracts.md).

Pure functions with no Streamlit, so tests/test_ui_view.py checks them on the Validation Set. The UI never computes a
finding or a score: it only orders what analyse_file returned, so a person sees the riskiest device first."""
import ipaddress
from dataclasses import dataclass

from conetuga.analysis import FileResult, Finding, Host
from conetuga.explain import Explanation, device_label, explain

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
    },
}

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
