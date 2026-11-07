"""Scanare: the network this computer is on (FR-01), whether the guardrail would allow a live scan of it (FR-02), and
the exact command a person runs in a terminal to scan it. The page itself runs nothing: no nmap, no administrator
rights (NFR-04); a scan run from the terminal lands in the history (FR-10), where the other pages show it.

The network is read the same way the live scan reads it (detect_network, wifi_ssid, check_scope), so the page and the
scan always agree. A Wi-Fi name is outside text: it is escaped before display (NFR-03)."""
import sys

import streamlit as st

from conetuga.guard import HOTSPOT_SSID, NetworkNotFound, check_scope, detect_network, wifi_ssid
from conetuga.guard.scan import (DEFAULT_MINUTES, EXTRA_TCP_PORTS, MAX_PACKETS_PER_SECOND, MIN_MINUTES, SAFE_SCRIPT,
                                 TOP_TCP_PORTS, UDP_PORTS)
from ui.state import current
from ui.view import md

LINUX_COMMAND = ".venv/bin/python -m conetuga scan --confirm"
WINDOWS_COMMAND = r".venv\Scripts\python -m conetuga scan --confirm"

TEXT = {
    "ro": {
        "title": "Scanare live",
        "intro": "Pagina asta nu scanează nimic. Îți arată la ce rețea ești conectat și comanda pe care o rulezi tu, "
                 "într-un terminal, din folderul proiectului.",
        "network": "Rețeaua ta",
        "wifi": "Wi-Fi",
        "no_wifi": "niciunul",
        "allowed": "✅ Ești pe hotspotul echipei: scanarea acestei rețele este permisă.",
        "refused": "⛔ Scanarea ar fi refuzată acum.",
        "not_hotspot": f"Conectează laptopul doar la hotspotul „{HOTSPOT_SSID}” și deschide din nou pagina.",
        "no_network": "Nu găsesc nicio rețea activă. Conectează laptopul la hotspotul echipei.",
        "command": "Comanda de rulat",
        "linux_note": "Programul îți cere parola de administrator doar pentru nmap, care trimite pachetele.",
        "windows_note": "Deschide terminalul ca administrator (clic dreapta, Run as administrator).",
        "after": "Rezultatul apare apoi în Istoric, lângă scanările de dinainte.",
        "details": "Detalii tehnice",
        "interface": "Interfața",
        "address": "Adresa acestui laptop",
        "subnet": "Subrețeaua (singura permisă)",
        "gateway": "Gateway",
        "guardrail": "Garda",
        "what_nmap_does": "Ce face nmap",
        "nmap_lines": [
            "`-sS -sU -sV` cu scriptul sigur `{script}` (titlurile paginilor de administrare)",
            "cel mult {rate} {rate_de}pachete pe secundă",
            "cele mai folosite {top} {top_de}porturi TCP plus {extra}, și UDP {udp}",
            "fără acest laptop (`--exclude {ip}`), ca să nu apară ca dispozitiv necunoscut",
            "cel mult {minutes} minute pe dispozitiv (`--minutes`, minimum {min_minutes}); un dispozitiv neterminat e "
            "numit, pentru că rezultatele lui lipsesc",
        ],
    },
    "en": {
        "title": "Live scan",
        "intro": "This page scans nothing. It shows the network you're connected to and the command you run yourself, "
                 "in a terminal, from the project folder.",
        "network": "Your network",
        "wifi": "Wi-Fi",
        "no_wifi": "none",
        "allowed": "✅ You're on the team's hotspot: scanning this network is allowed.",
        "refused": "⛔ A scan would be refused right now.",
        "not_hotspot": f"Connect the laptop only to the hotspot \"{HOTSPOT_SSID}\" and open this page again.",
        "no_network": "No active network found. Connect the laptop to the team's hotspot.",
        "command": "The command to run",
        "linux_note": "It asks for the administrator password only for nmap, which sends the packets.",
        "windows_note": "Open the terminal as administrator (right-click, Run as administrator).",
        "after": "The result then shows in the History, next to the earlier scans.",
        "details": "Technical details",
        "interface": "Interface",
        "address": "This laptop's address",
        "subnet": "Subnet (the only one allowed)",
        "gateway": "Gateway",
        "guardrail": "Guardrail",
        "what_nmap_does": "What nmap does",
        "nmap_lines": [
            "`-sS -sU -sV` with the safe `{script}` script (the titles of admin pages)",
            "at most {rate} packets per second",
            "the {top} most common TCP ports plus {extra}, and UDP {udp}",
            "without this laptop (`--exclude {ip}`), so it doesn't show as an unknown device",
            "at most {minutes} minutes per device (`--minutes`, at least {min_minutes}); a device not finished is "
            "named, since its results are missing",
        ],
    },
}


def render() -> None:
    settings = current()
    text = TEXT[settings.lang]
    st.title(text["title"])
    st.markdown(text["intro"])
    try:
        network = detect_network()
    except NetworkNotFound as exc:
        st.warning(f"⛔ {text['no_network']}")
        if settings.advanced:
            st.markdown(md(_in_language(str(exc), settings.lang)))  # not st.caption: 3.88:1 on light (FE-E2)
        _show_command(text)
        return
    ssid = wifi_ssid(network.interface)
    decision = check_scope(network.subnet, [network.subnet], True, ssid)
    st.subheader(text["network"])
    st.markdown(f"**{text['wifi']}:** {md(ssid) or text['no_wifi']} · **{text['subnet']}:** {md(network.subnet)}")
    if decision.allowed:
        st.success(text["allowed"])
    else:
        st.error(f"{text['refused']} {md(_in_language(decision.reason, settings.lang))}")
        if ssid != HOTSPOT_SSID:
            st.markdown(text["not_hotspot"])
    _show_command(text)
    if settings.advanced:
        _show_details(text, network, ssid, decision.reason, settings.lang)


def nmap_summary(lang: str, scanner_ip: str) -> list[str]:
    """What a live scan asks nmap to do, from the same constants conetuga/guard/scan.py builds its command with."""
    values = {
        "script": SAFE_SCRIPT,
        "rate": MAX_PACKETS_PER_SECOND,
        "rate_de": _de(MAX_PACKETS_PER_SECOND),
        "top": f"{TOP_TCP_PORTS:,}".replace(",", "." if lang == "ro" else ","),
        "top_de": _de(TOP_TCP_PORTS),
        "extra": ", ".join(str(port) for port in EXTRA_TCP_PORTS),
        "udp": ", ".join(str(port) for port in UDP_PORTS),
        "ip": scanner_ip,
        "minutes": DEFAULT_MINUTES,
        "min_minutes": MIN_MINUTES,
    }
    return [line.format(**values) for line in TEXT[lang]["nmap_lines"]]


def scan_command() -> str:
    """The command for this computer's system, run from the project folder (the package isn't installed)."""
    return WINDOWS_COMMAND if _on_windows() else LINUX_COMMAND


def _show_command(text: dict) -> None:
    st.subheader(text["command"])
    # Plain text: shell highlighting colours "--confirm" #00a4d4 on #f7f7f6 in the light theme, 2.69:1, under
    # WCAG AA's 4.5:1 (E's FE-E2 audit).
    st.code(scan_command(), language=None)
    st.markdown(text["windows_note"] if _on_windows() else text["linux_note"])
    st.markdown(text["after"])


def _show_details(text: dict, network, ssid: str, reason: str, lang: str) -> None:
    st.subheader(text["details"])
    rows = [(text["interface"], network.interface), (text["address"], network.ip), (text["subnet"], network.subnet),
            (text["gateway"], network.gateway), (text["wifi"], ssid or text["no_wifi"]),
            (text["guardrail"], _in_language(reason, lang))]
    st.markdown("\n".join(f"- **{label}:** {md(value)}" for label, value in rows))
    st.markdown(f"**{text['what_nmap_does']}:**\n" + "\n".join(f"- {line}" for line in nmap_summary(lang, network.ip)))


def _de(count: int) -> str:
    """Romanian puts "de" between a number of 20 or more and its noun ("100 de pachete"), except after 01 to 19
    ("101 pachete"). Only the Romanian lines use it."""
    return "de " if count >= 20 and (count % 100 == 0 or count % 100 >= 20) else ""


def _in_language(message: str, lang: str) -> str:
    """Our two-line messages hold Romanian first, then English (scope.py, network.py)."""
    lines = message.split("\n")
    return lines[0] if lang == "ro" or len(lines) == 1 else lines[1]


def _on_windows() -> bool:
    return sys.platform == "win32"
