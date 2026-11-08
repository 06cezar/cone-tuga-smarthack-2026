"""Scanare: the network this computer is on (FR-01), whether the guardrail would allow a live scan of it (FR-02), a
"Scanează acum" button, and the same scan as a terminal command.

The button calls only scan_from_app (specs/contracts.md), which asks the guardrail first and gives administrator rights
to nmap alone, through the system's own password window; the app itself stays an ordinary user (NFR-04) and never
sees a password. The page puts no text of its own into the scan: the target is always the connected subnet, and the
tick is the CLI's --confirm. The scan then lands in the history (FR-10) exactly as a terminal scan does.

The network is read the same way the live scan reads it (detect_network, wifi_ssid, check_scope), so the page and the
scan always agree. A Wi-Fi name and nmap's messages are outside text: they are escaped before display (NFR-03)."""
import sqlite3
import sys

import streamlit as st

from conetuga import ledger
from conetuga.analysis import analyse_file
from conetuga.guard import HOTSPOT_SSID, NetworkNotFound, check_scope, detect_network, wifi_ssid
from conetuga.guard.env_file import settings_with_env_file
from conetuga.guard.scan import (DEFAULT_MINUTES, EXTRA_TCP_PORTS, MAX_PACKETS_PER_SECOND, MIN_MINUTES, SAFE_SCRIPT,
                                 TOP_TCP_PORTS, UDP_PORTS, PasswordWindowRefused, ScanError, ScanRefused,
                                 scan_from_app)
from conetuga.history import save_scan
from ui.state import current
from ui.view import md

LINUX_COMMAND = ".venv/bin/python -m conetuga scan --confirm"
WINDOWS_COMMAND = r".venv\Scripts\python -m conetuga scan --confirm"
RETRY_FACTOR = 2  # as the CLI: a device that ran out of time gets twice the minutes on the next try
LEDGER_COMMAND = "app"  # how the findings log records where a finding came from (CLI: "scan", "analyse")

TEXT = {
    "ro": {
        "title": "Scanare live",
        "intro": "Aici scanezi rețeaua la care ești conectat, doar pe hotspotul echipei. Doar nmap primește drepturi "
                 "de administrator, prin fereastra de parolă a sistemului; aplicația nu le primește niciodată.",
        "network": "Rețeaua ta",
        "wifi": "Wi-Fi",
        "no_wifi": "niciunul",
        "allowed": "✅ Ești pe hotspotul echipei: scanarea acestei rețele este permisă.",
        "refused": "⛔ Scanarea ar fi refuzată acum.",
        "not_hotspot": f"Conectează laptopul doar la hotspotul „{HOTSPOT_SSID}” și deschide din nou pagina.",
        "no_network": "Nu găsesc nicio rețea activă. Conectează laptopul la hotspotul echipei.",
        "scan_now_title": "Scanează acum",
        "tick": "Confirm că vreau să scanez rețeaua asta",
        "scan_now": "🔍 Scanează acum",
        "button_off": "Butonul pornește doar pe hotspotul echipei, după ce bifezi confirmarea.",
        "linux_window": "Sistemul îți cere parola de administrator într-o fereastră a lui, doar pentru nmap.",
        "windows_window": "Windows îți cere acordul în fereastra lui (UAC), doar pentru nmap.",
        "scanning": "Scanez rețeaua... durează câteva minute (cel mult {minutes} minute pe dispozitiv).",
        "use_terminal": "Poți rula aceeași scanare din terminal, cu comanda de mai jos.",
        "done": "✅ Scanare gata: scor {score}, {devices}, {findings}.",
        "device": ("dispozitiv", "dispozitive"),
        "finding": ("problemă", "probleme"),
        "go_home": "Deschide **Acasă** din meniu: noua scanare apare acolo, comparată cu cea de dinainte.",
        "not_saved": "Scanarea nu a putut fi salvată în istoric ({reason}); rezultatul de mai sus rămâne valabil.",
        "not_logged": "Jurnalul de constatări nu a putut fi scris ({reason}).",
        "anchoring": "Trimit amprentele jurnalului pe blockchain...",
        "anchored": "🔗 Blockchain: am trimis amprentele lotului/loturilor {batches} (câte 10 constatări); ultima "
                    "tranzacție: {transaction}. Le verifici cu `ledger verify`.",
        "nothing_to_anchor": "🔗 Blockchain: niciun lot nou de 10 constatări de trimis acum; constatările noi așteaptă "
                             "în jurnal până se strâng 10.",
        "not_anchored": "Amprentele nu au ajuns pe blockchain; constatările rămân în jurnalul de pe acest calculator.",
        "timed_out": "⚠️ {device} nu a terminat în {minutes} minute, deci rezultatele lui lipsesc: „nicio problemă” "
                     "nu e adevărat pentru el. Rulează din terminal cu --minutes {retry}.",
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
        "intro": "Here you scan the network you're connected to, on the team's hotspot only. Only nmap gets "
                 "administrator rights, through the system's password window; the app itself never gets them.",
        "network": "Your network",
        "wifi": "Wi-Fi",
        "no_wifi": "none",
        "allowed": "✅ You're on the team's hotspot: scanning this network is allowed.",
        "refused": "⛔ A scan would be refused right now.",
        "not_hotspot": f"Connect the laptop only to the hotspot \"{HOTSPOT_SSID}\" and open this page again.",
        "no_network": "No active network found. Connect the laptop to the team's hotspot.",
        "scan_now_title": "Scan now",
        "tick": "I confirm I want to scan this network",
        "scan_now": "🔍 Scan now",
        "button_off": "The button works only on the team's hotspot, once you tick the confirmation.",
        "linux_window": "The system asks for the administrator password in its own window, for nmap only.",
        "windows_window": "Windows asks for your consent in its own window (UAC), for nmap only.",
        "scanning": "Scanning the network... this takes a few minutes (at most {minutes} minutes per device).",
        "use_terminal": "You can run the same scan from a terminal, with the command below.",
        "done": "✅ Scan finished: score {score}, {devices}, {findings}.",
        "device": ("device", "devices"),
        "finding": ("finding", "findings"),
        "go_home": "Open **Home** from the menu: the new scan shows there, compared with the one before.",
        "not_saved": "The scan couldn't be saved to the history ({reason}); the result above still stands.",
        "not_logged": "The findings log couldn't be written ({reason}).",
        "anchoring": "Sending the findings log's fingerprints to the blockchain...",
        "anchored": "🔗 Blockchain: sent the fingerprints of batch(es) {batches} (10 findings each); last transaction: "
                    "{transaction}. Check them with `ledger verify`.",
        "nothing_to_anchor": "🔗 Blockchain: no new batch of 10 findings to send yet; new findings wait in the log "
                             "until there are 10.",
        "not_anchored": "The fingerprints didn't reach the blockchain; the findings stay in this computer's log.",
        "timed_out": "⚠️ {device} didn't finish within {minutes} minutes, so its results are missing: \"no findings\" "
                     "isn't true for it. Run it from a terminal with --minutes {retry}.",
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
    _show_scan_button(text, decision.allowed, settings.lang)
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


def _show_scan_button(text: dict, allowed: bool, lang: str) -> None:
    """The tick and the button. Both stay off unless the guardrail allows the network shown above; scan_from_app
    asks the guardrail again anyway, so a stale page can't scan a network the laptop has since left."""
    st.subheader(text["scan_now_title"])
    confirmed = st.checkbox(text["tick"], key="scan_confirmed", disabled=not allowed)
    st.markdown(text["windows_window"] if _on_windows() else text["linux_window"])
    pressed = st.button(text["scan_now"], type="primary", disabled=not (allowed and confirmed))
    if not (allowed and confirmed):
        st.markdown(text["button_off"])
    if pressed:
        _scan_now(text, confirmed, lang)


def _scan_now(text: dict, confirmed: bool, lang: str) -> None:
    """Runs the scan, then does what the CLI's `scan --confirm` does with it: the analysis, the history (FR-10), the
    findings log, and a warning for every device nmap gave up on."""
    with st.spinner(text["scanning"].format(minutes=DEFAULT_MINUTES)):
        try:
            scan = scan_from_app(confirmed)
        except PasswordWindowRefused as exc:
            st.warning(f"{md(_in_language(str(exc), lang))} {text['use_terminal']}")
            return
        except (ScanRefused, NetworkNotFound, ScanError) as exc:
            st.error(f"⛔ {md(_in_language(str(exc), lang))} {text['use_terminal']}")
            return
        result = analyse_file(scan.xml)
    if result.error:
        st.error(f"⛔ {md(result.error)}")
        return
    st.success(text["done"].format(score=result.score,
                                   devices=_count(len(result.hosts), text["device"], lang),
                                   findings=_count(len(result.findings), text["finding"], lang)))
    try:
        save_scan(result, scan.xml.read_bytes())
    except OSError as exc:
        st.warning(text["not_saved"].format(reason=md(exc.strerror or str(exc))))
    try:
        ledger.record_findings([result], LEDGER_COMMAND)
    except (OSError, sqlite3.Error) as exc:
        st.warning(text["not_logged"].format(reason=md(str(exc))))
    else:
        _anchor(text, lang)
    for device in scan.timed_out:
        st.warning(text["timed_out"].format(device=md(device), minutes=scan.minutes,
                                            retry=scan.minutes * RETRY_FACTOR))
    st.markdown(text["go_home"])


def _anchor(text: dict, lang: str) -> None:
    """When the chain is set up (exported, or in .env like the CLI reads it), sends the findings log's full batches
    the chain doesn't hold yet, as the CLI's `scan` does. With no chain set up the log stays on this computer and the
    page says nothing; a chain that refuses or can't be reached is only a warning: the scan above still stands."""
    settings = ledger.settings_from_env(settings_with_env_file())
    if settings is None:
        return
    with st.spinner(text["anchoring"]):
        try:
            sent = ledger.anchor_pending(settings)
        except ledger.LedgerError as exc:  # its message never holds the key or the RPC URL (chain.py redacts them)
            st.warning(f"{text['not_anchored']} {md(_in_language(str(exc), lang))}")
            return
    if not sent:
        st.markdown(text["nothing_to_anchor"])
        return
    first, last = sent[0][0], sent[-1][0]
    st.markdown(text["anchored"].format(batches=first if first == last else f"{first}–{last}",
                                        transaction=md(sent[-1][1])))


def _count(count: int, forms: tuple[str, str], lang: str) -> str:
    """ "1 problemă", "2 probleme", "20 de probleme"; "1 finding", "2 findings"."""
    one, many = forms
    if count == 1:
        return f"1 {one}"
    return f"{count} {_de(count) if lang == 'ro' else ''}{many}"


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
