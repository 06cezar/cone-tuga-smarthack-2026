"""Cone's technical audit on Acasă in Advanced mode (after the dark mock-up): one row per device with its address,
masked MAC, name, open ports, services and versions, findings by severity and the CIS Controls / OWASP IoT references,
with a search box over every column.

The table is our own HTML: every piece of scan text in it goes through html.escape, so a hostname, a version or a
protocol can never become a tag or a link (NFR-03); the MAC is only ever the masked one (the parser keeps no other)."""
import html

import streamlit as st

from conetuga.explain import narrate
from ui.theme import AUDIT_KEY
from ui.view import DeviceView, SEVERITY_ICON, TEXT as VIEW_TEXT, device_status

SEARCH_KEY = "audit_search"
NONE = "—"

TEXT = {
    "ro": {
        "title": "Audit tehnic al dispozitivelor",
        "mode": "Mod avansat",
        "line": "**{devices}** dispozitive scanate · **{findings}** probleme · scor **{score}/100**",
        "search": "Caută în tabel",
        "search_hint": "🔍 Caută (IP, aparat, port, cod…)",
        "privacy": "🔒 MAC mascat",
        "columns": ("Adresă IP", "MAC mascat", "Dispozitiv / hostname", "Porturi deschise", "Serviciu / versiune",
                    "Probleme și risc", "Referințe"),
        "no_findings": "✅ Fără probleme",
        "no_match": "Niciun dispozitiv nu se potrivește căutării.",
    },
    "en": {
        "title": "Technical device audit",
        "mode": "Advanced mode",
        "line": "**{devices}** devices scanned · **{findings}** findings · score **{score}/100**",
        "search": "Search the table",
        "search_hint": "🔍 Search (IP, device, port, code…)",
        "privacy": "🔒 Masked MAC",
        "columns": ("IP address", "Masked MAC", "Device / hostname", "Open ports", "Service / version",
                    "Findings & severity", "References"),
        "no_findings": "✅ No problems",
        "no_match": "No device matches the search.",
    },
}


def short_reference(reference: str) -> str:
    """ "CIS Controls v8.1 4.8" -> "CIS v8.1 4.8", so a reference fits in one chip."""
    return reference.replace("CIS Controls ", "CIS ")


def audit_rows(devices: list[DeviceView], lang: str) -> list[dict[str, object]]:
    """One row per device, the riskiest first, as plain text (escaped only when drawn)."""
    rows = []
    for device in devices:
        host = device.host
        references: list[str] = []
        findings = []
        for view in device.findings:
            finding = view.finding
            findings.append((finding.severity, finding.code, VIEW_TEXT[lang][f"severity_{finding.severity}"]))
            for reference in narrate(finding, host, lang, "advanced").references:
                if short_reference(reference) not in references:
                    references.append(short_reference(reference))
        services = []
        for port in host.ports:
            words = " ".join(part for part in (port.service, port.product, port.version) if part)
            if words and words not in services:
                services.append(words)
        rows.append({
            "ip": host.ip,
            "mac": host.mac_masked or NONE,
            "device": device.name,
            "ports": ", ".join(f"{p.port}/{p.proto}" for p in host.ports) or NONE,
            "services": "; ".join(services) or NONE,
            "findings": findings,
            "references": references,
            "status": device_status(device),
        })
    return rows


def matches(row: dict[str, object], query: str) -> bool:
    """Whether a row holds the search words anywhere (case-insensitive); an empty search keeps every row."""
    words = query.strip().casefold()
    if not words:
        return True
    text = " ".join([str(row[k]) for k in ("ip", "mac", "device", "ports", "services")]
                    + [code for _severity, code, _word in row["findings"]] + list(row["references"]))
    return words in text.casefold()


def table_html(rows: list[dict[str, object]], lang: str) -> str:
    """The audit as one HTML block; every value is escaped."""
    text = TEXT[lang]
    e = html.escape
    head = "".join(f"<th>{e(column)}</th>" for column in text["columns"])
    body = []
    for row in rows:
        badges = "".join(
            f'<span class="ct-finding ct-finding-{severity}">{SEVERITY_ICON[severity]} {e(code)} ({e(word)})</span>'
            for severity, code, word in row["findings"]) or f'<span class="ct-finding ct-finding-none">{e(text["no_findings"])}</span>'
        refs = "".join(f'<span class="ct-ref">{e(reference)}</span>' for reference in row["references"]) or NONE
        body.append(
            f'<tr><td class="ct-ip">{e(str(row["ip"]))}</td><td class="ct-mono">{e(str(row["mac"]))}</td>'
            f'<td>{e(str(row["device"]))}</td><td class="ct-mono">{e(str(row["ports"]))}</td>'
            f'<td>{e(str(row["services"]))}</td><td>{badges}</td><td>{refs}</td></tr>')
    return (f'<div class="ct-table-wrap"><table class="ct-table"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def show_audit(result, devices: list[DeviceView], lang: str) -> None:
    """The audit card: its title and mode badge, the scan in one line, the search box and the table."""
    text = TEXT[lang]
    rows = audit_rows(devices, lang)
    findings = sum(len(row["findings"]) for row in rows)
    with st.container(key=AUDIT_KEY):
        st.markdown(f'<div class="ct-audit-head"><span class="ct-audit-title">{html.escape(text["title"])}</span>'
                    f'<span class="ct-badge-mode">{html.escape(text["mode"])}</span></div>', unsafe_allow_html=True)
        st.markdown(text["line"].format(devices=len(rows), findings=findings, score=result.score))
        search, privacy = st.columns((4, 1), vertical_alignment="center")
        query = search.text_input(text["search"], key=SEARCH_KEY, placeholder=text["search_hint"],
                                  label_visibility="collapsed")
        privacy.markdown(f'<span class="ct-pill">{html.escape(text["privacy"])}</span>', unsafe_allow_html=True)
        shown = [row for row in rows if matches(row, query)]
        if shown:
            st.markdown(table_html(shown, lang), unsafe_allow_html=True)
        else:
            st.markdown(text["no_match"])
