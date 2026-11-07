"""One device card, shared by Acasă (the most dangerous device) and Dispozitive (every device). It shows what the device
is and, for each finding, what the current guide says through B's narrate (specs/contracts.md): Tuga 🐢 in Simple
mode, Cone 🐇 with the evidence in Advanced mode. Scan text is escaped with view.md before display (NFR-03); every
severity comes with an icon and words, never colour alone (NFR-08)."""
import streamlit as st

from conetuga.explain import narrate
from ui.view import DeviceView, device_status, md, severity_label, status_options

TEXT = {
    "ro": {
        "risk": "risc",
        "points": "puncte",
        "vendor": "Producător",
        "hostname": "Nume în rețea",
        "mac": "MAC (mascat)",
        "unknown": "necunoscut",
        "no_findings": "Nicio problemă găsită pe acest dispozitiv.",
        "steps": "Ce să faci",
        "port": "port",
        "references": "Referințe",
        "tuga": "🐢 **Tuga:**",
        "cone": "🐇 **Cone:**",
        "evidence": "Ce a văzut nmap (dovada)",
        "not_checked": "Neverificat: nmap a renunțat la acest dispozitiv înainte să-i verifice porturile, deci nu știm "
                       "dacă e sigur. Scanează din nou cu mai mult timp (--minutes).",
    },
    "en": {
        "risk": "risk",
        "points": "points",
        "vendor": "Maker",
        "hostname": "Network name",
        "mac": "MAC (masked)",
        "unknown": "unknown",
        "no_findings": "No problems found on this device.",
        "steps": "What to do",
        "port": "port",
        "references": "References",
        "tuga": "🐢 **Tuga:**",
        "cone": "🐇 **Cone:**",
        "evidence": "What nmap saw (the evidence)",
        "not_checked": "Not checked: nmap gave up on this device before checking its ports, so we don't know whether it "
                       "is safe. Scan again with more time (--minutes).",
    },
}


def mode_of(advanced: bool) -> str:
    """The `mode` narrate takes, from the sidebar's Advanced toggle (ui/state.py)."""
    return "advanced" if advanced else "simple"


def show_device(device: DeviceView, lang: str, expanded: bool, advanced: bool) -> None:
    """One device in an expander: its status (worst severity, or not checked, or no problems) with icon and words, its
    name and address, then each finding as the current guide tells it."""
    text = TEXT[lang]
    host = device.host
    status = dict(status_options(lang))[device_status(device)]
    label = f"{status} · {md(device.name)} · {host.ip} · {text['risk']} {device.risk} {text['points']}"
    with st.expander(label, expanded=expanded):
        st.markdown(
            f"**{text['hostname']}:** {md(host.hostname) or text['unknown']} · "
            f"**{text['vendor']}:** {md(host.vendor) or text['unknown']} · "
            f"**{text['mac']}:** {md(host.mac_masked) or text['unknown']}"
        )
        if host.timed_out:
            st.warning(f"⏳ {text['not_checked']}")
        elif not device.findings:
            st.markdown(text["no_findings"])
        for view in device.findings:
            show_finding(view.finding, host, lang, advanced)


def show_finding(finding, host, lang: str, advanced: bool) -> None:
    """A finding as narrate tells it: the title with its severity and port, the guide's words, the steps, Cone's
    evidence in Advanced mode, and the CIS Controls / OWASP IoT references in both modes (the contract's choice)."""
    text = TEXT[lang]
    told = narrate(finding, host, lang, mode_of(advanced))
    where = f" · {text['port']} {finding.port}/{md(finding.proto)}" if finding.port is not None else ""
    code = f" · `{finding.code}`" if advanced else ""  # the catalog code, ours (never scan text): safe in backticks
    st.markdown(f"#### {severity_label(finding.severity, lang)} · {md(told.title)}{where}{code}")
    st.markdown(f"{text[told.speaker]} {md(told.text)}")
    st.markdown(f"**{text['steps']}:**\n" + "\n".join(f"{i}. {md(step)}" for i, step in enumerate(told.steps, start=1)))
    if told.evidence:
        st.markdown(f"**{text['evidence']}:**\n" + "\n".join(f"- {md(line)}" for line in told.evidence))
    if told.references:
        st.markdown(f"*{text['references']}: {md(', '.join(told.references))}*")
