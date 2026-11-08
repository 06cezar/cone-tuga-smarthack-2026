"""One device card, shared by Acasă (the most dangerous device) and Dispozitive (every device). It shows what the device
is and, for each finding, what the current guide says through B's narrate (specs/contracts.md): Tuga 🐢 in Simple
mode, Cone 🐇 with the evidence in Advanced mode. Scan text is escaped with view.md before display (NFR-03); every
severity comes with an icon and words, never colour alone (NFR-08)."""
import streamlit as st

from conetuga.explain import narrate
from ui.motion import page_is_dark
from ui.state import current
from ui.style import CARD_KEY, GAIN_KEY, SAY_KEY, block_key
from ui.view import DeviceView, device_status, ip_md, md, score_if_fixed, severity_label, status_options
from ui.voice import HEIGHT_PX as VOICE_HEIGHT_PX, read_aloud_html, spoken_text

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
        "recognise": "Ca să-l recunoști",
        "more_steps": "Mai sunt {n} pași în modul Avansat.",
        "problems": {0: "nicio problemă", 1: "1 problemă"},
        "problems_many": "{n} probleme",
        "tell_helper": "Dacă ceri ajutor cuiva, spune-i",
        "fix_gain": "🔧 **Ce-ar fi dacă repar?** Scorul urcă de la {before} la {after} (+{gain}).",
        "not_checked_simple": "Neverificat: nu am putut verifica acest aparat, deci nu știm dacă e sigur. Scanează din "
                              "nou mai târziu.",
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
        "recognise": "To recognise it",
        "more_steps": "{n} more steps in Advanced mode.",
        "problems": {0: "no problems", 1: "1 problem"},
        "problems_many": "{n} problems",
        "tell_helper": "If you ask someone for help, tell them",
        "fix_gain": "🔧 **What if I fix it?** The score goes up from {before} to {after} (+{gain}).",
        "not_checked_simple": "Not checked: we couldn't check this device, so we don't know whether it is safe. Scan "
                              "again a bit later.",
        "port": "port",
        "references": "References",
        "tuga": "🐢 **Tuga:**",
        "cone": "🐇 **Cone:**",
        "evidence": "What nmap saw (the evidence)",
        "not_checked": "Not checked: nmap gave up on this device before checking its ports, so we don't know whether it "
                       "is safe. Scan again with more time (--minutes).",
    },
}


# Simple mode (Tuga) is for a 12-year-old or a grandparent (NFR-09): the few steps that matter most, no evidence or
# references, and the port only as a line to tell a helper; Advanced mode (Cone) shows everything.
SIMPLE_STEPS = 3


def problem_count(n: int, lang: str) -> str:
    """ "nicio problemă", "1 problemă", "3 probleme": the number of findings in words, for the Simple-mode label."""
    return TEXT[lang]["problems"].get(n) or TEXT[lang]["problems_many"].format(n=n)


def mode_of(advanced: bool) -> str:
    """The `mode` narrate takes, from the sidebar's Advanced toggle (ui/state.py)."""
    return "advanced" if advanced else "simple"


def show_device(device: DeviceView, lang: str, expanded: bool, advanced: bool, result=None) -> None:
    """One device in an expander: its status (worst severity, or not checked, or no problems) with icon and words, its
    name and address, then each finding as the current guide tells it. Simple mode counts the problems in words instead
    of points and puts the network name, maker and masked MAC (FR-03) at the end, as a way to recognise the device;
    Advanced mode shows them first, with the points. With the scan's `result`, each finding also says how much the
    score would rise if it were fixed."""
    text = TEXT[lang]
    host = device.host
    status = dict(status_options(lang))[device_status(device)]
    details = (f"**{text['hostname']}:** {md(host.hostname) or text['unknown']} · "
               f"**{text['vendor']}:** {md(host.vendor) or text['unknown']} · "
               f"**{text['mac']}:** {md(host.mac_masked) or text['unknown']}")
    if advanced:
        label = f"{status} · {md(device.name)} · {ip_md(host.ip)} · {text['risk']} {device.risk} {text['points']}"
    else:
        label = f"{status} · {md(device.name)} · {ip_md(host.ip)} · {problem_count(len(device.findings), lang)}"
    # The card's key carries its status, so ui/style.py colours its band; the address keeps the key unique.
    with st.container(key=block_key(CARD_KEY, device_status(device), host.ip)), st.expander(label, expanded=expanded):
        if advanced:
            st.markdown(details)
        if host.timed_out:
            st.warning(f"⏳ {text['not_checked'] if advanced else text['not_checked_simple']}")
        elif not device.findings:
            st.markdown(text["no_findings"])
        for view in device.findings:
            show_finding(view.finding, host, lang, advanced, result)
        if not advanced:
            st.markdown(f"*{text['recognise']}:* {details}")


def show_finding(finding, host, lang: str, advanced: bool, result=None) -> None:
    """A finding as narrate tells it. Simple mode: the title with its severity, Tuga's words, the first SIMPLE_STEPS
    steps, and the port on one last line to tell whoever helps. Advanced mode puts the port and code in the
    title and adds every step, Cone's evidence and the CIS Controls / OWASP IoT references. In both modes, with the
    scan's `result`: what the score would be once this is fixed; in Simple mode, a button for Tuga to read it aloud."""
    text = TEXT[lang]
    told = narrate(finding, host, lang, mode_of(advanced))
    if advanced:
        where = f" · {text['port']} {finding.port}/{md(finding.proto)}" if finding.port is not None else ""
        code = f" · `{finding.code}`"  # the catalog code, ours (never scan text): safe in backticks
    else:
        where = code = ""
    st.markdown(f"#### {severity_label(finding.severity, lang)} · {md(told.title)}{where}{code}")
    where_key = (finding.ip, finding.port, finding.proto, finding.code)  # unique on the page: one finding, once
    with st.container(key=block_key(SAY_KEY, told.speaker, *where_key)):  # the guide's speech bubble
        st.markdown(f"{text[told.speaker]} {md(told.text)}")
    steps = told.steps if advanced else told.steps[:SIMPLE_STEPS]
    st.markdown(f"**{text['steps']}:**\n" + "\n".join(f"{i}. {md(step)}" for i, step in enumerate(steps, start=1)))
    if not advanced:
        spoken = spoken_text(told.title, told.text, text["steps"], steps)
        st.components.v1.html(read_aloud_html(spoken, lang, dark=page_is_dark(current())), height=VOICE_HEIGHT_PX)
    if len(told.steps) > len(steps):
        st.markdown(f"*{text['more_steps'].format(n=len(told.steps) - len(steps))}*")
    if result is not None:
        after = score_if_fixed(result, finding)
        if after > result.score:  # nothing to promise while the other findings still hold the score at 0
            with st.container(key=block_key(GAIN_KEY, *where_key)):
                st.markdown(text["fix_gain"].format(before=result.score, after=after, gain=after - result.score))
    if not advanced and finding.port is not None:
        # The port, for the adult or technician who helps: kept out of the title, one line at the end. No catalog code
        # for Tuga (tests/test_ui_app.py).
        st.markdown(f"*{text['tell_helper']}:* {text['port']} {finding.port}/{md(finding.proto)}")
    if advanced and told.evidence:
        st.markdown(f"**{text['evidence']}:**\n" + "\n".join(f"- {md(line)}" for line in told.evidence))
    if advanced and told.references:
        st.markdown(f"*{text['references']}: {md(', '.join(told.references))}*")
