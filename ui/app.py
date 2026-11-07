"""The ConeTuga web page (FR-11): run with `streamlit run ui/app.py`.

The first screen answers "Which device is the most dangerous, and what should I do first?" (ui/CLAUDE.md); below it,
the history compares the scan with an earlier one. Everything shown comes from analyse_file, explain and the history
(specs/contracts.md); scan text is escaped with view.md before display."""
import sys
import tempfile
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # `streamlit run ui/app.py` puts only ui/ on the path

from conetuga.analysis import analyse_file  # noqa: E402
from conetuga.explain import explain  # noqa: E402
from conetuga.history import delete_history, diff, digest_of, load_history, save_scan  # noqa: E402
from ui.view import device_name, devices_by_risk, headline, md, score_line, severity_label  # noqa: E402

# After "delete my history", the scan on screen is not saved again until the user picks another one.
SKIP_SAVE_KEY = "history_skip_digest"
DELETED_KEY = "history_just_deleted"
TIME_OF_DAY = slice(11, 16)  # "HH:MM" inside an ISO timestamp "2026-11-07T16:40:12"

# NFR-08 asks for text of at least 16 px; Streamlit draws widget labels, radio options, buttons and expander titles at
# 14 px. max(1rem, 1em) lifts small text to 16 px and leaves headings as large as they are. A fixed style, with no scan
# text in it.
MIN_TEXT_CSS = """<style>
.stApp p, .stApp span, .stApp label, .stApp small, .stApp li, .stApp button { font-size: max(1rem, 1em) !important; }
</style>"""

EXAMPLE_FOLDERS = [REPO_ROOT / "tests" / "fixtures" / "validation" / "scans", REPO_ROOT / "lab" / "scans"]
LANGUAGE_CHOICES = {"Română": "ro", "English": "en"}

TEXT = {
    "ro": {
        "title": "ConeTuga: cât de sigură e rețeaua ta?",
        "pick": "Alege o scanare din exemple",
        "upload": "sau încarcă fișierul tău nmap XML",
        "unreadable": "Fișierul nu poate fi citit",
        "score": "Scor standard",
        "devices": "Dispozitivele, de la cel mai periculos",
        "risk": "risc",
        "points": "puncte",
        "type": "Tip",
        "vendor": "Producător",
        "hostname": "Nume în rețea",
        "mac": "MAC (mascat)",
        "unknown": "necunoscut",
        "no_findings": "Nicio problemă găsită pe acest dispozitiv.",
        "steps": "Ce să faci",
        "port": "port",
        "references": "Referințe",
        "no_scan": "Alege sau încarcă o scanare ca să începi.",
        "history": "Istoric: înainte și după",
        "history_where": "Fiecare scanare analizată e păstrată doar pe acest calculator.",
        "history_empty": "Istoricul e gol.",
        "first_scan": "Aceasta e prima scanare din istoric. Repară ceva, scanează din nou și vezi aici diferența.",
        "compare_with": "Compară cu scanarea de la",
        "better": "mai bine",
        "worse": "mai rău",
        "same": "la fel",
        "alert": "Atenție, ceva nou în rețea",
        "new_device": "Dispozitiv nou",
        "opened_port": "Port nou deschis",
        "resolved": "Rezolvate",
        "removed_device": "Dispozitive care nu mai apar",
        "closed_port": "Porturi închise",
        "nothing_changed": "Nicio schimbare față de scanarea aleasă.",
        "delete": "🗑️ Șterge istoricul meu",
        "deleted": "Istoricul a fost șters de pe acest calculator.",
    },
    "en": {
        "title": "ConeTuga: how safe is your network?",
        "pick": "Pick an example scan",
        "upload": "or upload your own nmap XML file",
        "unreadable": "The file can't be read",
        "score": "Standard score",
        "devices": "Your devices, most dangerous first",
        "risk": "risk",
        "points": "points",
        "type": "Type",
        "vendor": "Maker",
        "hostname": "Network name",
        "mac": "MAC (masked)",
        "unknown": "unknown",
        "no_findings": "No problems found on this device.",
        "steps": "What to do",
        "port": "port",
        "references": "References",
        "no_scan": "Pick or upload a scan to start.",
        "history": "History: before and after",
        "history_where": "Every analysed scan is kept only on this computer.",
        "history_empty": "The history is empty.",
        "first_scan": "This is the first scan in the history. Fix something, scan again, and see the difference here.",
        "compare_with": "Compare with the scan from",
        "better": "better",
        "worse": "worse",
        "same": "the same",
        "alert": "Watch out, something new on the network",
        "new_device": "New device",
        "opened_port": "Newly opened port",
        "resolved": "Resolved",
        "removed_device": "Devices no longer seen",
        "closed_port": "Closed ports",
        "nothing_changed": "Nothing changed compared with the chosen scan.",
        "delete": "🗑️ Delete my history",
        "deleted": "Your history was deleted from this computer.",
    },
}


def example_scans() -> list[Path]:
    """The scan files we ship: the Validation Set and our masked lab captures."""
    return sorted(p for folder in EXAMPLE_FOLDERS if folder.is_dir() for p in folder.iterdir()
                  if p.is_file() and not p.name.startswith("."))


def analyse_upload(upload):
    """analyse_file on an uploaded file: written to a temporary folder under its own name (no path parts), read, and
    deleted. Only the analysis goes into the history."""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / (Path(upload.name).name or "upload.xml")
        path.write_bytes(upload.getvalue())
        return analyse_file(path)


def show_history(result, content: bytes, lang: str) -> None:
    """FR-10 and FR-13: store this scan, show the score trend, compare with an earlier scan, and offer to delete."""
    text = TEXT[lang]
    st.subheader(text["history"])
    digest = digest_of(content)
    if st.session_state.get(SKIP_SAVE_KEY) != digest:
        save_scan(result, content)
    if st.session_state.pop(DELETED_KEY, False):
        st.success(text["deleted"])
    records = load_history()
    if not records:
        st.markdown(text["history_empty"])
        return
    st.markdown(text["history_where"])
    st.markdown("\n".join(f"- {r.saved_at[TIME_OF_DAY]} · {md(r.file)} · {score_line(r.result.score, lang)[0]} "
                          f"{r.result.score}/100" for r in records))
    if len(records) > 1:
        st.line_chart({text["score"]: [r.result.score for r in records]})

    current = next((i for i, r in enumerate(records) if r.digest == digest), len(records))
    earlier = records[:current]
    if not earlier:
        st.markdown(text["first_scan"])
    else:
        choice = st.selectbox(text["compare_with"], range(len(earlier)), index=len(earlier) - 1,
                              format_func=lambda i: f"{earlier[i].saved_at[TIME_OF_DAY]} · {earlier[i].file}")
        show_diff(earlier[choice].result, result, lang)

    if st.button(text["delete"]):
        delete_history()
        st.session_state[SKIP_SAVE_KEY] = digest
        st.session_state[DELETED_KEY] = True
        st.rerun()


def show_diff(before, after, lang: str) -> None:
    text = TEXT[lang]
    change = diff(before, after)
    delta = change.score_after - change.score_before
    trend = text["better"] if delta > 0 else text["worse"] if delta < 0 else text["same"]
    arrow = "⬆️" if delta > 0 else "⬇️" if delta < 0 else "➡️"
    st.markdown(f"### {arrow} {text['score']}: {change.score_before} → {change.score_after} ({delta:+d}, {trend})")

    alerts = [f"{text['new_device']}: {md(device_name(h, lang))} ({h.ip})" for h in change.new_devices]
    alerts += [f"{text['opened_port']}: {p.port}/{p.proto} · {md(device_name(h, lang))} ({h.ip})"
               for h, p in change.opened_ports]
    if alerts:
        st.warning(f"🚨 **{text['alert']}**\n\n" + "\n".join(f"- {a}" for a in alerts))

    hosts_before = {h.ip: h for h in before.hosts}
    sections = [
        (f"✅ {text['resolved']}", [f"{md(explain(f, hosts_before[f.ip], lang).title)} · "
                                    f"{md(device_name(hosts_before[f.ip], lang))} ({f.ip})"
                                    for f in change.resolved_findings]),
        (f"➖ {text['removed_device']}", [f"{md(device_name(h, lang))} ({h.ip})" for h in change.removed_devices]),
        (f"🔒 {text['closed_port']}", [f"{p.port}/{p.proto} · {md(device_name(h, lang))} ({h.ip})"
                                      for h, p in change.closed_ports]),
    ]
    shown = [(title, items) for title, items in sections if items]
    if not shown and not alerts:
        st.markdown(text["nothing_changed"])
    for title, items in shown:
        st.markdown(f"**{title} ({len(items)})**\n" + "\n".join(f"- {item}" for item in items))


def show_device(device, lang: str, expanded: bool) -> None:
    text = TEXT[lang]
    host = device.host
    label = f"{md(device.name)} · {host.ip} · {text['risk']} {device.risk} {text['points']}"
    with st.expander(label, expanded=expanded):
        st.markdown(
            f"**{text['hostname']}:** {md(host.hostname) or text['unknown']} · "
            f"**{text['vendor']}:** {md(host.vendor) or text['unknown']} · "
            f"**{text['mac']}:** {md(host.mac_masked) or text['unknown']}"
        )
        if not device.findings:
            st.markdown(text["no_findings"])
        for view in device.findings:
            finding, explanation = view.finding, view.explanation
            where = f" · {text['port']} {finding.port}/{finding.proto}" if finding.port is not None else ""
            st.markdown(f"#### {severity_label(finding.severity, lang)} · {md(explanation.title)}{where}")
            st.markdown(md(explanation.text))
            st.markdown(f"**{text['steps']}:**\n" + "\n".join(f"{i}. {md(step)}"
                                                           for i, step in enumerate(explanation.steps, start=1)))
            if explanation.references:
                st.markdown(f"*{text['references']}: {md(', '.join(explanation.references))}*")


def main() -> None:
    st.set_page_config(page_title="ConeTuga", page_icon="🛡️", layout="wide")
    st.markdown(MIN_TEXT_CSS, unsafe_allow_html=True)
    lang = LANGUAGE_CHOICES[st.radio("Limba / Language", list(LANGUAGE_CHOICES), horizontal=True)]
    text = TEXT[lang]
    st.title(text["title"])

    examples = example_scans()
    names = [p.name for p in examples]
    left, right = st.columns(2)
    picked = left.selectbox(text["pick"], names, index=names.index("V2_smart_home.xml")
                            if "V2_smart_home.xml" in names else 0) if names else None
    upload = right.file_uploader(text["upload"], type=None)

    if upload is not None:
        result, content = analyse_upload(upload), upload.getvalue()
    elif picked is not None:
        path = examples[names.index(picked)]
        result, content = analyse_file(path), path.read_bytes()
    else:
        st.info(text["no_scan"])
        return

    if result.error:
        st.error(f"⛔ {text['unreadable']}: {md(result.error)}")
        return

    devices = devices_by_risk(result, lang)
    st.markdown(f"## {md(headline(devices, lang))}")
    icon, colour, sentence = score_line(result.score, lang)
    st.markdown(f"### {icon} {text['score']}: {result.score}/100 · {colour}. {sentence}")

    st.subheader(text["devices"])
    for i, device in enumerate(devices):
        show_device(device, lang, expanded=i == 0)

    show_history(result, content, lang)


main()
