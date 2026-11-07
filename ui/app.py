"""The ConeTuga web page (FR-11): run with `streamlit run ui/app.py`.

The first screen answers "Which device is the most dangerous, and what should I do first?" (ui/CLAUDE.md). Everything
shown comes from analyse_file and explain (specs/contracts.md); scan text is escaped with view.md before display."""
import sys
import tempfile
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # `streamlit run ui/app.py` puts only ui/ on the path

from conetuga.analysis import analyse_file  # noqa: E402
from ui.view import devices_by_risk, headline, md, score_line, severity_label  # noqa: E402

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
    },
}


def example_scans() -> list[Path]:
    """The scan files we ship: the Validation Set and our masked lab captures."""
    return sorted(p for folder in EXAMPLE_FOLDERS if folder.is_dir() for p in folder.iterdir()
                  if p.is_file() and not p.name.startswith("."))


def analyse_upload(upload):
    """analyse_file on an uploaded file: written to a temporary folder under its own name (no path parts), read, and
    deleted. Nothing is kept."""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / (Path(upload.name).name or "upload.xml")
        path.write_bytes(upload.getvalue())
        return analyse_file(path)


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
        result = analyse_upload(upload)
    elif picked is not None:
        result = analyse_file(examples[names.index(picked)])
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


main()
