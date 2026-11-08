"""Acasă: the first page. It answers "Which device is the most dangerous, and what should I do first?" (ui/CLAUDE.md),
then shows every device (Dispozitive, FE-D3, adds filters and order), the Q&A box and the report. Every scan shown is
saved to the history, which has its own page (Istoric, ui/pages/history.py).
Everything shown comes from analyse_file, narrate, answer_question and the history (specs/contracts.md); scan text is
escaped with view.md before display. In Simple mode Tuga 🐢 speaks; in Advanced mode Cone 🐇 adds what nmap saw."""
import sys
import tempfile
from datetime import date
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))  # ui/app.py already does this; kept so the page also imports on its own

from conetuga.analysis import analyse_file  # noqa: E402
from conetuga.explain import answer_question  # noqa: E402
from conetuga.explain.qa import MAX_QUESTION_CHARS  # noqa: E402
from conetuga.history import digest_of, load_history, save_scan  # noqa: E402
from conetuga.insights import record  # noqa: E402
from ui.cards import show_device  # noqa: E402
from ui.checkup import show_checklist, show_home_map  # noqa: E402
from ui.insights_panel import SEEN_KEY  # noqa: E402
from ui.report import html_report  # noqa: E402
from ui.state import SKIP_SAVE_KEY, current, page_link, remember_digest, remember_scan  # noqa: E402
from ui.dashboard import show_cone_dashboard, show_tuga_dashboard  # noqa: E402
from ui.style import PICKER_KEY  # noqa: E402
from ui.theme import HOME_TITLE_KEY  # noqa: E402
from ui.timeline import current_index, previous_index  # noqa: E402
from ui.view import devices_by_risk, md  # noqa: E402

HEADLINE_PICTURE_PX = 96  # the guide beside the headline: about as tall as its two lines of large text

EXAMPLE_FOLDERS = [REPO_ROOT / "tests" / "fixtures" / "validation" / "scans", REPO_ROOT / "lab" / "scans"]

TEXT = {
    "ro": {
        "title": "ConeTuga: securitate pe înțelesul tău",
        "start": "📂 Începe aici: alege o scanare",
        "start_help": "Un exemplu din listă sau fișierul tău de la nmap (`nmap -oX`): rezultatul apare imediat "
                      "dedesubt.",
        "pick": "Alege o scanare din exemple",
        "upload": "sau încarcă fișierul tău nmap XML",
        "unreadable": "Fișierul nu poate fi citit",
        "history_link": "📈 Istoric: vezi ce s-a schimbat față de scanările de dinainte",
        "devices": "Dispozitivele, de la cel mai periculos",
        "filters_elsewhere": "Pentru filtre (după risc sau tip) și altă ordine: pagina **Dispozitive** din meniul din "
                             "stânga.",
        "no_scan": "Alege sau încarcă o scanare ca să începi.",
        "report": "📄 Descarcă raportul (o pagină, pentru furnizorul IT sau asigurator)",
        "ask": "Întreabă despre rețeaua ta",
        "ask_label": "De exemplu: „Ce repar întâi?” sau „E periculos portul 9100 al imprimantei?”",
        "ask_source": "Răspunsul vine doar din această scanare, cu problemele pe care se sprijină.",
        "ask_invalid": "Scrie o întrebare de cel mult {limit} de caractere.",
    },
    "en": {
        "title": "ConeTuga: secure networks, simply explained",
        "start": "📂 Start here: pick a scan",
        "start_help": "An example from the list or your own nmap file (`nmap -oX`): the result appears right below.",
        "pick": "Pick an example scan",
        "upload": "or upload your own nmap XML file",
        "unreadable": "The file can't be read",
        "history_link": "📈 History: see what changed since your earlier scans",
        "devices": "Your devices, most dangerous first",
        "filters_elsewhere": "For filters (by risk or type) and another order: the **Devices** page in the menu on the "
                             "left.",
        "no_scan": "Pick or upload a scan to start.",
        "report": "📄 Download the report (one page, for your IT supplier or insurer)",
        "ask": "Ask about your network",
        "ask_label": "For example: \"What do I fix first?\" or \"Is my printer's port 9100 dangerous?\"",
        "ask_source": "The answer comes only from this scan, with the findings it relies on.",
        "ask_invalid": "Write a question of at most {limit} characters.",
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


def show_questions(result, lang: str) -> None:
    """FR-12: a question box answered by B's answer_question, from this scan only. The answer quotes findings as
    [ip:port CODE], and is escaped like every other text that carries scan data."""
    text = TEXT[lang]
    st.subheader(text["ask"])
    question = st.text_input(text["ask_label"], max_chars=MAX_QUESTION_CHARS)
    if not question.strip():
        return
    try:
        answer = answer_question(question, result, lang)
    except ValueError:
        st.warning(text["ask_invalid"].format(limit=MAX_QUESTION_CHARS))
        return
    st.info(md(answer.text))
    st.markdown(f"*{text['ask_source']}*")


def render() -> None:
    """The page itself; ui/app.py registers it in the navigation as the default page."""
    settings = current()
    lang, advanced = settings.lang, settings.advanced
    text = TEXT[lang]
    with st.container(key=HOME_TITLE_KEY):  # the logo shows the name; screen readers still read the title
        st.title(text["title"])

    # The page's main feature (Mihnea, 2026-11-08): choosing the scan, in a large box right under the title, styled by
    # ui/style.py through its key. The widgets are the same as before; only their box and size changed.
    examples = example_scans()
    names = [p.name for p in examples]
    with st.container(key=PICKER_KEY):
        st.markdown(f"### {text['start']}")
        left, right = st.columns(2, gap="large")
        picked = left.selectbox(text["pick"], names, index=names.index("V2_smart_home.xml")
                                if "V2_smart_home.xml" in names else 0) if names else None
        # The help sits behind the upload's "?" so the box stays short and the headline stays on the first screen of a
        # 1366×768 laptop, in a browser window (E's review of #71).
        upload = right.file_uploader(text["upload"], type=None, help=text["start_help"])

    if upload is not None:
        result, content = analyse_upload(upload), upload.getvalue()
    elif picked is not None:
        path = examples[names.index(picked)]
        result, content = analyse_file(path), path.read_bytes()
    else:
        st.info(text["no_scan"])
        return

    remember_scan(result)  # the other pages (Dispozitive) show this same scan, a broken one included
    if result.error:
        st.error(f"⛔ {text['unreadable']}: {md(result.error)}")
        return
    # The opt-in statistics (FE-A3): a readable scan counts once per session, and only if the person turned them on
    # (record checks that itself, inside its write).
    record(result, digest_of(content), st.session_state.setdefault(SEEN_KEY, set()))

    devices = devices_by_risk(result, lang)
    # The dashboard (ui/dashboard.py): Tuga's or Cone's, with the headline, the score and the guide.
    if advanced:
        show_cone_dashboard(result, devices, lang)
    else:
        show_tuga_dashboard(result, devices, lang)

    # Simple mode is a checkup (ui/checkup.py): the list of things to fix, then the home as device tiles. Advanced mode
    # lists every device with Cone's details.
    if not advanced:
        show_checklist(result, devices, lang)
        show_home_map(devices, lang)
        st.markdown(text["filters_elsewhere"])
    else:
        show_devices(result, devices, lang)

    show_questions(result, lang)
    compared = save_to_history(result, content)
    page_link("istoric", TEXT[lang]["history_link"])
    st.download_button(text["report"], html_report(result, lang, before=compared, date=date.today().isoformat()),
                       file_name=f"conetuga-{Path(result.file).stem}.html", mime="text/html")


def save_to_history(result, content: bytes):
    """FR-10: store the scan on screen (not again right after "delete my history" on Istoric, until another scan is
    picked) and remember its digest for Istoric. Returns the earlier scan of the same network the report compares
    with, the one Istoric's banner shows, or None."""
    digest = digest_of(content)
    if st.session_state.get(SKIP_SAVE_KEY) != digest:
        save_scan(result, content)
    remember_digest(digest)
    records = load_history()
    now = current_index(records, digest)
    if now is None or records[now].digest != digest:
        return None
    previous = previous_index(records, now)
    return None if previous is None else records[previous].result


def show_devices(result, devices, lang: str) -> None:
    """Advanced mode: every device as a card with Cone's details, the most dangerous first."""
    text = TEXT[lang]
    st.subheader(text["devices"])
    if devices:
        st.markdown(text["filters_elsewhere"])
    for i, device in enumerate(devices):
        show_device(device, lang, expanded=i == 0, advanced=True, result=result)
