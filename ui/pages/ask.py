"""Întreabă (FE-B5): a chat about the scan picked on Acasă, answered by B's reply() (specs/contracts.md, section reply)
from that scan only, with the findings each answer relies on. The conversation stays in this session's memory and is
cleared when another scan is picked; nothing is written anywhere.

Every text is shown through view.md: the answers carry scan text (hostnames, products), and the question is the
user's own untrusted text (NFR-03)."""
import streamlit as st

from conetuga.explain import reply
from conetuga.explain.assistant import ASSISTANT, MAX_MESSAGES, USER
from conetuga.explain.qa import MAX_QUESTION_CHARS
from ui.assets import guide_picture
from ui.cards import mode_of
from ui.state import current, current_scan, guide_of, show_guide
from ui.view import md

GUIDE_PICTURE_PX = 64  # the guide beside the page's one-line introduction, as on the Wiki page
MESSAGES_KEY = "ask_messages"  # the conversation: [{"role", "text", "source"}], oldest first
SCAN_KEY = "ask_scan"  # which scan the conversation is about: a new scan starts a new conversation

TEXT = {
    "ro": {
        "title": "Întreabă",
        "intro_tuga": "🐢 **Tuga** îți răspunde la întrebări despre rețeaua ta, doar din scanarea aleasă.",
        "intro_cone": "🐇 **Cone** îți răspunde la întrebări despre rețeaua ta, doar din scanarea aleasă, cu problemele "
                      "pe care se sprijină.",
        "no_scan": "Alege mai întâi o scanare pe pagina Acasă: apoi poți întreba aici despre ea.",
        "unreadable": "Fișierul nu poate fi citit",
        "placeholder": "De exemplu: „Ce repar întâi?” sau „E periculos portul 9100 al imprimantei?”",
        "invalid": "Scrie o întrebare de cel mult {limit} de caractere.",
        "source_retrieval": "Răspunsul vine doar din această scanare și din textele noastre, cu problemele pe care se "
                            "sprijină.",
        "clear": "Șterge conversația",
    },
    "en": {
        "title": "Ask",
        "intro_tuga": "🐢 **Tuga** answers questions about your network, from the chosen scan only.",
        "intro_cone": "🐇 **Cone** answers questions about your network, from the chosen scan only, with the findings "
                      "each answer relies on.",
        "no_scan": "First pick a scan on the Home page: then you can ask about it here.",
        "unreadable": "The file can't be read",
        "placeholder": "For example: \"What do I fix first?\" or \"Is my printer's port 9100 dangerous?\"",
        "invalid": "Write a question of at most {limit} characters.",
        "source_retrieval": "The answer comes only from this scan and our own texts, with the findings it relies on.",
        "clear": "Clear the conversation",
    },
}


def render() -> None:
    settings = current()
    lang, advanced = settings.lang, settings.advanced
    text = TEXT[lang]
    st.title(text["title"])
    show_guide(guide_of(advanced), lang, text["intro_cone" if advanced else "intro_tuga"], GUIDE_PICTURE_PX,
               widths=(1, 9))

    result = current_scan()
    if result is None:
        st.info(text["no_scan"])
        return
    if result.error:
        st.error(f"⛔ {text['unreadable']}: {md(result.error)}")
        return

    messages = conversation_about(result)
    for message in messages:
        show_message(message, lang, advanced)

    question = st.chat_input(text["placeholder"], max_chars=MAX_QUESTION_CHARS)
    if question:
        asked = {"role": USER, "text": question}
        # Only the latest messages go to reply(): the page may keep talking longer than one call accepts.
        try:
            answer = reply((messages + [asked])[-MAX_MESSAGES:], result, lang, mode_of(advanced))
        except ValueError:
            st.warning(text["invalid"].format(limit=MAX_QUESTION_CHARS))
        else:
            said = {"role": ASSISTANT, "text": answer.text, "source": answer.source}
            messages += [asked, said]
            show_message(asked, lang, advanced)
            show_message(said, lang, advanced)

    if messages and st.button(text["clear"]):
        messages.clear()
        st.rerun()


def conversation_about(result) -> list[dict]:
    """This session's conversation about `result`, started afresh when another scan is picked on Acasă. Scans are
    compared by value: the same file analysed again on a rerun is the same scan."""
    if st.session_state.get(SCAN_KEY) != result:
        st.session_state[SCAN_KEY] = result
        st.session_state[MESSAGES_KEY] = []
    return st.session_state[MESSAGES_KEY]


def show_message(message: dict, lang: str, advanced: bool) -> None:
    """One chat bubble: the user's question or the guide's answer (with the guide's picture), always through md()."""
    if message["role"] == USER:
        with st.chat_message(USER):
            st.markdown(md(message["text"]))
        return
    path, _alt = guide_picture(guide_of(advanced), lang)
    with st.chat_message(ASSISTANT, avatar=str(path)):
        st.markdown(md(message["text"]))
        st.markdown(f"*{TEXT[lang]['source_retrieval']}*")
