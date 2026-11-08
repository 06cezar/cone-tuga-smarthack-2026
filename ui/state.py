"""The settings every page shares, in one place: the language, the mode (Simple with Tuga 🐢, Advanced with
Cone 🐇) and large text. ui/app.py draws them in the sidebar on every page; a page reads them with `current()` and never keeps its own
copy, so switching the language or the mode changes every page at once. The scan picked on Acasă is shared the same
way (`remember_scan`, `current_scan`), so every page shows the same scan."""
from dataclasses import dataclass

import streamlit as st

from ui.assets import guide_picture
from ui.style import LARGE_TEXT_CSS

LANGUAGES = {"Română": "ro", "English": "en"}  # shown name -> the code every contract takes
LANGUAGE_KEY = "language_choice"
ADVANCED_KEY = "advanced_mode"
LARGE_TEXT_KEY = "large_text"
SCAN_KEY = "scan_result"  # the scan picked on Acasă, shared with the other pages
DEFAULT_LANGUAGE = "Română"  # the brief's users are Romanian; English is one click away
SIDEBAR_PICTURE_PX = 48  # the guide's picture in the sidebar: an icon beside one line of text
GUIDE_NAMES = {"tuga": "🐢 **Tuga**", "cone": "🐇 **Cone**"}  # the same in both languages

TEXT = {
    "ro": {
        "advanced": "Avansat (Cone 🐇)",
        "advanced_help": "Pornit: Cone arată detaliile tehnice (porturi, dovezi, referințe). Oprit: Tuga explică simplu.",
        "simple_guide": "🐢 **Tuga** îți explică pe înțeles.",
        "advanced_guide": "🐇 **Cone** îți arată și detaliile tehnice.",
        "large_text": "🔍 Scris mare",
        "large_text_help": "Pornit: toată pagina e mai mare, ușor de citit și de la distanță. Oprit: mărimea obișnuită.",
    },
    "en": {
        "advanced": "Advanced (Cone 🐇)",
        "advanced_help": "On: Cone shows the technical details (ports, evidence, references). Off: Tuga explains simply.",
        "simple_guide": "🐢 **Tuga** explains it in plain words.",
        "advanced_guide": "🐇 **Cone** also shows the technical details.",
        "large_text": "🔍 Large text",
        "large_text_help": "On: the whole page is larger, easy to read even from a distance. Off: the usual size.",
    },
}


@dataclass(frozen=True)
class Settings:
    lang: str  # "ro" or "en"
    advanced: bool  # False: Simple mode with Tuga (the default); True: Advanced mode with Cone
    large_text: bool = False  # on: the whole page larger; off: the usual size (the default, ui/style.py says why)


def sidebar_settings() -> Settings:
    """Draws the language switch, the Advanced toggle and the large-text toggle in the sidebar, applies large text,
    and returns what they say."""
    with st.sidebar:
        choice = st.radio("Limba / Language", list(LANGUAGES), horizontal=True, key=LANGUAGE_KEY,
                          index=list(LANGUAGES).index(DEFAULT_LANGUAGE))
        lang = LANGUAGES[choice]
        advanced = st.toggle(TEXT[lang]["advanced"], key=ADVANCED_KEY, help=TEXT[lang]["advanced_help"])
        show_guide(guide_of(advanced), lang, TEXT[lang]["advanced_guide" if advanced else "simple_guide"],
                   SIDEBAR_PICTURE_PX)
        large_text = st.toggle(TEXT[lang]["large_text"], value=False, key=LARGE_TEXT_KEY,
                               help=TEXT[lang]["large_text_help"])
        if large_text:
            st.markdown(LARGE_TEXT_CSS, unsafe_allow_html=True)
    return Settings(lang=lang, advanced=advanced, large_text=large_text)


def guide_of(advanced: bool) -> str:
    """Who speaks in this mode: "tuga" in Simple mode, "cone" in Advanced mode (narrate's `speaker`)."""
    return "cone" if advanced else "tuga"


def show_guide(speaker: str, lang: str, words: str, picture_px: int, name_below: bool = False,
               widths: tuple[int, int] = (1, 4)) -> None:
    """The guide's picture (FE-E1) with words beside it. The guide is always named, in `words` or, with `name_below`,
    under the picture: never the picture alone, so a person who can't see it loses nothing (NFR-08). `words` is
    Markdown the caller made safe (our own text, or scan text through view.md)."""
    path, alt = guide_picture(speaker, lang)
    picture, text = st.columns(list(widths), vertical_alignment="center")  # picture : words
    picture.image(str(path), width=picture_px, alt=alt)
    if name_below:
        picture.markdown(GUIDE_NAMES[speaker])
    text.markdown(words)


def remember_scan(result) -> None:
    """Keep the scan Acasă just analysed (its FileResult, an error included) for this session, so the other pages show
    the same scan. Only in this session's memory: nothing is written anywhere (the history saves scans itself)."""
    st.session_state[SCAN_KEY] = result


def current_scan():
    """The FileResult Acasă last analysed in this session, or None before any scan was picked."""
    return st.session_state.get(SCAN_KEY)


def current() -> Settings:
    """The settings as the sidebar left them in this run (the defaults before it is drawn)."""
    choice = st.session_state.get(LANGUAGE_KEY, DEFAULT_LANGUAGE)
    return Settings(lang=LANGUAGES.get(choice, LANGUAGES[DEFAULT_LANGUAGE]),
                    advanced=bool(st.session_state.get(ADVANCED_KEY, False)),
                    large_text=bool(st.session_state.get(LARGE_TEXT_KEY, False)))
