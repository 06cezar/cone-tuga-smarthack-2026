"""The settings every page shares, in one place: the language and the mode (Simple with Tuga 🐢, Advanced with
Cone 🐇). ui/app.py draws them in the sidebar on every page; a page reads them with `current()` and never keeps its own
copy, so switching the language or the mode changes every page at once."""
from dataclasses import dataclass

import streamlit as st

LANGUAGES = {"Română": "ro", "English": "en"}  # shown name -> the code every contract takes
LANGUAGE_KEY = "language_choice"
ADVANCED_KEY = "advanced_mode"
DEFAULT_LANGUAGE = "Română"  # the brief's users are Romanian; English is one click away

TEXT = {
    "ro": {
        "advanced": "Avansat (Cone 🐇)",
        "advanced_help": "Pornit: Cone arată detaliile tehnice (porturi, dovezi, referințe). Oprit: Tuga explică simplu.",
        "simple_guide": "🐢 **Tuga** îți explică pe înțeles.",
        "advanced_guide": "🐇 **Cone** îți arată și detaliile tehnice.",
    },
    "en": {
        "advanced": "Advanced (Cone 🐇)",
        "advanced_help": "On: Cone shows the technical details (ports, evidence, references). Off: Tuga explains simply.",
        "simple_guide": "🐢 **Tuga** explains it in plain words.",
        "advanced_guide": "🐇 **Cone** also shows the technical details.",
    },
}


@dataclass(frozen=True)
class Settings:
    lang: str  # "ro" or "en"
    advanced: bool  # False: Simple mode with Tuga (the default); True: Advanced mode with Cone


def sidebar_settings() -> Settings:
    """Draws the language switch and the Advanced toggle in the sidebar and returns what they say."""
    with st.sidebar:
        choice = st.radio("Limba / Language", list(LANGUAGES), horizontal=True, key=LANGUAGE_KEY,
                          index=list(LANGUAGES).index(DEFAULT_LANGUAGE))
        lang = LANGUAGES[choice]
        advanced = st.toggle(TEXT[lang]["advanced"], key=ADVANCED_KEY, help=TEXT[lang]["advanced_help"])
        st.markdown(TEXT[lang]["advanced_guide" if advanced else "simple_guide"])
    return Settings(lang=lang, advanced=advanced)


def current() -> Settings:
    """The settings as the sidebar left them in this run (the defaults before it is drawn)."""
    choice = st.session_state.get(LANGUAGE_KEY, DEFAULT_LANGUAGE)
    return Settings(lang=LANGUAGES.get(choice, LANGUAGES[DEFAULT_LANGUAGE]),
                    advanced=bool(st.session_state.get(ADVANCED_KEY, False)))
