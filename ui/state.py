"""The settings every page shares, in one place: the language, the mode (Simple with Tuga 🐢, Advanced with
Cone 🐇). ui/app.py draws them in the top bar on every page; a page reads them with `current()` and never keeps its own
copy, so switching the language or the mode changes every page at once. The scan picked on Acasă is shared the same
way (`remember_scan`, `current_scan`), so every page shows the same scan."""
from dataclasses import dataclass

import streamlit as st

from ui.assets import guide_picture
from ui.theme import LANG_KEY, MODE_KEY

LANGUAGES = {"Română": "ro", "English": "en"}  # shown name -> the code every contract takes
LANGUAGE_KEY = "language_choice"
ADVANCED_KEY = "advanced_mode"
SCAN_KEY = "scan_result"  # the scan picked on Acasă, shared with the other pages
DIGEST_KEY = "scan_digest"  # the SHA-256 of that scan file, so Istoric knows which record it is
# After "delete my history" on Istoric, Acasă doesn't save the scan on screen again until another one is picked.
SKIP_SAVE_KEY = "history_skip_digest"
PAGES_KEY = "pages_by_path"  # ui/app.py's pages by URL path, for links between pages
DEFAULT_LANGUAGE = "Română"  # the brief's users are Romanian; English is one click away
SHORT_NAMES = {"Română": "RO", "English": "EN"}  # what the RO | EN switch shows
TOPBAR_PICTURE_PX = 34  # the current guide in the top bar: an icon beside one line of text
TOPBAR_GUIDE_WIDTHS = (1, 6)  # its picture : its sentence
GUIDE_NAMES = {"tuga": "🐢 **Tuga**", "cone": "🐇 **Cone**"}  # the same in both languages

TEXT = {
    "ro": {
        "advanced": "🐇 Cone (Avansat)",
        "tuga_side": "🐢 Tuga (Simplu)",
        "advanced_help": "Pornit: Cone arată detaliile tehnice (porturi, dovezi, referințe). Oprit: Tuga explică simplu.",
        "simple_guide": "🐢 **Tuga** îți explică pe înțeles.",
        "advanced_guide": "🐇 **Cone** îți arată și detaliile tehnice.",
    },
    "en": {
        "advanced": "🐇 Cone (Advanced)",
        "tuga_side": "🐢 Tuga (Simple)",
        "advanced_help": "On: Cone shows the technical details (ports, evidence, references). Off: Tuga explains simply.",
        "simple_guide": "🐢 **Tuga** explains it in plain words.",
        "advanced_guide": "🐇 **Cone** also shows the technical details.",
    },
}


@dataclass(frozen=True)
class Settings:
    lang: str  # "ro" or "en"
    advanced: bool  # False: Simple mode with Tuga (the default); True: Advanced mode with Cone


def topbar_settings(mode_column, language_column) -> Settings:
    """Draws the settings in the top bar (ui/app.py), as in the mock-ups: the Tuga | Cone switch with the current guide
    under it, and RO | EN. Returns what they say. The language comes first in the code because the other
    labels need it; on the page it sits after the switch."""
    with language_column, st.container(key=LANG_KEY):
        choice = st.radio("Limba / Language", list(LANGUAGES), horizontal=True, key=LANGUAGE_KEY,
                          index=list(LANGUAGES).index(DEFAULT_LANGUAGE), format_func=SHORT_NAMES.get,
                          label_visibility="collapsed")
    lang = LANGUAGES[choice]
    was_advanced = bool(st.session_state.get(ADVANCED_KEY, False))
    with mode_column, st.container(key=MODE_KEY):
        switch = st.container(horizontal=True, vertical_alignment="center", gap="small")
        with switch, st.container(key=f"{MODE_KEY}-tuga-{'off' if was_advanced else 'on'}", width="content"):
            st.markdown(TEXT[lang]["tuga_side"])
        with switch, st.container(key=f"{MODE_KEY}-cone-{'on' if was_advanced else 'off'}", width="content"):
            advanced = st.toggle(TEXT[lang]["advanced"], key=ADVANCED_KEY, help=TEXT[lang]["advanced_help"])
        show_guide(guide_of(advanced), lang, TEXT[lang]["advanced_guide" if advanced else "simple_guide"],
                   TOPBAR_PICTURE_PX, widths=TOPBAR_GUIDE_WIDTHS)
    return Settings(lang=lang, advanced=advanced)


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


def remember_digest(digest: str) -> None:
    """Keep the digest of the scan file Acasă shows, so Istoric marks that record as "now" and compares with it."""
    st.session_state[DIGEST_KEY] = digest


def current_digest() -> str | None:
    """The digest Acasă last remembered, or None before any scan was picked."""
    return st.session_state.get(DIGEST_KEY)


def page_link(url_path: str, label: str) -> None:
    """A link to another page of the app, by its URL path ("istoric"). A page drawn on its own (the tests) has no
    navigation, so it shows no link instead of failing."""
    page = st.session_state.get(PAGES_KEY, {}).get(url_path)
    if page is not None:
        st.page_link(page, label=label)


def current_scan():
    """The FileResult Acasă last analysed in this session, or None before any scan was picked."""
    return st.session_state.get(SCAN_KEY)


def current() -> Settings:
    """The settings as the top bar left them in this run (the defaults before it is drawn)."""
    choice = st.session_state.get(LANGUAGE_KEY, DEFAULT_LANGUAGE)
    return Settings(lang=LANGUAGES.get(choice, LANGUAGES[DEFAULT_LANGUAGE]),
                    advanced=bool(st.session_state.get(ADVANCED_KEY, False)))
