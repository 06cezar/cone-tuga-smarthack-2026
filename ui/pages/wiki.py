"""Wiki amenințări (FE-B4, the page built by E for D on top of B's wiki_entries): what each problem ConeTuga can find
and five basic network ideas mean, as the current guide tells them (Tuga 🐢 in Simple mode, Cone 🐇 in Advanced
mode), with A's "most common problems" panel at the top (FE-A3).

No scan is needed and none is read. Every text is our own (data/wiki.toml, data/cone.toml), never scan text; it still
goes through view.md like every other text on a page. Each problem shows the catalog's own severity, with an icon and
words (NFR-08); the page computes no finding and no score."""
import streamlit as st

from conetuga.analysis.catalog import load_catalog
from conetuga.explain import wiki_entries
from ui.cards import mode_of
from ui.insights_panel import render_common_problems
from ui.state import current, guide_of, show_guide
from ui.view import md, severity_label

GUIDE_PICTURE_PX = 64  # the guide beside the page's one-line introduction
SEVERITY_OF = {rule.code: rule.severity for rule in load_catalog().rules}  # read from data/catalog.toml, never guessed

TEXT = {
    "ro": {
        "title": "Wiki amenințări",
        "intro_tuga": "🐢 **Tuga** îți explică pe scurt fiecare problemă pe care o poate găsi ConeTuga, plus câteva idei "
                      "de bază despre rețele.",
        "intro_cone": "🐇 **Cone** îți arată fiecare problemă tehnic: serviciul, regula din catalog și de ce contează.",
        "codes": "Problemele pe care le poate găsi ConeTuga",
        "concepts": "Idei de bază despre rețele",
        "related": "Legat de",
        "references": "Referințe",
    },
    "en": {
        "title": "Threat wiki",
        "intro_tuga": "🐢 **Tuga** explains, in a few words, every problem ConeTuga can find, plus a few basic ideas about "
                      "networks.",
        "intro_cone": "🐇 **Cone** shows every problem in technical terms: the service, the catalog rule and why it "
                      "matters.",
        "codes": "The problems ConeTuga can find",
        "concepts": "Basic ideas about networks",
        "related": "Related to",
        "references": "References",
    },
}


def render() -> None:
    settings = current()
    lang, advanced = settings.lang, settings.advanced
    text = TEXT[lang]
    entries = wiki_entries(lang, mode_of(advanced))
    titles = {entry.id: entry.title for entry in entries}

    st.title(text["title"])
    show_guide(guide_of(advanced), lang, text["intro_cone" if advanced else "intro_tuga"], GUIDE_PICTURE_PX,
               widths=(1, 9))
    render_common_problems({entry.id: entry.title for entry in entries if entry.kind == "code"}, lang)

    st.subheader(text["codes"])
    for entry in entries:
        if entry.kind == "code":
            show_entry(entry, titles, lang, advanced)
    st.subheader(text["concepts"])
    for entry in entries:
        if entry.kind == "concept":
            show_entry(entry, titles, lang, advanced)


def show_entry(entry, titles: dict[str, str], lang: str, advanced: bool) -> None:
    """One entry in an expander: a problem with its severity (and, for Cone, its catalog code), its text, the entries
    it relates to by their titles, and its CIS Controls / OWASP IoT references."""
    text = TEXT[lang]
    if entry.kind == "code":
        code = f" · `{entry.id}`" if advanced else ""  # the catalog code, ours (never scan text): safe in backticks
        label = f"{severity_label(SEVERITY_OF[entry.id], lang)} · {md(entry.title)}{code}"
    else:
        label = md(entry.title)
    with st.expander(label):
        st.markdown(md(entry.text))
        if entry.related_codes:
            st.markdown(f"**{text['related']}:** " + " · ".join(md(titles[code]) for code in entry.related_codes))
        if entry.references:
            st.markdown(f"*{text['references']}: {md(', '.join(entry.references))}*")
