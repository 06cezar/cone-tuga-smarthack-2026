"""The "Cele mai comune probleme" panel (FE-A3): the opt-in switch for the local statistics and the problems found most
often in the scans the person looked at, drawn on the Wiki page.

It only shows what `conetuga.insights` returns (contract "insights"): no finding, count or title is computed here.
The page that draws it passes the titles (B's `wiki_entries`, whose `id` is the catalog code), so the panel follows
the page's language and mode. A save the store refuses is reported from `set_enabled`'s own answer, never guessed
from `status()` before it (D's review of #50): the store can fail on the write even when it read fine."""
from dataclasses import dataclass

import streamlit as st

from conetuga.insights import STATUS_ON, STATUS_UNAVAILABLE, set_enabled, status, top_codes
from ui.view import md

ROMANIAN_DE_FROM = 20  # the Romanian rule for "de" after a number, see how_many_times
TOP_N = 5  # how many problems the panel lists: enough to see a pattern, short enough to read at a glance
SWITCH_KEY = "insights_switch"
# The session's set of scans already counted (the insights contract's `seen`): Acasă adds to it through record()
# and empties it with "Șterge istoricul meu". It lives only in this session, never on disk.
SEEN_KEY = "insights_seen"
SAVE_FAILED_KEY = "insights_save_failed"
WARNING_ICON = "⚠️"  # with the words, never alone (NFR-08); Streamlit draws it from `icon=`, not from the text

TEXT = {
    "ro": {
        "heading": "📊 Cele mai comune probleme",
        "about": "Doar pe acest calculator: numărăm doar tipurile de probleme (niciun IP, MAC sau nume), și numai dacă "
                 "pornești statisticile. „Șterge istoricul meu” le șterge și pe ele.",
        "switch": "Pornește statisticile locale",
        "unavailable": "Statisticile nu sunt disponibile acum: fișierul lor nu poate fi citit. Restul aplicației "
                       "merge normal.",
        "not_saved": "Alegerea nu a putut fi salvată (fișierul statisticilor nu poate fi scris). Nimic nu s-a "
                     "schimbat.",
        "off": "Statisticile sunt oprite. Pornește-le ca să vezi ce probleme apar cel mai des în scanările tale.",
        "empty": "Încă nimic de arătat: deschide o scanare și problemele ei apar aici.",
        "list_intro": "În scanările pe care le-ai deschis:",
        "times": "{count} ori",
        "times_with_de": "{count} de ori",  # Romanian: "20 de ori", "100 de ori", but "101 ori"
        "once": "o dată",
    },
    "en": {
        "heading": "📊 Most common problems",
        "about": "Only on this computer: we count only the kinds of problems (no IP, MAC or name), and only if you turn "
                 "statistics on. \"Delete my history\" deletes them too.",
        "switch": "Turn on local statistics",
        "unavailable": "Statistics aren't available right now: their file can't be read. The rest of the app works "
                       "as usual.",
        "not_saved": "Your choice couldn't be saved (the statistics file can't be written). Nothing changed.",
        "off": "Statistics are off. Turn them on to see which problems show up most often in your scans.",
        "empty": "Nothing to show yet: open a scan and its problems appear here.",
        "list_intro": "In the scans you looked at:",
        "times": "{count} times",
        "times_with_de": "{count} times",  # English has no "de"
        "once": "once",
    },
}


@dataclass(frozen=True)
class CommonProblem:
    code: str  # the catalog code, which is also the Wiki entry's id
    title: str  # what the person reads: the Wiki's title, or the code when the page gave none
    count: int  # how many times it was found in the counted scans


def common_problems(n: int, titles: dict[str, str]) -> list[CommonProblem]:
    """The n problems found most often, most first (insights.top_codes), each with the title the page gave for its
    code; the code itself when the page has no title for it."""
    return [CommonProblem(code=code, title=titles.get(code, code), count=count) for code, count in top_codes(n)]


def render_common_problems(titles: dict[str, str], lang: str) -> None:
    """Draws the panel: a heading, what the statistics keep, the opt-in switch, and the list (or why there is none)."""
    text = TEXT[lang]
    st.subheader(text["heading"])
    st.caption(text["about"])
    state = status()
    if state == STATUS_UNAVAILABLE:
        st.warning(text["unavailable"], icon=WARNING_ICON)
        return
    st.session_state[SWITCH_KEY] = state == STATUS_ON  # the switch always shows the store's real state
    st.toggle(text["switch"], key=SWITCH_KEY, on_change=_save_switch)
    if st.session_state.pop(SAVE_FAILED_KEY, False):
        st.error(text["not_saved"], icon=WARNING_ICON)
    if state != STATUS_ON:
        st.info(text["off"])
        return
    rows = common_problems(TOP_N, titles)
    if not rows:
        st.info(text["empty"])
        return
    lines = [f"{i}. {md(row.title)}: {how_many_times(row.count, lang)}"
             for i, row in enumerate(rows, start=1)]
    st.markdown(text["list_intro"] + "\n\n" + "\n".join(lines))


def how_many_times(count: int, lang: str) -> str:
    """"o dată", "3 ori", "20 de ori": Romanian puts "de" after a number whose last two digits are 00 or 20 and above
    ("20 de ori", "100 de ori", "120 de ori"), and not otherwise ("101 ori", "119 ori"). English: "once", "3 times"."""
    text = TEXT[lang]
    if count == 1:
        return text["once"]
    needs_de = count >= ROMANIAN_DE_FROM and (count % 100 == 0 or count % 100 >= ROMANIAN_DE_FROM)
    return text["times_with_de" if needs_de else "times"].format(count=count)


def _save_switch() -> None:
    """The switch's callback: save the new choice; if the store refuses it, remember to say so on this run."""
    if not set_enabled(bool(st.session_state[SWITCH_KEY])):
        st.session_state[SAVE_FAILED_KEY] = True
