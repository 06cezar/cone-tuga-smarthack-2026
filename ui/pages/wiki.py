"""The Common Threat Wiki (FE-B4, built by E on B's wiki_entries; drawn by Despre, ui/pages/about.py): every problem
ConeTuga can find, with a search box and a filter by severity, then five basic network ideas, as the current guide
tells them, with A's "most common problems" panel on top (FE-A3).

- Simple mode, Tuga 🐢: each problem's plain explanation and its 1-5 fix steps (B's `steps`, written without a scan).
- Advanced mode, Cone 🐇: Cone's technical text and the detection rule, read from data/catalog.toml (the nmap service
  names, the protocol, the outdated versions list), then the CIS Controls / OWASP IoT references.

No scan is needed and none is read. Every text is our own (data/wiki.toml, data/cone.toml, data/catalog.toml), never
scan text; it still goes through view.md. Each problem shows the catalog's own severity and points, with an icon and
words (NFR-08); the page computes no finding and no score."""
import streamlit as st

from conetuga.analysis.catalog import load_catalog
from conetuga.explain import wiki_entries
from ui.cards import mode_of
from ui.insights_panel import render_common_problems
from ui.state import current, guide_of, show_guide
from ui.theme import WIKI_FILTER_KEY
from ui.view import md, severity_label

GUIDE_PICTURE_PX = 64  # the guide beside the section's one-line introduction
CATALOG = load_catalog()  # severities, points, services and the outdated list: read from data/catalog.toml, never guessed
SEVERITY_OF = {rule.code: rule.severity for rule in CATALOG.rules}
SEVERITIES = tuple(CATALOG.severity_points)  # high, medium, low, info: the catalog's order
OUTDATED_CODE = "OUTDATED_SERVICE"
UNKNOWN_DEVICE_CODE = "UNKNOWN_DEVICE"
OUTDATED_SIGNS = {"equals": "=", "below": "<", "at_most": "≤"}  # catalog.OUTDATED_RULE_KINDS as a reader writes them
SEARCH_KEY = "wiki_search"  # the widgets' keys; the tests set them by these
SEVERITY_FILTER_KEY = "wiki_severity"

TEXT = {
    "ro": {
        "title": "📚 Common Threat Wiki: catalogul celor {count} probleme",
        "intro_tuga": "🐢 **Tuga** îți explică pe scurt fiecare problemă pe care o poate găsi ConeTuga și ce faci ca s-o "
                      "repari, plus câteva idei de bază despre rețele.",
        "intro_cone": "🐇 **Cone** îți arată fiecare problemă tehnic: regula de detecție din catalog, serviciul văzut de "
                      "nmap și referințele CIS Controls / OWASP IoT.",
        "search": "Caută în wiki",
        "search_hint": "🔍 De exemplu: telnet, cameră, imprimantă, TELNET_OPEN",
        "severity": "Arată doar severitatea",
        "shown": "Afișate: {shown} din {total} probleme.",
        "no_match": "Nicio problemă nu se potrivește cu căutarea și filtrul alese.",
        "codes": "Problemele pe care le poate găsi ConeTuga",
        "concepts": "Idei de bază despre rețele",
        "steps": "Ce faci, pas cu pas",
        "rule": "Regula de detecție",
        "rule_points": "Scade **{points}** puncte din scorul de 100 ({severity}).",
        "rule_services": "Serviciul raportat de nmap: {services}, pe orice port",
        "rule_udp": " (doar UDP)",
        "rule_no_ssl": "Doar fără criptare: nmap nu raportează `tunnel=\"ssl\"` pe port.",
        "rule_title": "Titlul paginii (scriptul nmap `http-title`) conține unul dintre: {words}.",
        "rule_one_per_device": "O singură problemă pe dispozitiv, pe primul port deschis dintre: {ports}.",
        "rule_outdated": "Orice serviciu al cărui produs și versiune (nmap `-sV`) sunt pe lista de versiuni vechi, în "
                         "plus față de problema serviciului, pe același port:",
        "rule_unknown": "O regulă despre dispozitiv, nu despre un port: nmap nu găsește nici producătorul plăcii de "
                        "rețea (după MAC), nici un nume, iar dispozitivul are cel puțin un port deschis. Coloana de "
                        "port rămâne goală.",
        "related": "Legat de",
        "references": "Referințe",
    },
    "en": {
        "title": "📚 Common Threat Wiki: the catalog of {count} problems",
        "intro_tuga": "🐢 **Tuga** explains, in a few words, every problem ConeTuga can find and how to fix it, plus a few "
                      "basic ideas about networks.",
        "intro_cone": "🐇 **Cone** shows every problem in technical terms: the catalog's detection rule, the service nmap "
                      "sees and the CIS Controls / OWASP IoT references.",
        "search": "Search the wiki",
        "search_hint": "🔍 For example: telnet, camera, printer, TELNET_OPEN",
        "severity": "Show only severity",
        "shown": "Showing {shown} of {total} problems.",
        "no_match": "No problem matches the chosen search and filter.",
        "codes": "The problems ConeTuga can find",
        "concepts": "Basic ideas about networks",
        "steps": "What to do, step by step",
        "rule": "Detection rule",
        "rule_points": "Takes **{points}** points off the score of 100 ({severity}).",
        "rule_services": "Service reported by nmap: {services}, on any port",
        "rule_udp": " (UDP only)",
        "rule_no_ssl": "Only without encryption: nmap reports no `tunnel=\"ssl\"` on the port.",
        "rule_title": "The page title (nmap's `http-title` script) contains one of: {words}.",
        "rule_one_per_device": "One finding per device, on the first open port among: {ports}.",
        "rule_outdated": "Any service whose product and version (nmap `-sV`) are on the outdated list, in addition to "
                         "the service's own finding, on the same port:",
        "rule_unknown": "A rule about a device, not a port: nmap finds neither the network card's maker (from the MAC) "
                        "nor a name, and the device has at least one open port. The port column stays empty.",
        "related": "Related to",
        "references": "References",
    },
}


def render() -> None:
    """The wiki section: its title, the guide's introduction, the common problems, the search and the severity
    filter, then the problems and the basic ideas that match."""
    settings = current()
    lang, advanced = settings.lang, settings.advanced
    text = TEXT[lang]
    entries = wiki_entries(lang, mode_of(advanced))
    titles = {entry.id: entry.title for entry in entries}
    codes = [entry for entry in entries if entry.kind == "code"]

    st.header(text["title"].format(count=len(codes)))
    show_guide(guide_of(advanced), lang, text["intro_cone" if advanced else "intro_tuga"], GUIDE_PICTURE_PX,
               widths=(1, 9))
    render_common_problems({entry.id: entry.title for entry in codes}, lang)

    with st.container(key=WIKI_FILTER_KEY):
        search, severity = st.columns((2, 3), vertical_alignment="bottom")
        query = search.text_input(text["search"], key=SEARCH_KEY, placeholder=text["search_hint"])
        chosen = severity.pills(text["severity"], SEVERITIES, selection_mode="multi", default=list(SEVERITIES),
                                key=SEVERITY_FILTER_KEY, format_func=lambda s: severity_chip(s, lang))
    allowed = set(chosen) or set(SEVERITIES)  # nothing picked means no filter, never an empty page

    st.subheader(text["codes"])
    shown = [entry for entry in codes if SEVERITY_OF[entry.id] in allowed and matches(entry, query)]
    st.markdown(text["shown"].format(shown=len(shown), total=len(codes)))
    if not shown:
        st.info(text["no_match"])
    for entry in shown:
        show_entry(entry, titles, lang, advanced)
    st.subheader(text["concepts"])
    for entry in entries:
        if entry.kind == "concept" and matches(entry, query):
            show_entry(entry, titles, lang, advanced)


def severity_chip(severity: str, lang: str) -> str:
    """A severity in the filter: its icon, its words and its points ("⛔ Risc mare · −20p")."""
    return f"{severity_label(severity, lang)} · {points_text(CATALOG.severity_points[severity])}"


def points_text(points: int) -> str:
    """What a problem costs, as the wiki writes it: "−20p", or "0p" for the informative ones."""
    return f"−{points}p" if points else "0p"


def matches(entry, query: str) -> bool:
    """Whether the search words are in the entry's id, title, text or steps (case-insensitive); empty keeps all."""
    words = query.strip().casefold()
    return not words or words in " ".join([entry.id, entry.title, entry.text, *entry.steps]).casefold()


def show_entry(entry, titles: dict[str, str], lang: str, advanced: bool) -> None:
    """One entry as a card: a problem with its severity and points (and, for Cone, its catalog code), its text, then
    Tuga's fix steps or Cone's detection rule, the entries it relates to by their titles, and its references."""
    text = TEXT[lang]
    if entry.kind == "code":
        severity = SEVERITY_OF[entry.id]
        code = f" · `{entry.id}`" if advanced else ""  # the catalog code, ours (never scan text): safe in backticks
        label = (f"{severity_label(severity, lang)} · {points_text(CATALOG.severity_points[severity])} · "
                 f"{md(entry.title)}{code}")
    else:
        label = md(entry.title)
    with st.expander(label):
        st.markdown(md(entry.text))
        if entry.kind == "code" and advanced:
            st.markdown(f"**{text['rule']}**\n" + "\n".join(f"- {line}" for line in detection_rule(entry.id, lang)))
        elif entry.steps:
            st.markdown(f"**{text['steps']}**\n" + "\n".join(f"{i}. {md(step)}"
                                                             for i, step in enumerate(entry.steps, start=1)))
        if entry.related_codes:
            st.markdown(f"**{text['related']}:** " + " · ".join(md(titles[code]) for code in entry.related_codes))
        if entry.references:
            st.markdown(f"*{text['references']}: {md(', '.join(entry.references))}*")


def detection_rule(code: str, lang: str) -> list[str]:
    """How analyse_file finds this code, in a reader's words, built only from data/catalog.toml's rule: the points,
    the nmap service names and protocol, the extra conditions, and the outdated versions list."""
    text = TEXT[lang]
    rule = CATALOG.rule(code)
    lines = [text["rule_points"].format(points=CATALOG.points(code), severity=severity_label(rule.severity, lang))]
    if rule.services:
        services = ", ".join(f"`{service}`" for service in sorted(rule.services))
        lines.append(text["rule_services"].format(services=services)
                     + (text["rule_udp"] if rule.protocol == "udp" else "") + ".")
    if rule.without_ssl:
        lines.append(text["rule_no_ssl"])
    if rule.title_keywords:
        lines.append(text["rule_title"].format(words=", ".join(f"`{word}`" for word in rule.title_keywords)))
    if rule.one_per_device:
        lines.append(text["rule_one_per_device"].format(ports=", ".join(str(port) for port in rule.preferred_ports)))
    if code == OUTDATED_CODE:
        lines.append(text["rule_outdated"] + " " + "; ".join(
            f"`{outdated.product} {OUTDATED_SIGNS[outdated.kind]} {outdated.limit}`" for outdated in CATALOG.outdated))
    if code == UNKNOWN_DEVICE_CODE:
        lines.append(text["rule_unknown"])
    return lines
