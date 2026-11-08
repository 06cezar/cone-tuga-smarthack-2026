"""Istoric (FR-10, FR-13, FR-15, NFR-02): every scan analysed on this computer, on two columns.

- On top, the change banner (FR-13): what changed between the scan on screen and the newest earlier scan of the same
  network (`same_network`, so two unrelated networks are never compared on their own), and the red "Șterge istoricul
  meu" button on the right (NFR-02).
- Left: the score over time for this network, then the list of every stored scan; in Advanced mode, the standard
  export (findings.csv and scores.csv for a folder of scans, C's `export`).
- Right: the before/after comparator, any two scans face to face, the findings fixed since marked "Rezolvat". Tuga 🐢
  sums up the progress in plain words (Simple mode); Cone 🐇 lists every port, service and code that changed (Advanced
  mode).

Everything comes from load_history, diff, explain and export (specs/contracts.md); scan text is escaped with view.md
(Markdown) or html.escape (HTML) before display, and the page computes no finding and no score."""
import html
import itertools
import tempfile
from pathlib import Path

import streamlit as st

from conetuga.explain import explain
from conetuga.guard.export import FINDINGS_FILE, SCORES_FILE, ExportError, export
from conetuga.history import delete_history, diff, load_history
from ui.insights_panel import SEEN_KEY
from ui.pages.home import EXAMPLE_FOLDERS
from ui.state import SKIP_SAVE_KEY, current, current_digest, page_link, show_guide
from ui.theme import (HISTORY_BANNER_KEY, HISTORY_COMPARE_KEY, HISTORY_DELETE_KEY, HISTORY_EXPORT_KEY, HISTORY_KEY,
                      HISTORY_LIST_KEY, HISTORY_SAY_KEY, HISTORY_TREND_KEY, TREND_LINE_KEY)
from ui.timeline import current_index, previous_index
from ui.view import device_name, ip_md, light, md, same_network, score_line

DELETED_KEY = "history_just_deleted"  # shows "deleted" once, after the rerun the delete button starts
BEFORE_KEY = "history_before"  # the comparator's two boxes; the tests set them by these keys
AFTER_KEY = "history_after"
EXPORT_FOLDER_KEY = "history_export_folder"
TIME_OF_DAY = slice(11, 16)  # "HH:MM" inside an ISO timestamp "2026-11-07T16:40:12"
COLUMN_WIDTHS = (1, 1.25)  # the trend and the list : the comparator, which holds two cards side by side
TREND_CHART_PX = 260
GUIDE_PICTURE_PX = 56  # the guide beside its summary of the comparison
# Each comparison drawn gets its own number, so its containers' keys stay unique when a page shows two of them.
COMPARISON_NUMBERS = itertools.count()

TEXT = {
    "ro": {
        "title": "📈 Istoric: înainte și după",
        "delete": "🗑️ Șterge istoricul meu",
        "delete_help": "Șterge de pe acest calculator toate scanările păstrate și statisticile. Nu se poate anula.",
        "deleted": "Istoricul a fost șters de pe acest calculator.",
        "empty": "Istoricul e gol. Alege sau încarcă o scanare pe pagina Acasă: fiecare scanare analizată e păstrată "
                 "aici, doar pe acest calculator.",
        "go_home": "🏠 Mergi la Acasă",
        "banner": "🔔 Ce s-a schimbat",
        "banner_since": "De la scanarea #{before} ({before_time}, {before_file}) la scanarea #{after} ({after_time}, "
                        "{after_file}):",
        "first_scan": "Aceasta e prima scanare din istoric. Repară ceva, scanează din nou și vezi aici diferența.",
        "no_match": "Nicio scanare mai veche nu are aceleași dispozitive ca aceasta (doar cu unele adăugate sau "
                    "scoase), deci nu comparăm singuri. Dacă e aceeași rețea, alege scanarea în comparatorul de mai "
                    "jos.",
        "chip_new": "dispozitive noi",
        "chip_removed": "dispozitive dispărute",
        "chip_opened": "porturi deschise",
        "chip_closed": "porturi închise",
        "chip_resolved": "probleme rezolvate",
        "alert": "Atenție, ceva nou în rețea",
        "new_device": "Dispozitiv nou",
        "opened_port": "Port nou deschis",
        "trend": "📈 Evoluția scorului",
        "trend_axis": "Scanarea nr.",
        "score": "Scor standard",
        "trend_one": "Doar o scanare din această rețea până acum. După o reparație, scanează din nou și vezi linia "
                     "urcând.",
        "list": "🗂️ Scanările păstrate",
        "list_where": "Fiecare scanare analizată e păstrată doar pe acest calculator.",
        "now": "⬅️ acum",
        "compare": "⚖️ Înainte vs. după",
        "before_box": "Înainte",
        "after_box": "După",
        "pick": "Alege o scanare",
        "pick_before": "Alege în stânga scanarea cu care compari.",
        "same_scan": "Ai ales aceeași scanare de două ori: alege alta în stânga.",
        "before_card": "Înainte",
        "after_card": "După",
        "risk_green": "Securizat!",
        "risk_yellow": "Risc mediu",
        "risk_red": "Risc mare",
        "active_threats": "{n} probleme active",
        "resolved_tag": "REZOLVAT",
        "new_tag": "NOU",
        "better": "mai bine",
        "worse": "mai rău",
        "same": "la fel",
        "tuga_up": "Bravo! Scorul a urcat de la **{before}** la **{after}** (+{delta}). Ai reparat **{resolved}** "
                   "probleme.",
        "tuga_down": "Atenție: scorul a coborât de la **{before}** la **{after}** ({delta}). Au apărut **{new}** "
                     "probleme noi.",
        "tuga_same": "Scorul a rămas **{after}**.",
        "tuga_left": "Mai sunt **{left}** probleme de reparat: le găsești pe pagina Acasă, cu pașii lor.",
        "tuga_none_left": "Nu mai e nicio problemă de reparat. 🎉",
        "resolved": "Rezolvate",
        "removed_device": "Dispozitive care nu mai apar",
        "closed_port": "Porturi închise",
        "nothing_changed": "Nicio schimbare între cele două scanări.",
        "log": "Jurnal tehnic al schimbărilor",
        "log_columns": ["Schimbare", "Dispozitiv", "Port", "Serviciu", "Cod"],
        "log_new_device": "➕ dispozitiv nou",
        "log_removed_device": "➖ dispozitiv dispărut",
        "log_opened": "🔓 port deschis",
        "log_closed": "🔒 port închis",
        "log_resolved": "✅ rezolvat",
        "log_new_finding": "❗ problemă nouă",
        "export": "📦 Export standard (FR-15)",
        "export_help": "findings.csv și scores.csv pentru un folder întreg de scanări, exact în formatul cerut de "
                       "concurs (aceleași fișiere ca `python -m conetuga analyse <folder> --out <folder>`).",
        "export_folder": "Folderul cu scanări",
        "export_failed": "Exportul nu a mers",
    },
    "en": {
        "title": "📈 History: before and after",
        "delete": "🗑️ Delete my history",
        "delete_help": "Deletes every stored scan and the statistics from this computer. It can't be undone.",
        "deleted": "Your history was deleted from this computer.",
        "empty": "The history is empty. Pick or upload a scan on the Home page: every analysed scan is kept here, "
                 "only on this computer.",
        "go_home": "🏠 Go to Home",
        "banner": "🔔 What changed",
        "banner_since": "From scan #{before} ({before_time}, {before_file}) to scan #{after} ({after_time}, "
                        "{after_file}):",
        "first_scan": "This is the first scan in the history. Fix something, scan again, and see the difference here.",
        "no_match": "No earlier scan has the same devices as this one (only with some added or removed), so we don't "
                    "compare on our own. If it is the same network, pick that scan in the comparator below.",
        "chip_new": "new devices",
        "chip_removed": "devices gone",
        "chip_opened": "ports opened",
        "chip_closed": "ports closed",
        "chip_resolved": "problems resolved",
        "alert": "Watch out, something new on the network",
        "new_device": "New device",
        "opened_port": "Newly opened port",
        "trend": "📈 Score over time",
        "trend_axis": "Scan no.",
        "score": "Standard score",
        "trend_one": "Only one scan of this network so far. After a fix, scan again and watch the line go up.",
        "list": "🗂️ Stored scans",
        "list_where": "Every analysed scan is kept only on this computer.",
        "now": "⬅️ now",
        "compare": "⚖️ Before vs. after",
        "before_box": "Before",
        "after_box": "After",
        "pick": "Pick a scan",
        "pick_before": "Pick the scan to compare with on the left.",
        "same_scan": "You picked the same scan twice: pick another one on the left.",
        "before_card": "Before",
        "after_card": "After",
        "risk_green": "Secure!",
        "risk_yellow": "Medium risk",
        "risk_red": "High risk",
        "active_threats": "{n} active threats",
        "resolved_tag": "RESOLVED",
        "new_tag": "NEW",
        "better": "better",
        "worse": "worse",
        "same": "the same",
        "tuga_up": "Well done! The score went up from **{before}** to **{after}** (+{delta}). You fixed **{resolved}** "
                   "problems.",
        "tuga_down": "Watch out: the score went down from **{before}** to **{after}** ({delta}). **{new}** new "
                     "problems showed up.",
        "tuga_same": "The score stayed at **{after}**.",
        "tuga_left": "**{left}** problems are left to fix: they are on the Home page, with their steps.",
        "tuga_none_left": "Nothing is left to fix. 🎉",
        "resolved": "Resolved",
        "removed_device": "Devices no longer seen",
        "closed_port": "Closed ports",
        "nothing_changed": "Nothing changed between the two scans.",
        "log": "Technical diff log",
        "log_columns": ["Change", "Device", "Port", "Service", "Code"],
        "log_new_device": "➕ new device",
        "log_removed_device": "➖ device gone",
        "log_opened": "🔓 port opened",
        "log_closed": "🔒 port closed",
        "log_resolved": "✅ resolved",
        "log_new_finding": "❗ new problem",
        "export": "📦 Standard export (FR-15)",
        "export_help": "findings.csv and scores.csv for a whole folder of scans, exactly in the contest's format (the "
                       "same files as `python -m conetuga analyse <folder> --out <folder>`).",
        "export_folder": "Folder of scans",
        "export_failed": "The export failed",
    },
}


def render() -> None:
    """The page itself; ui/app.py registers it in the navigation."""
    settings = current()
    lang, advanced = settings.lang, settings.advanced
    text = TEXT[lang]
    title, delete = st.columns((3, 1), vertical_alignment="center")
    title.title(text["title"])
    with delete, st.container(key=HISTORY_DELETE_KEY):
        if st.button(text["delete"], type="primary", use_container_width=True, help=text["delete_help"]):
            delete_my_history()
    if st.session_state.pop(DELETED_KEY, False):
        st.success(text["deleted"])

    records = load_history()
    if not records:
        st.info(text["empty"])
        page_link("acasa", text["go_home"])
        return
    now = current_index(records, current_digest())
    previous = previous_index(records, now)
    show_banner(records, now, previous, lang)

    left, right = st.columns(COLUMN_WIDTHS, gap="large")
    with left:
        show_trend(records, now, lang)
        show_list(records, now, lang)
        if advanced:
            show_export(lang)
    with right:
        show_comparator(records, now, previous, lang, advanced)


def delete_my_history() -> None:
    """NFR-02's one click: the stored scans and the statistics go, the scan on screen is not saved again until another
    is picked, and the session's "already counted" set empties, so a scan opened after opting in again counts again
    (the insights contract's "Deleting")."""
    delete_history()
    st.session_state.get(SEEN_KEY, set()).clear()
    st.session_state[SKIP_SAVE_KEY] = current_digest()
    st.session_state[DELETED_KEY] = True
    st.rerun()


def scan_label(records, index: int) -> str:
    """How a stored scan is named in boxes and the banner: its number, time and file ("#2 · 16:40 · V6b_after.xml")."""
    record = records[index]
    return f"#{index + 1} · {record.saved_at[TIME_OF_DAY]} · {record.file}"


def change_alerts(change, lang: str) -> list[str]:
    """FR-13's alerts, escaped for Markdown: every new device and every newly opened port."""
    text = TEXT[lang]
    alerts = [f"{text['new_device']}: {md(device_name(h, lang))} ({ip_md(h.ip)})" for h in change.new_devices]
    alerts += [f"{text['opened_port']}: {p.port}/{md(p.proto)} · {md(device_name(h, lang))} ({ip_md(h.ip)})"
               for h, p in change.opened_ports]
    return alerts


def show_banner(records, now: int, previous: int | None, lang: str) -> None:
    """FR-13: the scan on screen against the newest earlier scan of its network, as counts, then the alerts."""
    text = TEXT[lang]
    with st.container(key=HISTORY_BANNER_KEY):
        st.markdown(f"### {text['banner']}")
        if previous is None:
            st.markdown(text["first_scan"] if now == 0 else text["no_match"])
            return
        before, after = records[previous], records[now]
        change = diff(before.result, after.result)
        st.markdown(text["banner_since"].format(
            before=previous + 1, before_time=before.saved_at[TIME_OF_DAY], before_file=md(before.file),
            after=now + 1, after_time=after.saved_at[TIME_OF_DAY], after_file=md(after.file)))
        chips = [("🆕", len(change.new_devices), "chip_new"), ("➖", len(change.removed_devices), "chip_removed"),
                 ("🔓", len(change.opened_ports), "chip_opened"), ("🔒", len(change.closed_ports), "chip_closed"),
                 ("✅", len(change.resolved_findings), "chip_resolved")]
        st.markdown('<div class="ct-chips">' + "".join(
            f'<span class="ct-chip"><strong>{icon} {count}</strong> {html.escape(text[key])}</span>'
            for icon, count, key in chips) + "</div>", unsafe_allow_html=True)
        alerts = change_alerts(change, lang)
        if alerts:
            st.warning(f"🚨 **{text['alert']}**\n\n" + "\n".join(f"- {a}" for a in alerts))


def show_trend(records, now: int, lang: str) -> None:
    """The score of every stored scan of this network, oldest first, numbered as in the list below."""
    text = TEXT[lang]
    this_network = [i for i in range(len(records))
                    if i == now or same_network(records[i].result, records[now].result)
                    or same_network(records[now].result, records[i].result)]
    with st.container(key=HISTORY_TREND_KEY):
        st.subheader(text["trend"])
        if len(this_network) < 2:
            st.markdown(text["trend_one"])
            return
        st.line_chart({text["trend_axis"]: [i + 1 for i in this_network],
                       text["score"]: [records[i].result.score for i in this_network]},
                      x=text["trend_axis"], y=text["score"], height=TREND_CHART_PX)


def show_list(records, now: int, lang: str) -> None:
    """Every stored scan, newest first, with its traffic light and score; the one on screen is marked "now"."""
    text = TEXT[lang]
    with st.container(key=HISTORY_LIST_KEY):
        st.subheader(text["list"])
        st.markdown(text["list_where"])
        lines = []
        for i in reversed(range(len(records))):
            score = records[i].result.score
            mark = f" · **{text['now']}**" if i == now else ""
            lines.append(f"- **#{i + 1}** · {records[i].saved_at[TIME_OF_DAY]} · {md(records[i].file)} · "
                         f"{score_line(score, lang)[0]} {score}/100{mark}")
        st.markdown("\n".join(lines))


def show_export(lang: str) -> None:
    """FR-15 in Advanced mode: C's `export` on one of the folders we ship, offered as the two standard files."""
    text = TEXT[lang]
    folders = [folder for folder in EXAMPLE_FOLDERS if folder.is_dir()]
    with st.container(key=HISTORY_EXPORT_KEY):
        st.subheader(text["export"])
        st.markdown(text["export_help"])
        folder = st.selectbox(text["export_folder"], folders, key=EXPORT_FOLDER_KEY,
                              format_func=lambda path: str(path.relative_to(EXAMPLE_FOLDERS[0].parents[3])))
        if folder is None:
            return
        try:
            files = exported_files(folder)
        except ExportError as exc:
            st.error(f"⛔ {text['export_failed']}: {md(str(exc))}")
            return
        first, second = st.columns(2)
        first.download_button(f"⬇️ {FINDINGS_FILE}", files[FINDINGS_FILE], file_name=FINDINGS_FILE, mime="text/csv",
                              use_container_width=True)
        second.download_button(f"⬇️ {SCORES_FILE}", files[SCORES_FILE], file_name=SCORES_FILE, mime="text/csv",
                               use_container_width=True)


def exported_files(folder: Path) -> dict[str, bytes]:
    """The two CSVs `export` writes for `folder`, read back from a temporary folder that is then deleted."""
    with tempfile.TemporaryDirectory() as out:
        export(folder, Path(out))
        return {name: (Path(out) / name).read_bytes() for name in (FINDINGS_FILE, SCORES_FILE)}


def show_comparator(records, now: int, previous: int | None, lang: str, advanced: bool) -> None:
    """Any two stored scans face to face. It opens on the banner's pair; with no earlier scan of this network, the
    "before" box starts empty, so nothing is compared until the person picks a scan."""
    text = TEXT[lang]
    with st.container(key=HISTORY_COMPARE_KEY):
        st.subheader(text["compare"])
        first, second = st.columns(2)
        options = list(range(len(records)))
        before = first.selectbox(text["before_box"], options, index=previous, key=BEFORE_KEY,
                                 placeholder=text["pick"], format_func=lambda i: scan_label(records, i))
        after = second.selectbox(text["after_box"], options, index=now, key=AFTER_KEY,
                                 format_func=lambda i: scan_label(records, i))
        if before is None or after is None:
            st.info(text["pick_before"])
            return
        if before == after:
            st.info(text["same_scan"])
            return
        show_diff(records[before].result, records[after].result, lang, advanced)


def risk_words(score: int, lang: str) -> str:
    """The words in a before/after card: "Securizat!", "Risc mediu", "Risc mare" (with the traffic light's icon)."""
    return f"{score_line(score, lang)[0]} {TEXT[lang]['risk_' + light(score)]}"


def threat_html(code: str, title: str, tag: str = "", resolved: bool = False) -> str:
    """One finding in a before/after card: its code and title, and a tag ("REZOLVAT", "NOU") when it has one."""
    e = html.escape
    tag_html = f'<span class="ct-tag{" ct-tag-ok" if resolved else ""}">{e(tag)}</span>' if tag else ""
    return (f'<div class="ct-threat{" ct-resolved" if resolved else ""}"><span>{"🛡️" if resolved else "❗"} '
            f'<strong>{e(code)}</strong><br>{e(title)}</span>{tag_html}</div>')


def new_findings(before, after) -> list:
    """The findings of `after` that `before` didn't have (same device, port and code)."""
    seen = {(f.ip, f.port, f.proto, f.code) for f in before.findings}
    return [f for f in after.findings if (f.ip, f.port, f.proto, f.code) not in seen]


def show_cards(before, after, change, lang: str, number: int) -> None:
    """The two scans as cards: each score and its findings; in "after", the findings fixed since are kept, marked
    "REZOLVAT", and the new ones are marked "NOU"."""
    text = TEXT[lang]
    hosts_before, hosts_after = {h.ip: h for h in before.hosts}, {h.ip: h for h in after.hosts}
    resolved, new = set(change.resolved_findings), set(new_findings(before, after))
    columns = st.columns(2, gap="medium")
    for column, side, scan, score in ((columns[0], "before", before, change.score_before),
                                      (columns[1], "after", after, change.score_after)):
        with column, st.container(key=f"{HISTORY_KEY}-{light(score)}-{side}-{number}"):
            st.markdown(f'<div class="ct-card-head"><span class="ct-card-title">{html.escape(text[side + "_card"])}'
                        f'</span><span class="ct-tag">{html.escape(scan.file)}</span></div>'
                        f'<div class="ct-big-score">{score}<small>/100</small></div>', unsafe_allow_html=True)
            st.markdown(f"**{risk_words(score, lang)}** · {text['active_threats'].format(n=len(scan.findings))}")
            if side == "before":
                items = [threat_html(f.code, explain(f, hosts_before[f.ip], lang).title) for f in before.findings]
            else:
                items = [threat_html(f.code, explain(f, hosts_before[f.ip], lang).title, text["resolved_tag"], True)
                         for f in before.findings if f in resolved]
                items += [threat_html(f.code, explain(f, hosts_after[f.ip], lang).title,
                                      text["new_tag"] if f in new else "")
                          for f in after.findings]
            if items:
                st.markdown("".join(items), unsafe_allow_html=True)


def show_diff(before, after, lang: str, advanced: bool = False) -> None:
    """One comparison: the two cards, the score line, then Tuga's summary and the changes in plain words (Simple
    mode) or Cone's technical log (Advanced mode)."""
    text = TEXT[lang]
    change = diff(before, after)
    delta = change.score_after - change.score_before
    trend = text["better"] if delta > 0 else text["worse"] if delta < 0 else text["same"]
    arrow = "⬆️" if delta > 0 else "⬇️" if delta < 0 else "➡️"
    number = next(COMPARISON_NUMBERS)
    show_cards(before, after, change, lang, number)
    with st.container(key=f"{TREND_LINE_KEY}-{number}"):
        st.markdown(f"### {arrow} {text['score']}: {change.score_before} → {change.score_after} ({delta:+d}, {trend})")
    if advanced:
        show_log(before, after, change, lang, number)
    else:
        show_tuga_summary(before, after, change, lang, number)


def show_tuga_summary(before, after, change, lang: str, number: int) -> None:
    """Simple mode: Tuga says in a few words how it went, then lists the changes by name, no port numbers first."""
    text = TEXT[lang]
    delta = change.score_after - change.score_before
    key = "tuga_up" if delta > 0 else "tuga_down" if delta < 0 else "tuga_same"
    words = text[key].format(before=change.score_before, after=change.score_after, delta=delta,
                             resolved=len(change.resolved_findings), new=len(new_findings(before, after)))
    left = len(after.findings)
    words += " " + (text["tuga_left"].format(left=left) if left else text["tuga_none_left"])
    with st.container(key=f"{HISTORY_SAY_KEY}-{number}"):
        show_guide("tuga", lang, words, GUIDE_PICTURE_PX, widths=(1, 7))

    hosts_before = {h.ip: h for h in before.hosts}
    sections = [
        (f"✅ {text['resolved']}", [f"{md(explain(f, hosts_before[f.ip], lang).title)} · "
                                    f"{md(device_name(hosts_before[f.ip], lang))} ({ip_md(f.ip)})"
                                    for f in change.resolved_findings]),
        (f"🚨 {text['alert']}", change_alerts(change, lang)),
        (f"➖ {text['removed_device']}", [f"{md(device_name(h, lang))} ({ip_md(h.ip)})"
                                         for h in change.removed_devices]),
        (f"🔒 {text['closed_port']}", [f"{p.port}/{md(p.proto)} · {md(device_name(h, lang))} ({ip_md(h.ip)})"
                                      for h, p in change.closed_ports]),
    ]
    shown = [(title, items) for title, items in sections if items]
    if not shown:
        st.markdown(text["nothing_changed"])
    for title, items in shown:
        st.markdown(f"**{title} ({len(items)})**\n" + "\n".join(f"- {item}" for item in items))


def show_log(before, after, change, lang: str, number: int) -> None:
    """Advanced mode: Cone's table of every change, one row each: devices, ports with nmap's service, and findings by
    catalog code. Every scan value goes through md() or ip_md()."""
    text = TEXT[lang]
    rows = [(text["log_new_device"], h, "", "", "") for h in change.new_devices]
    rows += [(text["log_removed_device"], h, "", "", "") for h in change.removed_devices]
    rows += [(text["log_opened"], h, f"{p.port}/{md(p.proto)}", md(service_words(p)), "") for h, p in change.opened_ports]
    rows += [(text["log_closed"], h, f"{p.port}/{md(p.proto)}", md(service_words(p)), "") for h, p in change.closed_ports]
    hosts_before, hosts_after = {h.ip: h for h in before.hosts}, {h.ip: h for h in after.hosts}
    rows += [(text["log_resolved"], hosts_before[f.ip], port_of(f), "", f"`{f.code}`") for f in change.resolved_findings]
    rows += [(text["log_new_finding"], hosts_after[f.ip], port_of(f), "", f"`{f.code}`")
             for f in new_findings(before, after)]
    with st.container(key=f"{HISTORY_SAY_KEY}-{number}"):
        show_guide("cone", lang, f"🐇 **Cone** · {text['log']}", GUIDE_PICTURE_PX, widths=(1, 7))
    if not rows:
        st.markdown(text["nothing_changed"])
        return
    header = "| " + " | ".join(text["log_columns"]) + " |\n|" + "---|" * len(text["log_columns"])
    # Cone's table names a device the technical way, by its IP and its hostname, so the row stays one line.
    body = "\n".join(f"| {kind} | {ip_md(host.ip)} {md(host.hostname)} | {port} | {service} | {code} |"
                     for kind, host, port, service, code in rows)
    st.markdown(f"{header}\n{body}")


def service_words(port) -> str:
    """nmap's service, product and version of a port, as one plain string (escaped by the caller)."""
    return " ".join(part for part in (port.service, port.product, port.version) if part)


def port_of(finding) -> str:
    """A finding's port as "23/tcp", or "—" for UNKNOWN_DEVICE, which has none."""
    return "—" if finding.port is None else f"{finding.port}/{md(finding.proto)}"
