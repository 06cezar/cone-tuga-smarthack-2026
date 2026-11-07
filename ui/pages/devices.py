"""Dispozitive (FE-D3): every device of the scan picked on Acasă, riskiest first, with filters by status and device type
and a choice of order (A's functions in ui/view.py, FE-A4). Each card says what the current guide says (ui/cards.py).
A device nmap gave up on shows as "Neverificat", never as safe (Host.timed_out). The page computes nothing: it only
filters and orders what analyse_file returned."""
import streamlit as st

from ui.cards import show_device
from ui.state import current, current_scan
from ui.view import SORT_KEYS, devices_by_risk, filter_devices, md, sort_devices, status_options, type_options

# Fixed widget keys: the type filter is cleaned up through its key below, and the tests set the widgets by them.
STATUS_KEY = "devices_status_filter"
TYPE_KEY = "devices_type_filter"
SORT_KEY = "devices_sort"

TEXT = {
    "ro": {
        "title": "Dispozitive",
        "no_scan": "Alege mai întâi o scanare pe pagina Acasă: aici apar apoi toate dispozitivele ei.",
        "unreadable": "Fișierul nu poate fi citit",
        "status": "Arată doar",
        "type": "Tipul dispozitivului",
        "all": "Toate",
        "sort": "Ordinea",
        "sort_by": {"risk": "Cel mai periculos întâi", "ip": "După adresa IP", "name": "După nume",
                    "type": "După tip"},
        "count": "Afișate: {shown} din {total} dispozitive.",
        "none_match": "Niciun dispozitiv nu se potrivește cu filtrele alese.",
    },
    "en": {
        "title": "Devices",
        "no_scan": "First pick a scan on the Home page: all its devices then show here.",
        "unreadable": "The file can't be read",
        "status": "Show only",
        "type": "Device type",
        "all": "All",
        "sort": "Order",
        "sort_by": {"risk": "Most dangerous first", "ip": "By IP address", "name": "By name", "type": "By type"},
        "count": "Showing {shown} of {total} devices.",
        "none_match": "No device matches the chosen filters.",
    },
}


def render() -> None:
    settings = current()
    lang = settings.lang
    text = TEXT[lang]
    st.title(text["title"])
    result = current_scan()
    if result is None:
        st.info(text["no_scan"])
        return
    if result.error:
        st.error(f"⛔ {text['unreadable']}: {md(result.error)}")
        return

    devices = devices_by_risk(result, lang)
    statuses = dict(status_options(lang))
    types = dict(type_options(devices, lang))
    # A type picked for another scan (a camera) may not exist in this one: drop it before the widget is drawn, so the
    # filter never asks for an option it doesn't have.
    if TYPE_KEY in st.session_state:
        st.session_state[TYPE_KEY] = [t for t in st.session_state[TYPE_KEY] if t in types]
    left, middle, right = st.columns(3)
    picked_statuses = left.multiselect(text["status"], list(statuses), format_func=statuses.get,
                                       placeholder=text["all"], key=STATUS_KEY)
    picked_types = middle.multiselect(text["type"], list(types), format_func=types.get, placeholder=text["all"],
                                      key=TYPE_KEY)
    order = right.selectbox(text["sort"], SORT_KEYS, format_func=text["sort_by"].get, key=SORT_KEY)

    # An empty filter means "all", as its placeholder says.
    shown = sort_devices(filter_devices(devices, set(picked_statuses) or None, set(picked_types) or None), order, lang)
    st.markdown(text["count"].format(shown=len(shown), total=len(devices)))
    if not shown:
        st.markdown(text["none_match"])
    for i, device in enumerate(shown):
        show_device(device, lang, expanded=i == 0, advanced=settings.advanced)
