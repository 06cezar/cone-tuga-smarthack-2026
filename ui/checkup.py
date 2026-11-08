"""Acasă in Simple mode as a checkup (design idea on D-fe-checkup), for a child, a grandparent, anyone.

Ideas borrowed from services people already find easy:
- Google's Security Checkup: a list of things to fix, each one ticked when done, with the progress shown.
- GOV.UK's design: one thing at a time. Only the next task not yet done is open; plain words; large targets.
- Fing's device list: the home as tiles, one per device, with what it is, its status and how to recognise it.

Our own ideas stay: Tuga 🐢 explains each task (ui/cards.show_finding, with the read-aloud button and "Ce-ar fi dacă
repar?"), and the estimated score comes from A's standard_score (ui/view.score_without). A tick is the person's word,
not a new scan: the page says the estimate is only real after scanning again."""
import streamlit as st

from conetuga.explain import narrate
from ui.cards import TEXT as CARD_TEXT, show_finding
from ui.style import CARD_KEY, block_key
from ui.view import DeviceView, device_status, md, score_without, status_options

TILE_COLUMNS = 3  # device tiles per row on a laptop; Streamlit stacks them on a phone
CELEBRATED_KEY = "checkup_celebrated"  # the scans whose list was finished: balloons once per scan, not on every rerun

# The device types of conetuga/analysis/devices.py, as a picture a child knows. Always beside the type's words.
DEVICE_ICON = {"camera": "📷", "printer": "🖨️", "nas": "🗄️", "router": "📡", "tv": "📺", "smart-home": "💡",
               "computer": "💻", "server": "🖥️", "phone": "📱", "unknown": "❓"}

TEXT = {
    "ro": {
        "todo": "🧰 Lista ta de reparat",
        "todo_help": "Începe cu prima: e cea care îți crește cel mai mult scorul. Bifeaz-o când ai terminat.",
        "done_box": "✅ Am făcut asta",
        "progress": "{done} din {total} făcute · scor estimat: {score}/100",
        "points": "+{n} puncte",
        "all_done": "🎉 Bravo! Ai făcut tot. Scanează din nou ca să vezi scorul adevărat.",
        "nothing": "🎉 Nu ai nimic de reparat. Bravo!",
        "estimate": "Scorul estimat e doar ce ai bifat tu; scorul adevărat îl vezi după o nouă scanare.",
        "home": "🏠 Casa ta",
        "home_help": "Toate aparatele găsite în rețea. Detaliile fiecăruia sunt pe pagina **Dispozitive**.",
    },
    "en": {
        "todo": "🧰 Your list of things to fix",
        "todo_help": "Start with the first one: it raises your score the most. Tick it when you are done.",
        "done_box": "✅ I did this",
        "progress": "{done} of {total} done · estimated score: {score}/100",
        "points": "+{n} points",
        "all_done": "🎉 Well done! You did everything. Scan again to see your real score.",
        "nothing": "🎉 You have nothing to fix. Well done!",
        "estimate": "The estimated score is only what you ticked; you see the real score after a new scan.",
        "home": "🏠 Your home",
        "home_help": "Every device found on the network. The details of each are on the **Devices** page.",
    },
}


def tasks_of(devices: list[DeviceView]) -> list[tuple[DeviceView, object]]:
    """Every finding as (device, finding), the one worth the most points first; ties keep the devices' order."""
    tasks = [(device, view.finding) for device in devices for view in device.findings]
    return sorted(tasks, key=lambda task: -task[1].points)


def done_key(finding) -> str:
    """The checkbox key of one task: the finding's place and code, the same on every rerun of this scan."""
    return block_key("done", finding.file, finding.ip, finding.port, finding.proto, finding.code)


def show_checklist(result, devices: list[DeviceView], lang: str) -> None:
    """The tasks, each a closed card except the next one to do, with the progress and the estimated score on top."""
    text = TEXT[lang]
    st.subheader(text["todo"])
    tasks = tasks_of(devices)
    if not tasks:
        st.success(text["nothing"])
        return
    st.markdown(text["todo_help"])
    done = [finding for _device, finding in tasks if st.session_state.get(done_key(finding))]
    estimate = score_without(result, done)
    st.progress(len(done) / len(tasks), text=text["progress"].format(done=len(done), total=len(tasks), score=estimate))
    next_task = next((finding for _device, finding in tasks if finding not in done), None)
    for number, (device, finding) in enumerate(tasks, start=1):
        title = narrate(finding, device.host, lang, "simple").title
        icon = DEVICE_ICON.get(device.host.device_type, DEVICE_ICON["unknown"])
        gain = f" · {text['points'].format(n=finding.points)}" if finding.points else ""
        tick = "✅ " if finding in done else ""
        label = f"{tick}{number}. {icon} {md(device.name)}: {md(title)}{gain}"
        with st.expander(label, expanded=finding is next_task):
            show_finding(finding, device.host, lang, advanced=False, result=result)
            st.checkbox(text["done_box"], key=done_key(finding))
    if next_task is None:
        st.success(text["all_done"])
        if result.file not in st.session_state.setdefault(CELEBRATED_KEY, set()):
            st.session_state[CELEBRATED_KEY].add(result.file)
            st.balloons()
    st.markdown(f"*{text['estimate']}*")


def show_home_map(devices: list[DeviceView], lang: str) -> None:
    """Every device as a tile: its picture and name, its status in icon and words, and how to recognise it (FR-03)."""
    text, card = TEXT[lang], CARD_TEXT[lang]
    statuses = dict(status_options(lang))
    st.subheader(text["home"])
    st.markdown(text["home_help"])
    columns = st.columns(TILE_COLUMNS)
    for i, device in enumerate(devices):
        host, status = device.host, device_status(device)
        icon = DEVICE_ICON.get(host.device_type, DEVICE_ICON["unknown"])
        with columns[i % TILE_COLUMNS], st.container(key=block_key(CARD_KEY, status, host.ip)):
            st.markdown(f"### {icon}\n**{md(device.name)}**\n\n{statuses[status]}")
            st.markdown(f"IP {host.ip} · {card['vendor']}: {md(host.vendor) or card['unknown']} · "
                        f"{card['mac']}: {md(host.mac_masked) or card['unknown']}")
