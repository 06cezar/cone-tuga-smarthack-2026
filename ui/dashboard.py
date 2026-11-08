"""Acasă's dashboard, under the scan picker, after Cezar's mock-ups (D-mockup).

Tuga (Simple mode, light):
- left: the security score card (a half-circle gauge, its percentage pill, the warning in words), then Tuga's card:
  his drawing with a traffic-cone hat and a speech bubble; tap him and he reads the headline and the score aloud;
- right: the red "most dangerous device" card (siren, the device in large type, the danger, a big green
  "Repară acum!" link to the checkup), then the devices with no problem.
Cone (Advanced mode, dark): left, Cone's analysis card and a small score card with a ring; right, the same headline in
a red strip and the technical audit (ui/summary.py).

What the brief and the tests need stays: the headline is the first "## " text, holds "Cel mai periculos" and
"Fă asta întâi", and is the same in both modes (live check 2, ui/CLAUDE.md); the guide is named under its picture;
scan text is escaped (view.md in Markdown, html.escape in HTML); colour never stands alone (NFR-08)."""
import html

import streamlit as st

from conetuga.explain import narrate
from ui.assets import ASSETS_DIR, guide_picture
from ui.checkup import DEVICE_ICON, tasks_of
from ui.gauge import ARC_HEIGHT_PX, RING_HEIGHT_PX, arc_html, ring_html
from ui.state import GUIDE_NAMES
from ui.style import CHECKUP_ANCHOR, HEADLINE_KEY, block_key
from ui.summary import show_audit
from ui.talking import HEIGHT_PX as TALKING_HEIGHT_PX, TEXT as TALKING_TEXT, talking_html
from ui.theme import CONE_BUBBLE_KEY, DANGER_KEY, FIX_NOW_KEY, LIGHTS, SAFE_KEY, SCORE_KEY, STATUS, status_text
from ui.view import DeviceView, STATUS_NONE, TEXT as VIEW_TEXT, device_status, headline, light, md, score_line

TUGA_COLUMNS = (1, 1)  # left: score and Tuga; right: the worst device and the safe ones
CONE_COLUMNS = (1, 2.4)  # left: Cone and the score; right: the headline and the audit
GUIDE_WIDTHS = (2, 3)  # Tuga's drawing : his speech bubble
HERO_PX = {"tuga": 200, "cone": 230}  # the guides' drawings in their cards: large enough to tap

TEXT = {
    "ro": {
        "score_card": "Scor de securitate",
        "score": "Scor standard",
        "danger": "Cel mai periculos dispozitiv",
        "calm": "Nimic urgent",
        "risk": "Pericol",
        "fix_now": "👉 Repară acum!",
        "safe": "Dispozitive sigure",
        "safe_none": "Încă niciun dispozitiv fără probleme.",
        "tuga_hello": "Salutare! Nu-ți face griji, ne ocupăm împreună de siguranța casei tale online! Hai să începem "
                      "cu **{device}**, de alături.",
        "tuga_calm": "Salutare! Rețeaua ta arată bine. Uită-te mai jos la aparatele tale.",
        "cone_title": "Analiza lui Cone",
        "cone_hello": "Scanare completă! Am găsit **{findings}** probleme pe **{devices}** dispozitive. Cea mai gravă: "
                      "`{code}` la {ip}. Hai să o reparăm! 🛡️",
        "cone_calm": "Scanare completă! Nicio problemă din catalog pe cele **{devices}** dispozitive. 🛡️",
        "score_label": "Scor:",
    },
    "en": {
        "score_card": "Security score",
        "score": "Standard score",
        "danger": "Most dangerous device",
        "calm": "Nothing urgent",
        "risk": "Risk",
        "fix_now": "👉 Fix it now!",
        "safe": "Safe devices",
        "safe_none": "No device without problems yet.",
        "tuga_hello": "Hello there! Don't worry, we can secure your home network together! Let's start with "
                      "**{device}**, next to me.",
        "tuga_calm": "Hello there! Your network looks good. Have a look at your devices below.",
        "cone_title": "Cone's analysis",
        "cone_hello": "Scan done! I found **{findings}** findings on **{devices}** devices. The worst: `{code}` on "
                      "{ip}. Let's fix it! 🛡️",
        "cone_calm": "Scan done! No catalog finding on the **{devices}** devices. 🛡️",
        "score_label": "Score:",
    },
}


def headline_markdown(devices: list[DeviceView], lang: str) -> str:
    """The headline as the card shows it: "Cel mai periculos" (read by screen readers, shown by the card's siren
    title), the device in large type, then "Fă asta întâi: …". The same in both modes."""
    words = VIEW_TEXT[lang]
    if not devices or devices[0].risk == 0:
        return f"## {words['nothing_urgent']}"
    top = devices[0]
    step = top.findings[0].explanation.steps[0]
    return (f'## <span class="ct-sr">{words["most_dangerous"]}:</span> <span class="ct-device">{md(top.name)} '
            f'({md(top.host.ip)})</span> {words["do_first"]}: {md(step)}')


def spoken_summary(devices: list[DeviceView], result, lang: str) -> str:
    _icon, colour, sentence = score_line(result.score, lang)
    return f"{headline(devices, lang)} {TEXT[lang]['score']}: {result.score} / 100, {colour}. {sentence}"


def show_score_card(result, lang: str, dark: bool) -> None:
    """The score card: its title with the percentage pill, the gauge (Tuga's half circle or Cone's ring), and the
    score in words, which a screen reader and the tests read."""
    text = TEXT[lang]
    icon, colour, _sentence = score_line(result.score, lang)
    strong = STATUS[dark][LIGHTS[light(result.score)]][0]
    with st.container(key=SCORE_KEY):
        st.markdown(f'<div class="ct-card-head"><span class="ct-card-title">{html.escape(text["score_card"])}</span>'
                    f'<span class="ct-pill"><span class="ct-dot" style="background:{strong}"></span>'
                    f'{result.score}%</span></div>', unsafe_allow_html=True)
        if dark:
            number, ring = st.columns((1, 1), vertical_alignment="center")
            number.markdown(f'<div class="ct-big-score" style="color:{status_text(LIGHTS[light(result.score)], True)}">'
                            f'{result.score}<small>/100</small></div>', unsafe_allow_html=True)
            with ring:
                st.components.v1.html(ring_html(result.score, lang), height=RING_HEIGHT_PX)
        else:
            st.components.v1.html(arc_html(result.score, lang), height=ARC_HEIGHT_PX)
        st.markdown(f"{icon} {text['score']}: {result.score}/100 · {colour}")


def show_guide_card(speaker: str, lang: str, words: str, spoken: str) -> None:
    """A guide's card: the drawing with its name under it and the speech bubble; tapping the drawing reads `spoken`
    aloud (ui/talking.py). Tuga has the bubble beside him, Cone above him, as in the mock-ups."""
    path, alt = ASSETS_DIR / f"{speaker}_hero.svg", guide_picture(speaker, lang)[1]
    bubble = f"{words}\n\n*{TALKING_TEXT[lang]}*"
    with st.container(key=block_key(HEADLINE_KEY, speaker)):
        if speaker == "cone":
            st.markdown(f"#### {TEXT[lang]['cone_title']}")
            with st.container(key=CONE_BUBBLE_KEY):
                st.markdown(bubble)
            st.image(str(path), width=HERO_PX[speaker], alt=alt)
            st.markdown(GUIDE_NAMES[speaker])
        else:
            picture, talk = st.columns(GUIDE_WIDTHS, vertical_alignment="center")
            picture.image(str(path), width=HERO_PX[speaker], alt=alt)
            picture.markdown(GUIDE_NAMES[speaker])
            talk.markdown(bubble)
        st.components.v1.html(talking_html(spoken, lang, speaker), height=TALKING_HEIGHT_PX)


def show_danger_card(devices: list[DeviceView], lang: str, simple: bool) -> None:
    """The red card: siren and title, the headline with the device in large type, then in Simple mode the danger in
    plain words and the big green link to the checkup."""
    text = TEXT[lang]
    tasks = tasks_of(devices)
    with st.container(key=block_key(DANGER_KEY, "on" if tasks else "off")):
        siren, title = ("🚨", text["danger"]) if tasks else ("✅", text["calm"])
        st.markdown(f'<div class="ct-alert-head"><span class="ct-siren">{siren}</span>'
                    f'<span>{html.escape(title)}</span></div>', unsafe_allow_html=True)
        st.markdown(headline_markdown(devices, lang), unsafe_allow_html=True)
        if simple and tasks:
            device, finding = tasks[0]
            danger = narrate(finding, device.host, lang, "simple").title
            st.markdown(f"**{text['risk']}:** {md(danger)}")
            with st.container(key=FIX_NOW_KEY):
                st.markdown(f"[{text['fix_now']}](#{CHECKUP_ANCHOR})")


def show_safe_card(devices: list[DeviceView], lang: str) -> None:
    """The devices with no problem, each with a tick, its picture in a circle and its name."""
    text = TEXT[lang]
    safe = [d for d in devices if device_status(d) == STATUS_NONE]
    with st.container(key=SAFE_KEY):
        st.markdown(f"### {text['safe']}")
        if not safe:
            st.markdown(text["safe_none"])
            return
        items = "".join(
            f'<div class="ct-safe-item"><span class="ct-check" aria-hidden="true">✓</span>'
            f'<span class="ct-device-icon" aria-hidden="true">'
            f'{DEVICE_ICON.get(d.host.device_type, DEVICE_ICON["unknown"])}</span>'
            f'<span>{html.escape(d.name)}</span></div>' for d in safe)
        st.markdown(f'<div class="ct-safe-grid">{items}</div>', unsafe_allow_html=True)


def show_tuga_dashboard(result, devices: list[DeviceView], lang: str) -> None:
    text = TEXT[lang]
    hello = (text["tuga_hello"].format(device=md(devices[0].name)) if tasks_of(devices) else text["tuga_calm"])
    left, right = st.columns(TUGA_COLUMNS, gap="large")
    with left:
        show_score_card(result, lang, dark=False)
        show_guide_card("tuga", lang, hello, spoken_summary(devices, result, lang))
    with right:
        show_danger_card(devices, lang, simple=True)
        show_safe_card(devices, lang)


def show_cone_dashboard(result, devices: list[DeviceView], lang: str) -> None:
    text = TEXT[lang]
    findings = [view.finding for device in devices for view in device.findings]
    if findings:
        worst = max(findings, key=lambda f: f.points)
        insight = text["cone_hello"].format(findings=len(findings), devices=len(devices), code=worst.code,
                                            ip=md(worst.ip))
    else:
        insight = text["cone_calm"].format(devices=len(devices))
    left, right = st.columns(CONE_COLUMNS, gap="large")
    with left:
        show_guide_card("cone", lang, insight, spoken_summary(devices, result, lang))
        show_score_card(result, lang, dark=True)
    with right:
        show_danger_card(devices, lang, simple=False)
        show_audit(result, devices, lang)
