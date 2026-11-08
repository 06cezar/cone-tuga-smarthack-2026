"""Despre & Wiki: what ConeTuga does and who its two guides are (left), the ethical shield and the guardrail it keeps
(right, FR-02 and NFR-02), then the Common Threat Wiki of every problem it can find (ui/pages/wiki.py).

The shield shows the subnet the live scan may cover now, read the way the live scan reads it (C's detect_network, the
default allowlist); with no active network it says the live scan is blocked. Everything else is our own fixed text,
in Romanian and English (NFR-09); no scan data on this page."""
import streamlit as st

from conetuga.guard import HOTSPOT_SSID, NetworkNotFound, detect_network
from ui.pages import wiki
from ui.state import current, page_link, show_guide
from ui.theme import ABOUT_INTRO_KEY, ABOUT_SHIELD_KEY
from ui.view import md

GUIDE_PICTURE_PX = 72  # each guide beside the lines that introduce it
COLUMN_WIDTHS = (1, 1)  # the app and its guides : the shield
MASKED_MAC_EXAMPLE = "AA:BB:CC:xx:xx:xx"  # the shape every MAC takes on screen (Host.mac_masked)

TEXT = {
    "ro": {
        "title": "Despre ConeTuga",
        "what": "**Ce face.** ConeTuga se uită la rețeaua ta de acasă, găsește aparatele și „ușile” lor deschise spre "
                "rețea (porturile), îți spune pe înțeles ce înseamnă fiecare și ce să faci, pas cu pas. Istoricul îți "
                "arată dacă scorul a crescut după ce ai reparat ceva.",
        "guides": "**Cei doi ghizi.**",
        "tuga": "🐢 **Tuga** (o țestoasă) îți explică simplu, fără cuvinte tehnice: este modul obișnuit, **Simplu**.",
        "cone": "🐇 **Cone** (un iepure) îți arată și detaliile tehnice: porturi, ce a văzut scanarea, regulile și "
                "referințele. Îl pornești din comutatorul **Cone (Avansat)** de sus.",
        "how": "**Cum decide.** Problemele și scorul vin doar din catalogul oficial al concursului, nu dintr-o "
               "inteligență artificială: același fișier dă mereu același rezultat.",
        "shield": "🛡️ Scutul Etic & Guardrail activ",
        "shield_sub": "FR-02 și NFR-02: ce scanăm, ce refuzăm și ce rămâne pe acest calculator.",
        "allowlist": "**Subrețeaua permisă acum (allowlist):** `{subnet}` pe {interface}: rețeaua la care e conectat "
                     "calculatorul, găsită singură.",
        "no_network": "**Subrețeaua permisă acum:** niciuna. Calculatorul nu e conectat la nicio rețea, deci scanarea "
                      "live e blocată.",
        "hotspot": "**Doar pe hotspotul nostru** „{ssid}”: pe orice alt Wi-Fi (de exemplu al sălii), fiecare scanare "
                   "e refuzată, chiar și subrețeaua conectată.",
        "refused": "**Refuzate mereu:** adresele de pe internet (IP-uri publice), alte rețele și ținte mai mari decât "
                   "subrețeaua; o scanare live pornește doar după confirmarea ta (`--confirm`).",
        "mac": "**Adrese MAC mascate peste tot:** rămâne doar partea producătorului, de forma `{example}`, pe ecran, în "
               "rapoarte și în istoric.",
        "local": "**100% local:** aplicația se deschide doar de pe acest calculator, nu trimite nicio statistică, iar "
                 "explicațiile vin din fișierele noastre, nu dintr-un serviciu de pe internet.",
        "history": "**Istoricul** stă doar pe acest calculator și îl ștergi cu un clic, pe pagina Istoric: „Șterge "
                   "istoricul meu”.",
        "history_link": "📈 Mergi la Istoric",
    },
    "en": {
        "title": "About ConeTuga",
        "what": "**What it does.** ConeTuga looks at your home network, finds the devices and the \"doors\" they leave "
                "open (ports), tells you in plain words what each one means and what to do, step by step. The history "
                "shows whether your score went up after a fix.",
        "guides": "**The two guides.**",
        "tuga": "🐢 **Tuga** (a tortoise) explains simply, with no technical words: the usual **Simple** mode.",
        "cone": "🐇 **Cone** (a hare) also shows the technical details: ports, what the scan saw, the rules and the "
                "references. Turn it on with the **Cone (Advanced)** switch at the top.",
        "how": "**How it decides.** Problems and the score come only from the contest's official catalog, never from "
               "an AI: the same file always gives the same result.",
        "shield": "🛡️ Ethical Shield & active guardrail",
        "shield_sub": "FR-02 and NFR-02: what we scan, what we refuse and what stays on this computer.",
        "allowlist": "**Subnet allowed now (allowlist):** `{subnet}` on {interface}: the network this computer is "
                     "connected to, found on its own.",
        "no_network": "**Subnet allowed now:** none. This computer isn't connected to any network, so the live scan is "
                      "blocked.",
        "hotspot": "**Only on our hotspot** \"{ssid}\": on any other Wi-Fi (the venue's, say), every scan is refused, "
                   "the connected subnet too.",
        "refused": "**Always refused:** internet addresses (public IPs), other networks and targets larger than the "
                   "subnet; a live scan starts only after you confirm it (`--confirm`).",
        "mac": "**MAC addresses masked everywhere:** only the maker's part stays, shaped like `{example}`, on screen, in "
               "reports and in the history.",
        "local": "**100% local:** the app opens only from this computer, sends no statistics, and the explanations "
                 "come from our own files, not from an internet service.",
        "history": "**The history** stays only on this computer, and one click on the History page deletes it: "
                   "\"Delete my history\".",
        "history_link": "📈 Go to History",
    },
}


def render() -> None:
    """The page: the two cards side by side, then the wiki under them."""
    lang = current().lang
    text = TEXT[lang]
    st.title(text["title"])
    intro, shield = st.columns(COLUMN_WIDTHS, gap="large")
    with intro, st.container(key=ABOUT_INTRO_KEY):
        st.markdown(text["what"])
        st.markdown(text["guides"])
        show_guide("tuga", lang, text["tuga"], GUIDE_PICTURE_PX, widths=(1, 5))
        show_guide("cone", lang, text["cone"], GUIDE_PICTURE_PX, widths=(1, 5))
        st.markdown(text["how"])
    with shield, st.container(key=ABOUT_SHIELD_KEY):
        show_shield(lang)
    wiki.render()


def show_shield(lang: str) -> None:
    """The guardrail as it stands now: the allowed subnet (or none), the hotspot rule, what is always refused, MAC
    masking and what stays local. The interface name and the subnet come from the system: escaped like scan text."""
    text = TEXT[lang]
    st.subheader(text["shield"])
    st.markdown(f"*{text['shield_sub']}*")
    try:
        network = detect_network()
        allowlist = text["allowlist"].format(subnet=network.subnet.replace("`", ""), interface=md(network.interface))
    except NetworkNotFound:
        allowlist = text["no_network"]
    lines = [allowlist, text["hotspot"].format(ssid=md(HOTSPOT_SSID)), text["refused"],
             text["mac"].format(example=MASKED_MAC_EXAMPLE), text["local"], text["history"]]
    st.markdown("\n".join(f"- ✅ {line}" for line in lines))
    page_link("istoric", text["history_link"])
