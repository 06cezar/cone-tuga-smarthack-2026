"""Despre: what ConeTuga does, who the two guides are, and the safety and privacy rules it keeps. Fixed text only, in
Romanian and English (NFR-09); no scan data on this page."""
import streamlit as st

from ui.state import current

TEXT = {
    "ro": {
        "title": "Despre ConeTuga",
        "body": """
**Ce face.** ConeTuga se uită la rețeaua ta de acasă, găsește aparatele și „ușile” lor deschise spre rețea (porturile),
îți spune pe înțeles ce înseamnă fiecare și ce să faci, pas cu pas. Istoricul îți arată dacă scorul a crescut după ce ai
reparat ceva.

**Cei doi ghizi.** 🐢 **Tuga** (o țestoasă) îți explică simplu, fără cuvinte tehnice: este modul obișnuit.
🐇 **Cone** (un iepure) îți arată și detaliile tehnice: porturi, ce a văzut scanarea, referințe. Îl pornești din
butonul „Avansat”.

**Cum decide.** Problemele și scorul vin doar din regulile oficiale ale concursului, nu dintr-o inteligență artificială:
același fișier dă mereu același rezultat.

**Siguranță.** Scanăm doar rețeaua noastră de laborator, cu acordul tuturor. Programul refuză adresele de pe internet,
alte rețele și orice scanare fără confirmare.

**Confidențialitate.** Adresele MAC sunt ascunse peste tot (rămâne doar partea producătorului). Istoricul stă doar pe
acest calculator și îl ștergi cu un clic, din pagina principală: „Șterge istoricul meu”.
""",
    },
    "en": {
        "title": "About ConeTuga",
        "body": """
**What it does.** ConeTuga looks at your home network, finds the devices and the "doors" they leave open (ports),
tells you in plain words what each one means and what to do, step by step. The history shows whether your score went
up after a fix.

**The two guides.** 🐢 **Tuga** (a tortoise) explains simply, with no technical words: the usual mode.
🐇 **Cone** (a hare) also shows the technical details: ports, what the scan saw, references. Turn it on with the
"Advanced" toggle.

**How it decides.** Problems and the score come only from the contest's official rules, never from an AI: the same
file always gives the same result.

**Safety.** We scan only our own lab network, with everyone's consent. The tool refuses internet addresses, other
networks and any scan without confirmation.

**Privacy.** MAC addresses are hidden everywhere (only the maker's part stays). The history stays on this computer,
and one click on the main page deletes it: "Delete my history".
""",
    },
}


def render() -> None:
    text = TEXT[current().lang]
    st.title(text["title"])
    st.markdown(text["body"])
