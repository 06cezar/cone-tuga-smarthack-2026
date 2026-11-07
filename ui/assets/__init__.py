"""The pictures of the two guides, Tuga 🐢 (the tortoise, Simple mode) and Cone 🐇 (the hare, Advanced mode): our own
drawings, one small SVG file each (FE-E1).

A picture is only a companion: a page shows it next to the guide's name and words, never alone, so a person who can't
see it loses nothing (NFR-08). The alternative text is what a screen reader says instead. Show one with
`path, alt = guide_picture(narration.speaker, lang)` and `st.image(str(path), width=48, alt=alt)`."""
from pathlib import Path

ASSETS_DIR = Path(__file__).resolve().parent

# Narration.speaker ("tuga" or "cone", docs/frontend-plan.md) -> the picture file and its alternative text.
GUIDES = {
    "tuga": ("tuga.svg", {"ro": "Tuga, broasca țestoasă care îți explică pe înțeles",
                          "en": "Tuga, the tortoise who explains things in plain words"}),
    "cone": ("cone.svg", {"ro": "Cone, iepurele care îți arată detaliile tehnice",
                          "en": "Cone, the hare who shows you the technical details"}),
}


def guide_picture(speaker: str, lang: str) -> tuple[Path, str]:
    """The picture file and its alternative text for a guide ("tuga" or "cone") in "ro" or "en". Any other speaker or
    language raises KeyError, so a typo fails a test instead of showing a page without its guide."""
    file_name, alt = GUIDES[speaker]
    return ASSETS_DIR / file_name, alt[lang]
