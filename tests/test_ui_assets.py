"""FE-E1: the pictures of the two guides, Tuga 🐢 and Cone 🐇 (ui/assets/). We ship them to every user, so they are
checked like any other file the page draws: safe XML with nothing that runs or loads from elsewhere, small, readable on
both themes (NFR-08), and drawn by Streamlit with their alternative text."""
import pytest
from defusedxml import ElementTree

from ui.assets import guide_picture

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

SPEAKERS = {"tuga": "Tuga", "cone": "Cone"}  # Narration.speaker -> the name every alternative text must say
LANGUAGES = ("ro", "en")
SVG = "{http://www.w3.org/2000/svg}"
MAX_PICTURE_BYTES = 4096  # "small" in the plan: each guide is an icon (about 1.5 KB today)
# Plain shapes only: no script, foreignObject, image, use, link or style, so a picture can neither run code nor load
# anything from elsewhere.
ALLOWED_TAGS = {"svg", "title", "g", "circle", "ellipse", "rect", "path", "polygon"}
# The page backgrounds of Streamlit's built-in light and dark themes; if FE-D5 sets its own, put its colours here.
PAGE_BACKGROUNDS = {"light": "#FFFFFF", "dark": "#0E1117"}
MIN_GRAPHIC_CONTRAST = 3.0  # WCAG 2.1 SC 1.4.11: the parts of a picture needed to see it, against what surrounds them
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def svg_root(speaker: str):
    path, _ = guide_picture(speaker, "en")
    return ElementTree.parse(path).getroot()


def local(tag: str) -> str:
    return tag.removeprefix(SVG)


def contrast(first: str, second: str) -> float:
    """The WCAG contrast ratio of two "#RRGGBB" colours, from 1 (the same) to 21 (black on white)."""
    def luminance(colour: str) -> float:
        channels = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("speaker", SPEAKERS)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_every_guide_has_a_picture_and_an_alternative_text(speaker, lang):
    path, alt = guide_picture(speaker, lang)
    assert path.is_file()
    assert SPEAKERS[speaker] in alt


def test_an_unknown_guide_or_language_is_an_error():
    with pytest.raises(KeyError):
        guide_picture("robot", "ro")
    with pytest.raises(KeyError):
        guide_picture("tuga", "fr")


@pytest.mark.parametrize("speaker", SPEAKERS)
def test_a_picture_is_small(speaker):
    path, _ = guide_picture(speaker, "ro")
    assert path.stat().st_size <= MAX_PICTURE_BYTES


@pytest.mark.parametrize("speaker", SPEAKERS)
def test_a_picture_has_only_plain_shapes_and_nothing_that_runs_or_loads(speaker):
    for element in svg_root(speaker).iter():
        assert local(element.tag) in ALLOWED_TAGS
        for name, value in element.attrib.items():
            assert not local(name).lower().startswith("on")  # no event handler
            assert "href" not in name.lower()  # no link to another file or site
            assert "url(" not in value and "javascript:" not in value.lower()


@pytest.mark.parametrize("speaker", SPEAKERS)
def test_a_picture_names_its_guide_for_screen_readers(speaker):
    root = svg_root(speaker)
    title = root.find(f"{SVG}title")
    assert root.get("role") == "img"
    assert root.get("aria-labelledby") == title.get("id")
    assert SPEAKERS[speaker] in title.text


@pytest.mark.parametrize("speaker", SPEAKERS)
def test_a_picture_reads_on_both_themes(speaker):
    """Each guide sits on its own light badge with a dark rim: on a dark page the badge stands out, on a light page the
    rim does, and the drawing's outlines are measured against the badge, so they read the same on both themes."""
    root = svg_root(speaker)
    badge = next(e for e in root.iter() if e.get("id") == "badge")
    assert contrast(badge.get("fill"), PAGE_BACKGROUNDS["dark"]) >= MIN_GRAPHIC_CONTRAST
    assert contrast(badge.get("stroke"), PAGE_BACKGROUNDS["light"]) >= MIN_GRAPHIC_CONTRAST
    outlines = {e.get("stroke") for e in root.iter() if e is not badge and e.get("stroke")}
    assert outlines
    for colour in outlines:
        assert contrast(colour, badge.get("fill")) >= MIN_GRAPHIC_CONTRAST


def test_streamlit_draws_both_guides_with_their_alternative_text():
    app = AppTest.from_string("""
import streamlit as st
from ui.assets import guide_picture
for speaker in ("tuga", "cone"):
    path, alt = guide_picture(speaker, "ro")
    st.image(str(path), width=48, alt=alt)
""", default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    pictures = [element.proto.imgs[0] for element in app.get("image")]
    assert [p.alt for p in pictures] == [guide_picture(s, "ro")[1] for s in ("tuga", "cone")]
    assert all(p.url.startswith("data:image/svg+xml;base64,") for p in pictures)
