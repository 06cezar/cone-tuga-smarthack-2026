"""The ConeTuga web app (FR-11): run with `python -m streamlit run ui/app.py`.

This file is only the shell, after the mock-ups (D-mockup): page settings, the base style (ui/style.py: 16 px text, a
visible keyboard focus), the top bar on every page (the ConeTuga logo, the pages as tabs, the Tuga | Cone switch,
and RO | EN, in ui/state.py), and the look of the current mode (ui/theme.py: Tuga light, Cone dark). Each
page is one module in ui/pages/ with a `render()` function; to add a page, add one line to PAGES."""
import base64
import sys
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # `streamlit run ui/app.py` puts only ui/ on the path

from ui.assets import ASSETS_DIR  # noqa: E402
from ui.pages import about, ask, devices, home, scan, wiki  # noqa: E402
from ui.state import topbar_settings  # noqa: E402
from ui.style import PAGE_CSS  # noqa: E402  (16 px text and a visible keyboard focus, NFR-08)
from ui.theme import NAV_ACTIVE_KEY, TOPBAR_KEY, theme_css  # noqa: E402

# (module, Romanian title, English title, icon, URL path, short tab label RO, EN); the first page opens by default.
PAGES = [
    (home, "Acasă", "Home", "🏠", "acasa", "Acasă", "Home"),
    (devices, "Dispozitive", "Devices", "💻", "dispozitive", "Dispozitive", "Devices"),
    (ask, "Întreabă", "Ask", "💬", "intreaba", "Întreabă", "Ask"),
    (wiki, "Wiki amenințări", "Threat wiki", "📚", "wiki", "Wiki", "Wiki"),
    (scan, "Scanare", "Scan", "📡", "scanare", "Scanare", "Scan"),
    (about, "Despre", "About", "ℹ️", "despre", "Despre", "About"),
]
TOPBAR_WIDTHS = (2.0, 4.8, 3.9, 1.4)  # logo, pages, Tuga | Cone switch, RO | EN
LOGO_PICTURE = ASSETS_DIR / "tuga_hero.svg"


def logo_html() -> str:
    """The ConeTuga logo: Tuga with her cone hat, then "Cone" in blue and "Tuga" in green. Our own drawing, inlined so
    nothing is loaded; it is decoration beside the words, so its alternative text is empty."""
    picture = base64.b64encode(LOGO_PICTURE.read_bytes()).decode("ascii")
    return (f'<div class="ct-logo"><img src="data:image/svg+xml;base64,{picture}" alt="">'
            f'<span><span class="ct-cone">Cone</span><span class="ct-tuga">Tuga</span></span></div>')


def show_tabs(column, pages, current, lang: str) -> None:
    """The pages as tabs along the top; the current one is underlined (and read as the current page by the browser)."""
    with column, st.container(horizontal=True, vertical_alignment="center", gap="small"):
        for page, row in zip(pages, PAGES):
            label = row[5] if lang == "ro" else row[6]
            if page.url_path == current.url_path:
                with st.container(key=NAV_ACTIVE_KEY, width="content"):
                    st.page_link(page, label=label)
            else:
                st.page_link(page, label=label)


def main() -> None:
    st.set_page_config(page_title="ConeTuga", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
    st.markdown(PAGE_CSS, unsafe_allow_html=True)
    with st.container(key=TOPBAR_KEY):
        logo, tabs, mode, language = st.columns(TOPBAR_WIDTHS, vertical_alignment="center")
        settings = topbar_settings(mode, language)
        pages = [st.Page(row[0].render, title=row[1] if settings.lang == "ro" else row[2], icon=row[3],
                         url_path=row[4], default=i == 0)
                 for i, row in enumerate(PAGES)]
        current = st.navigation(pages, position="hidden")
        logo.markdown(logo_html(), unsafe_allow_html=True)
        show_tabs(tabs, pages, current, settings.lang)
    st.markdown(theme_css(settings.advanced), unsafe_allow_html=True)
    current.run()


main()
