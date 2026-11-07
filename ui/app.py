"""The ConeTuga web app (FR-11): run with `python -m streamlit run ui/app.py`.

This file is only the shell: page settings, the page style (ui/style.py: 16 px text, a visible keyboard focus), the
sidebar (language and the Simple/Advanced mode, in ui/state.py) and the list of pages. Each page is one module in ui/pages/ with a `render()` function; to add a page, add
one line to PAGES."""
import sys
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # `streamlit run ui/app.py` puts only ui/ on the path

from ui.pages import about, devices, home, scan, wiki  # noqa: E402
from ui.state import sidebar_settings  # noqa: E402
from ui.style import PAGE_CSS  # noqa: E402  (16 px text and a visible keyboard focus, NFR-08)


# (module, Romanian title, English title, icon, URL path); the first one is the page that opens by default.
PAGES = [
    (home, "Acasă", "Home", "🏠", "acasa"),
    (devices, "Dispozitive", "Devices", "💻", "dispozitive"),
    (wiki, "Wiki amenințări", "Threat wiki", "📚", "wiki"),
    (scan, "Scanare", "Scan", "📡", "scanare"),
    (about, "Despre", "About", "ℹ️", "despre"),
]


def main() -> None:
    st.set_page_config(page_title="ConeTuga", page_icon="🛡️", layout="wide")
    st.markdown(PAGE_CSS, unsafe_allow_html=True)
    settings = sidebar_settings()
    pages = [st.Page(module.render, title=ro if settings.lang == "ro" else en, icon=icon, url_path=path,
                     default=i == 0)
             for i, (module, ro, en, icon, path) in enumerate(PAGES)]
    st.navigation(pages).run()


main()
