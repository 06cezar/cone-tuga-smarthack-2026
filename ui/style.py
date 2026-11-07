"""The page's one fixed style, drawn by ui/app.py on every page (NFR-08). Its own module, with no Streamlit call, so the
tests read it without starting the app. It holds no scan text.

- Text of at least 16 px: Streamlit draws widget labels, radio options, buttons and expander titles at 14 px;
  max(1rem, 1em) lifts small text to 16 px and leaves headings as large as they are.
- A page that works from the keyboard: Streamlit marks a focused menu link only with a faint background, the same one
  the open page has, so the keyboard's place is hard to see (E's FE-E2 audit). A 3 px outline outside the focused link,
  button or expander shows it on both themes: FOCUS_COLOUR has at least 3:1 contrast against the light and the dark
  page and sidebar (WCAG 2.4.7 and 1.4.11; tests/test_ui_focus.py)."""

FOCUS_COLOUR = "#2F7CF6"

PAGE_CSS = f"""<style>
.stApp p, .stApp span, .stApp label, .stApp small, .stApp li, .stApp button {{ font-size: max(1rem, 1em) !important; }}
.stApp a:focus-visible, .stApp button:focus-visible, .stApp summary:focus-visible {{
  outline: 3px solid {FOCUS_COLOUR} !important; outline-offset: 2px; }}
</style>"""
