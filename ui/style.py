"""The page's one fixed style, drawn by ui/app.py on every page (NFR-08). Its own module, with no Streamlit call, so the
tests read it without starting the app. It holds no scan text.

- Text of at least 16 px: Streamlit draws widget labels, radio options, buttons and expander titles at 14 px;
  max(1rem, 1em) lifts small text to 16 px and leaves headings as large as they are.
- A page that works from the keyboard: Streamlit marks a focused menu link only with a faint background, the same one
  the open page has, so the keyboard's place is hard to see (E's FE-E2 audit). A 3 px outline outside the focused link,
  button or expander shows it on both themes: FOCUS_COLOUR has at least 3:1 contrast against the light and the dark
  page and sidebar (WCAG 2.4.7 and 1.4.11; tests/test_ui_focus.py).
- The scan picker, Acasă's main feature: the box `st.container(key=PICKER_KEY)` draws (Streamlit gives it the class
  st-key-<key>) gets a border in FOCUS_COLOUR, a light tint of it behind, and larger labels, list and upload area. The
  tint is translucent, so it works on both themes, and the theme's own text keeps WCAG AA contrast on it
  (tests/test_ui_scan_picker.py)."""

FOCUS_COLOUR = "#2F7CF6"
PICKER_KEY = "scan_picker"
PICKER_TINT_ALPHA = 0.08  # how much FOCUS_COLOUR shows behind the picker: enough to set it apart, little enough for AA
PICKER_TINT = "rgba({}, {}, {}, {})".format(*(int(FOCUS_COLOUR[i:i + 2], 16) for i in (1, 3, 5)), PICKER_TINT_ALPHA)
PICKER_FIELD_HEIGHT = "3rem"  # the example list and the upload area, side by side at one height (Streamlit's: ~2.5rem)
PICKER_TEXT_SIZE = "1.2rem"  # the picker's labels and the chosen file name: a step above the page's 16 px text
PICKER = f".stApp .st-key-{PICKER_KEY}"
# Streamlit leaves 6rem (96 px) above the page's title, under a 60 px header. 4rem still clears the header and gives
# back 32 px, so with the picker box the headline and the score fit the first screen of a 1366×768 laptop in a browser
# window, about 650 px tall (E's review of #71: score line bottom at 649 px).
MAIN_TOP_PADDING = "4rem"
# The !important below: the 16 px rule above is !important too, and Streamlit's own styles set the sizes on the inner
# elements; a more specific selector with !important is how the picker's larger sizes win. The selectors are the
# data-testid and role attributes Streamlit 1.67 writes (its list is a react-aria ComboBox: role="group" and an input).

PAGE_CSS = f"""<style>
.stApp p, .stApp span, .stApp label, .stApp small, .stApp li, .stApp button, .stApp code {{
  font-size: max(1rem, 1em) !important; }}
.stApp a:focus-visible, .stApp button:focus-visible, .stApp summary:focus-visible {{
  outline: 3px solid {FOCUS_COLOUR} !important; outline-offset: 2px; }}
.stApp [data-testid="stMainBlockContainer"] {{ padding-top: {MAIN_TOP_PADDING}; }}
{PICKER} {{ border: 2px solid {FOCUS_COLOUR}; border-radius: 1rem; padding: 0.5rem 1.25rem 0.75rem;
  background: {PICKER_TINT}; }}
{PICKER} h3 {{ padding: 0.25rem 0 0 !important; }}
{PICKER} [data-testid="stVerticalBlock"] {{ gap: 0.5rem; }}
{PICKER} [data-testid="stWidgetLabel"] p {{ font-size: {PICKER_TEXT_SIZE} !important; font-weight: 600; }}
{PICKER} [data-testid="stSelectbox"] [role="group"] {{ min-height: {PICKER_FIELD_HEIGHT} !important; }}
{PICKER} [data-testid="stSelectbox"] input {{ font-size: {PICKER_TEXT_SIZE} !important; }}
{PICKER} [data-testid="stFileUploaderDropzone"] {{ min-height: {PICKER_FIELD_HEIGHT} !important;
  border: 2px dashed {FOCUS_COLOUR} !important; align-items: center; }}
</style>"""
