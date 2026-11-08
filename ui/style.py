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
  (tests/test_ui_scan_picker.py).
- A friendly look for everyone, a child and a grandparent too (NFR-08, NFR-09): each device is a rounded card with a
  coloured band on its left by status (the status's icon and word stay in its title: colour is never alone); what
  Tuga 🐢 or Cone 🐇 says sits in a speech bubble; "Ce-ar fi dacă repar?" is a green note; text has more room between
  lines and steps; buttons and card titles are at least 48 px tall, easy to hit with a shaky hand or a finger (WCAG
  2.5.5 asks 44). ui/cards.py draws the blocks with st.container(key=...), which Streamlit gives the class
  st-key-<key>; CARD_KEY, SAY_KEY and GAIN_KEY are the keys' first part. Every tint is translucent, so it works on
  both themes and the theme's own text keeps WCAG AA contrast on it (tests/test_ui_friendly_style.py).
- The talking guide (ui/talking.py): beside Acasă's headline, Tuga walks in slowly (Cone hops in quickly), the
  headline sits in the guide's speech bubble, and while the guide reads it aloud the picture sways. With "reduce
  motion" turned on in the operating system, nothing moves."""

# "🔍 Scris mare" (B's proposal, 2026-11-08): the whole page larger, for a grandparent or a jury reading from a distance.
# Off by default (Cezar's call): at 1366×768 with it on, the headline ends at 894 px and the score at 1070 px, below the
# first screen that live check 2 needs; with it off they end at 579 and 720 px. The presenter turns it on for the pitch.
# Streamlit sizes its text and boxes in rem, so a larger root size scales them all; off, the 16 px rule holds (NFR-08).
LARGE_TEXT_PERCENT = 125  # of the browser's root size: 16 px becomes 20 px
LARGE_TEXT_CSS = f"<style>html {{ font-size: {LARGE_TEXT_PERCENT}% !important; }}</style>"

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
# The friendly look (see above). One colour per device status (ui.view.device_status), for the card's band and tint.
STATUS_COLOURS = {"high": "#CF222E", "medium": "#BF8700", "low": "#0969DA", "info": "#6E7781",
                  "unchecked": "#8250DF", "none": "#1A7F37"}
TUGA_COLOUR = "#1A7F37"  # Tuga is a green turtle
CONE_COLOUR = "#8250DF"  # Cone's bubble, in Advanced mode
GAIN_COLOUR = "#1A7F37"  # the score goes up: good news
TINT_ALPHA = 0.08  # as the picker's: enough to tell the blocks apart, little enough for AA on both themes
BUBBLE_BORDER_ALPHA = 0.35  # a speech bubble's outline: stronger than its tint, still soft
BAND_WIDTH = "6px"  # the coloured band on a card's left
ROUNDING = "1rem"
TARGET_HEIGHT = "48px"  # buttons and card titles, above WCAG 2.5.5's 44 px
LINE_HEIGHT = 1.6  # more room between lines for a slow reader (WCAG 1.4.12 tests with 1.5)
STEP_GAP = "0.4rem"  # between a finding's numbered steps
CARD_KEY, SAY_KEY, GAIN_KEY = "card", "say", "gain"
VERDICT_KEY = "verdict"  # block_key(VERDICT_KEY, light): the score line as a large tinted banner (D-fe-checkup)
LIGHT_COLOURS = {"green": "#1A7F37", "yellow": "#BF8700", "red": "#CF222E"}
HEADLINE_KEY = "headline"  # block_key(HEADLINE_KEY, speaker): the guide's picture and the headline beside it
TALKING_CLASS = "conetuga-talking"  # on the headline block while the guide speaks (ui/talking.py)
NOTE_ATTRIBUTE = "data-conetuga-note"  # on the headline block: how to add a voice, when there is none
TUGA_WALK_MS = 1800  # a tortoise walks in slowly
CONE_HOP_MS = 600  # a hare hops in quickly
SWAY_MS = 450  # one sway of the guide while it speaks


def tint(colour: str, alpha: float = TINT_ALPHA) -> str:
    """A translucent version of a #RRGGBB colour, for a background that works on both themes."""
    return "rgba({}, {}, {}, {})".format(*(int(colour[i:i + 2], 16) for i in (1, 3, 5)), alpha)


def block_key(kind: str, *parts) -> str:
    """A container key from its kind and parts, with only letters, digits and dashes, so the class Streamlit makes from
    it (st-key-<key>) is a plain CSS class: "card-high-192-168-1-40"."""
    words = [kind, *(str(part) for part in parts)]
    return "-".join("".join(c if c.isalnum() else "-" for c in word.lower()) for word in words)


CARDS_CSS = "\n".join(
    f'.stApp [class*="st-key-{CARD_KEY}-{status}-"] {{ border-left: {BAND_WIDTH} solid {colour}; '
    f"background: {tint(colour)}; border-radius: {ROUNDING}; padding: 0.25rem 0.5rem 0.25rem 0.75rem; }}"
    for status, colour in STATUS_COLOURS.items())
SAY_CSS = "\n".join(
    f'.stApp [class*="st-key-{SAY_KEY}-{speaker}-"] {{ background: {tint(colour)}; '
    f"border: 2px solid {tint(colour, BUBBLE_BORDER_ALPHA)}; border-radius: {ROUNDING} {ROUNDING} {ROUNDING} 0.25rem; padding: 0.5rem 1rem; }}"
    for speaker, colour in (("tuga", TUGA_COLOUR), ("cone", CONE_COLOUR)))
FRIENDLY_CSS = f"""{CARDS_CSS}
{SAY_CSS}
.stApp [class*="st-key-{GAIN_KEY}-"] {{ background: {tint(GAIN_COLOUR)}; border-radius: 999px; padding: 0.1rem 1rem; }}
.stApp [class*="st-key-{CARD_KEY}-"] [data-testid="stExpander"] details {{ border: none; }}
.stApp [data-testid="stMarkdownContainer"] p, .stApp [data-testid="stMarkdownContainer"] li {{
  line-height: {LINE_HEIGHT}; }}
.stApp [data-testid="stMarkdownContainer"] li {{ margin-bottom: {STEP_GAP}; }}
.stApp [data-testid="stExpander"] summary {{ min-height: {TARGET_HEIGHT}; font-weight: 600; }}
.stApp button {{ min-height: {TARGET_HEIGHT}; border-radius: 999px !important; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"] [data-testid="stElementContainer"]:has(iframe) {{ display: none; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"] img {{ cursor: pointer; transition: transform 0.2s; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"] img:hover {{ transform: scale(1.06); }}
.stApp .st-key-{HEADLINE_KEY}-tuga img {{ animation: guide-walk-in {TUGA_WALK_MS}ms ease-out both; }}
.stApp .st-key-{HEADLINE_KEY}-cone img {{ animation: guide-hop-in {CONE_HOP_MS}ms ease-out both; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"].{TALKING_CLASS} img {{
  animation: guide-sway {SWAY_MS}ms ease-in-out infinite alternate; filter: drop-shadow(0 0 6px {TUGA_COLOUR}); }}
.stApp .st-key-{HEADLINE_KEY}-tuga [data-testid="stColumn"]:last-child {{ background: {tint(TUGA_COLOUR)};
  border-radius: {ROUNDING} {ROUNDING} {ROUNDING} 0.25rem; padding: 0 1rem; }}
.stApp .st-key-{HEADLINE_KEY}-cone [data-testid="stColumn"]:last-child {{ background: {tint(CONE_COLOUR)};
  border-radius: {ROUNDING} {ROUNDING} {ROUNDING} 0.25rem; padding: 0 1rem; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"][{NOTE_ATTRIBUTE}]::after {{ content: attr({NOTE_ATTRIBUTE}); display: block;
  padding: 0.25rem 0.5rem; }}
@keyframes guide-walk-in {{ 0% {{ transform: translateX(-56px) rotate(-6deg); opacity: 0; }}
  30% {{ transform: translateX(-36px) rotate(4deg); opacity: 1; }} 60% {{ transform: translateX(-16px) rotate(-4deg); }}
  100% {{ transform: none; }} }}
@keyframes guide-hop-in {{ 0% {{ transform: translateY(-24px); opacity: 0; }} 60% {{ transform: translateY(4px);
  opacity: 1; }} 100% {{ transform: none; }} }}
@keyframes guide-sway {{ from {{ transform: translateY(0) rotate(-4deg); }} to {{ transform: translateY(-4px) rotate(4deg); }} }}
.stApp [class*="st-key-{VERDICT_KEY}-"] {{ border-radius: {ROUNDING}; padding: 0.25rem 1.25rem; }}
{chr(10).join(f'.stApp .st-key-{VERDICT_KEY}-{light} {{{{ background: {tint(colour)}; border: 2px solid {colour}; }}}}'
              for light, colour in LIGHT_COLOURS.items())}
.stApp [data-testid="stCheckbox"] label {{ min-height: {TARGET_HEIGHT}; align-items: center; font-weight: 600; }}
@media (prefers-reduced-motion: reduce) {{ .stApp [class*="st-key-{HEADLINE_KEY}-"] img {{ animation: none !important;
  transition: none; }} }}"""

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
{FRIENDLY_CSS}
</style>"""
