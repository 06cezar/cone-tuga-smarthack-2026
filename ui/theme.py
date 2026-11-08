"""The two looks of the mock-ups (D-mockup): Tuga's light, cozy page in Simple mode and Cone's dark, technical page in
Advanced mode, switched by the mode toggle (the UI kit: "Tuga Light Mode vs Cone Dark Mode").

Streamlit's own theme stays light (.streamlit/config.toml), and this style sets every colour the page shows on top of
it, so the look depends only on the mode. Every pair of text and background colours below keeps WCAG AA contrast
(tests/test_ui_theme.py), every status keeps its icon and word (colour is never alone, NFR-08), and no font or file is
loaded from outside: the rounded fonts are used when the computer has them, else the system font."""
from ui.style import CARD_KEY, CHIP_KEY, GAIN_KEY, HEADLINE_KEY, PICKER_KEY, SAY_KEY, VERDICT_KEY

FONTS = '"Nunito", "Poppins", "Quicksand", "Segoe UI", system-ui, sans-serif'
# Streamlit draws its icons (the expander's arrow, the upload cloud) as a word in this font, which turns the word into
# a picture. The page font above also covers `span`, so without this rule the word shows ("keyboard_arrow_right").
ICON_FONT = '"Material Symbols Rounded"'
MONO_FONTS ='"JetBrains Mono", "Cascadia Mono", Consolas, "Courier New", monospace'
CARD_ROUNDING = "24px"
TRANSITION = "background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease"

# The blocks the pages draw with st.container(key=...), named here so the style and the code agree.
TOPBAR_KEY = "ct-topbar"
NAV_ACTIVE_KEY = "ct-nav-active"
MODE_KEY = "ct-mode"
LANG_KEY = "ct-lang"
SCORE_KEY = "ct-score"
DANGER_KEY = "ct-danger"
SAFE_KEY = "ct-safe"
AUDIT_KEY = "ct-audit"
HISTORY_KEY = "ct-hist"
FIX_NOW_KEY = "ct-fix-now"
HOME_TITLE_KEY = "ct-home-title"  # Acasă's title: read by screen readers, shown by the logo
CONE_BUBBLE_KEY = "ct-cone-bubble"
TREND_LINE_KEY = "ct-trend-line"
# Istoric (ui/pages/history.py): the change banner, the red delete button, the trend, the list, the export, the
# comparator and the guide's summary. None of them starts with "ct-hist-green/-yellow/-red", the before/after cards.
HISTORY_BANNER_KEY = "ct-hist-banner"
HISTORY_DELETE_KEY = "ct-hist-delete"
HISTORY_TREND_KEY = "ct-hist-trend"
HISTORY_LIST_KEY = "ct-hist-list"
HISTORY_EXPORT_KEY = "ct-hist-export"
HISTORY_COMPARE_KEY = "ct-hist-compare"
HISTORY_SAY_KEY = "ct-hist-say"
# Despre (ui/pages/about.py): the app and its guides, the ethical shield, and the wiki's search and filters.
ABOUT_INTRO_KEY = "ct-about-intro"
ABOUT_SHIELD_KEY = "ct-about-shield"
WIKI_FILTER_KEY = "ct-wiki-filter"
DELETE_FILL = "#B91C1C"  # "Șterge istoricul meu": white bold text on it is 6.5:1 (AA), red in both looks
DELETE_TEXT = "#FFFFFF"
# Streamlit's info, warning and success boxes keep their light colours under its light theme; on Cone's dark page they
# take the page's colours instead, so their (light) text keeps its contrast.
ALERTS = ('.stApp [data-testid="stAlertContainer"] { background: var(--ct-soft) !important; '
          "border: 1px solid var(--ct-line); }")

THEMES = {
    False: {  # Tuga: light, warm, soft shadows
        "page": "#FAF6F0", "card": "#FFFFFF", "soft": "#F3EFE7", "line": "#E5DCCB", "text": "#1F2937",
        "muted": "#4B5563", "blue": "#2563EB", "green": "#15803D", "link": "#1D4ED8",
        "shadow": "0 14px 30px -18px rgba(31, 41, 55, 0.35)",
        "bubble": "#EEF3FA", "bubble_line": "#B9C8DC",
        "danger_bg": "#FEF2F2", "danger_line": "#EF4444", "ok_bg": "#F0FDF4", "ok_line": "#22C55E",
        "code_bg": "#F3EFE7", "code": "#9A3412", "gain_bg": "#DCFCE7", "gain_text": "#14532D",
        "say_tuga": "#F1F8EC", "say_tuga_line": "#C9E2BC", "say_cone": "#F1ECFF", "say_cone_line": "#D6CCF5",
        "table_head": "#F3EFE7",
    },
    True: {  # Cone: dark navy, neon blue
        "page": "#0B1220", "card": "#111C30", "soft": "#0F1A2D", "line": "#1E3A5F", "text": "#E2E8F0",
        "muted": "#94A3B8", "blue": "#60A5FA", "green": "#4ADE80", "link": "#7DD3FC",
        "shadow": "0 0 0 1px rgba(56, 189, 248, 0.18), 0 0 28px -8px rgba(56, 189, 248, 0.35)",
        "bubble": "#16243D", "bubble_line": "#38BDF8",
        "danger_bg": "#2A1420", "danger_line": "#F87171", "ok_bg": "#10261C", "ok_line": "#4ADE80",
        "code_bg": "#0B1220", "code": "#7DD3FC", "gain_bg": "#10261C", "gain_text": "#86EFAC",
        "say_tuga": "#132A1E", "say_tuga_line": "#2F6B45", "say_cone": "#1A1F3D", "say_cone_line": "#4F46E5",
        "table_head": "#0F1A2D",
    },
}
# The traffic light and the severities, for bands, badges and the score: (strong colour, text colour on a card).
STATUS = {
    False: {"high": ("#EF4444", "#B91C1C"), "medium": ("#F59E0B", "#92400E"), "low": ("#3B82F6", "#1D4ED8"),
            "info": ("#94A3B8", "#475569"), "none": ("#22C55E", "#166534"), "unchecked": ("#8B5CF6", "#6D28D9")},
    True: {"high": ("#F87171", "#FCA5A5"), "medium": ("#FBBF24", "#FCD34D"), "low": ("#60A5FA", "#93C5FD"),
           "info": ("#94A3B8", "#CBD5E1"), "none": ("#4ADE80", "#86EFAC"), "unchecked": ("#A78BFA", "#C4B5FD")},
}
LIGHTS = {"green": "none", "yellow": "medium", "red": "high"}  # traffic light -> the status whose colours it uses
FIX_NOW_FILL = "#15803D"  # the big "Repară acum": white bold text on it is 5:1
FIX_NOW_TEXT = "#FFFFFF"


def status_text(status: str, dark: bool) -> str:
    """The colour for a status's words on a card (AA on the card)."""
    return STATUS[dark][status][1]


def _variables(dark: bool) -> str:
    colours = {**THEMES[dark],
               **{f"st-{s}": strong for s, (strong, _text) in STATUS[dark].items()},
               **{f"st-{s}-text": text for s, (_strong, text) in STATUS[dark].items()}}
    return " ".join(f"--ct-{name.replace('_', '-')}: {value};" for name, value in colours.items())


def theme_css(dark: bool) -> str:
    """The whole look for one mode, as one <style> block drawn after ui/style.py's PAGE_CSS."""
    card = ("background: var(--ct-card); border: 1px solid var(--ct-line); border-radius: " + CARD_ROUNDING
            + "; box-shadow: var(--ct-shadow); padding: 1rem 1.25rem;")
    bands = "\n".join(
        f'.stApp [class*="st-key-{CARD_KEY}-{s}-"] {{ {card} border-left: 7px solid var(--ct-st-{s}); }}'
        for s in STATUS[dark])
    chips = "\n".join(
        f'.stApp .st-key-{CHIP_KEY}-{s} {{ {card} border-top: 6px solid var(--ct-st-{s}); text-align: center; }}'
        for s in ("high", "medium", "low", "info"))
    history = "\n".join(
        f'.stApp [class*="st-key-{HISTORY_KEY}-{light}"] {{ {card} border-top: 8px solid var(--ct-st-{status}); }}'
        for light, status in LIGHTS.items())
    return f"""<style>
:root {{ {_variables(dark)} }}
.stApp {{ background: var(--ct-page) !important; color: var(--ct-text); font-family: {FONTS}; transition: {TRANSITION}; }}
.stApp [data-testid="stHeader"] {{ display: none; }}
.stApp [data-testid="stMainBlockContainer"] {{ padding: 1rem 2rem 3rem !important; max-width: 1560px; }}
.stApp p, .stApp li, .stApp label, .stApp span, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp strong,
.stApp em, .stApp summary, .stApp small {{ color: var(--ct-text); font-family: {FONTS}; }}
.stApp [data-testid="stIconMaterial"] {{ font-family: {ICON_FONT} !important; }}
.stApp h1, .stApp h2, .stApp h3, .stApp h4 {{ font-weight: 800; letter-spacing: -0.02em; }}
.stApp h1 {{ font-size: 1.75rem !important; }}
.stApp a {{ color: var(--ct-link); }}
.stApp code {{ background: var(--ct-code-bg); color: var(--ct-code); }}
.stApp hr {{ border-color: var(--ct-line); }}

/* The top bar: logo, pages, the Tuga/Cone switch, RO | EN */
.stApp .st-key-{TOPBAR_KEY} {{ border-bottom: 1px solid var(--ct-line); padding: 0.25rem 0 0.75rem; margin-bottom: 0.5rem; }}
.stApp .ct-logo {{ display: flex; align-items: center; gap: 0.4rem; font-size: 1.7rem !important; font-weight: 900;
  letter-spacing: -0.03em; white-space: nowrap; }}
.stApp .ct-logo img {{ width: 46px; height: 46px; }}
.stApp .ct-logo .ct-cone {{ color: var(--ct-blue); }}
.stApp .ct-logo .ct-tuga {{ color: var(--ct-green); }}
.stApp .st-key-{TOPBAR_KEY} [data-testid="stPageLink"] a {{ border-bottom: 3px solid transparent; border-radius: 0;
  padding: 0.2rem 0.3rem; background: transparent; }}
.stApp .st-key-{HOME_TITLE_KEY} {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }}
.stApp .st-key-{PICKER_KEY} [data-testid="stFileUploaderDropzone"] {{ padding: 0.35rem 0.75rem; }}
.stApp .st-key-{PICKER_KEY} [data-testid="stVerticalBlock"] {{ gap: 0.35rem; }}
.stApp .st-key-{TOPBAR_KEY} [data-testid="stPageLink"] p {{ font-size: 1rem !important; font-weight: 700; white-space: nowrap; }}
.stApp .st-key-{NAV_ACTIVE_KEY} [data-testid="stPageLink"] a {{ border-bottom-color: var(--ct-blue); }}
.stApp .st-key-{NAV_ACTIVE_KEY} [data-testid="stPageLink"] p {{ color: var(--ct-blue); }}
.stApp .st-key-{MODE_KEY} {{ background: var(--ct-soft); border: 1px solid var(--ct-line); border-radius: 22px;
  padding: 0.4rem 1rem 0.2rem; }}
.stApp .st-key-{MODE_KEY} p {{ font-weight: 700; white-space: nowrap; }}
.stApp [class*="st-key-{MODE_KEY}-"][class*="-on"] p {{ color: var(--ct-blue); font-weight: 900; }}
.stApp [class*="st-key-{MODE_KEY}-"][class*="-off"] p {{ color: var(--ct-muted); }}
.stApp .st-key-{LANG_KEY} label p {{ font-weight: 800; }}

/* Cards */
.stApp .st-key-{PICKER_KEY}, .stApp .st-key-{SCORE_KEY}, .stApp .st-key-{SAFE_KEY}, .stApp .st-key-{AUDIT_KEY},
.stApp [class*="st-key-{HEADLINE_KEY}-"], .stApp [class*="st-key-{VERDICT_KEY}-"],
.stApp .st-key-{HISTORY_TREND_KEY}, .stApp .st-key-{HISTORY_LIST_KEY}, .stApp .st-key-{HISTORY_EXPORT_KEY},
.stApp .st-key-{HISTORY_COMPARE_KEY}, .stApp .st-key-{ABOUT_INTRO_KEY}, .stApp .st-key-{ABOUT_SHIELD_KEY},
.stApp .st-key-{WIKI_FILTER_KEY} {{ {card} }}
.stApp .st-key-{PICKER_KEY} {{ padding: 0.5rem 1.25rem 0.75rem; }}
.stApp .st-key-{PICKER_KEY} h3 {{ font-size: 1.15rem !important; }}
{bands}
{chips}
{history}
.stApp [class*="st-key-{CARD_KEY}-"] [data-testid="stExpander"] details {{ background: transparent; border: none;
  box-shadow: none; }}
.stApp [data-testid="stExpander"] details {{ background: var(--ct-card); border: 1px solid var(--ct-line);
  border-radius: 18px; box-shadow: var(--ct-shadow); }}

/* The score card: its title and the small badge, then the gauge */
.stApp .ct-card-head {{ display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }}
.stApp .ct-card-head .ct-card-title {{ font-size: 1.5rem !important; font-weight: 800; }}
.stApp .ct-pill {{ display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 999px; padding: 0.2rem 0.8rem;
  font-weight: 800; background: var(--ct-soft); border: 1px solid var(--ct-line); }}
.stApp .ct-dot {{ width: 0.8rem; height: 0.8rem; border-radius: 50%; display: inline-block; }}

/* The worst problem: red card, siren, the device in large type, the green button */
.stApp .st-key-{DANGER_KEY}-on {{ background: var(--ct-danger-bg); border: 4px solid var(--ct-danger-line);
  border-radius: {CARD_ROUNDING}; box-shadow: var(--ct-shadow); padding: 1rem 1.5rem 1.25rem; text-align: center; }}
.stApp .st-key-{DANGER_KEY}-off {{ background: var(--ct-ok-bg); border: 3px solid var(--ct-ok-line);
  border-radius: {CARD_ROUNDING}; box-shadow: var(--ct-shadow); padding: 1rem 1.5rem 1.25rem; text-align: center; }}
.stApp .ct-alert-head {{ display: flex; justify-content: center; align-items: center; gap: 0.75rem;
  font-size: 1.55rem !important; font-weight: 900; text-transform: uppercase; letter-spacing: 0.01em; }}
.stApp .ct-alert-head .ct-siren {{ font-size: 2.6rem !important; }}
.stApp [class*="st-key-{DANGER_KEY}-"] h2 {{ font-size: 1.1rem !important; font-weight: 600; line-height: 1.45; text-align: center; }}
.stApp [class*="st-key-{DANGER_KEY}-"] h2 .ct-device {{ display: block; font-size: 2.1rem !important; font-weight: 900;
  line-height: 1.2; margin-bottom: 0.4rem; }}
.stApp [class*="st-key-{DANGER_KEY}-"] .ct-risk {{ font-size: 1.3rem !important; line-height: 1.4; }}
.stApp .ct-sr {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0);
  white-space: nowrap; }}
.stApp .st-key-{FIX_NOW_KEY} a {{ display: flex; align-items: center; justify-content: center; gap: 0.6rem;
  min-height: 64px; padding: 0.5rem 1rem; border-radius: 18px; background: {FIX_NOW_FILL};
  color: {FIX_NOW_TEXT} !important; font-size: 1.9rem !important; font-weight: 900; text-decoration: none; text-transform: uppercase;
  box-shadow: 0 10px 22px -10px rgba(21, 128, 61, 0.8); transition: transform 0.15s ease; }}
.stApp .st-key-{FIX_NOW_KEY} a:hover {{ transform: translateY(-2px); }}

/* Devices with no problem */
.stApp .ct-safe-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 0.9rem; }}
.stApp .ct-safe-item {{ display: flex; align-items: center; gap: 0.6rem; font-size: 1.15rem !important; font-weight: 700; }}
.stApp .ct-check {{ width: 1.7rem; height: 1.7rem; border-radius: 50%; background: var(--ct-text); color: var(--ct-card);
  display: inline-flex; align-items: center; justify-content: center; font-size: 1rem !important; font-weight: 900; flex: none; }}
.stApp .ct-device-icon {{ width: 2.6rem; height: 2.6rem; border-radius: 50%; background: var(--ct-soft);
  display: inline-flex; align-items: center; justify-content: center; font-size: 1.5rem !important; flex: none; }}

/* A guide's card: the picture and its speech bubble */
.stApp [class*="st-key-{HEADLINE_KEY}-"] [data-testid="stColumn"]:last-child {{ background: var(--ct-bubble);
  border: 2px solid var(--ct-bubble-line); border-radius: 22px; padding: 0.75rem 1rem; position: relative; }}
.stApp [class*="st-key-{HEADLINE_KEY}-"] [data-testid="stColumn"]:last-child p {{ font-size: 1.2rem !important; line-height: 1.5; }}
.stApp .st-key-{CONE_BUBBLE_KEY} {{ background: var(--ct-bubble); border: 2px solid var(--ct-bubble-line);
  border-radius: 22px; padding: 0.75rem 1rem; box-shadow: 0 0 18px -6px var(--ct-bubble-line); }}
.stApp .st-key-{CONE_BUBBLE_KEY} p {{ font-size: 1.15rem !important; line-height: 1.5; }}
.stApp [class*="st-key-{TREND_LINE_KEY}-"] h3 {{ font-size: 1.05rem !important; font-weight: 700; color: var(--ct-muted); }}
.stApp [class*="st-key-{DANGER_KEY}-"] p {{ font-size: 1.25rem !important; }}
.stApp [class*="st-key-{SAY_KEY}-tuga-"] {{ background: var(--ct-say-tuga); border: 1px solid var(--ct-say-tuga-line);
  border-radius: 18px; padding: 0.5rem 1rem; }}
.stApp [class*="st-key-{SAY_KEY}-cone-"] {{ background: var(--ct-say-cone); border: 1px solid var(--ct-say-cone-line);
  border-radius: 18px; padding: 0.5rem 1rem; }}
.stApp [class*="st-key-{GAIN_KEY}-"] {{ background: var(--ct-gain-bg); border-radius: 999px; padding: 0.1rem 1rem; }}
.stApp [class*="st-key-{GAIN_KEY}-"] p, .stApp [class*="st-key-{GAIN_KEY}-"] strong {{ color: var(--ct-gain-text); }}

/* Cone's technical audit table */
.stApp .ct-audit-head {{ display: flex; justify-content: space-between; align-items: center; gap: 1rem; }}
.stApp .ct-audit-title {{ font-size: 1.6rem !important; font-weight: 800; }}
.stApp .ct-badge-mode {{ border: 2px solid var(--ct-blue); color: var(--ct-blue); border-radius: 12px;
  padding: 0.3rem 0.9rem; font-weight: 800; }}
.stApp .ct-table-wrap {{ overflow-x: auto; border: 1px solid var(--ct-line); border-radius: 16px; }}
.stApp table.ct-table {{ width: 100%; border-collapse: collapse; font-size: 1rem !important; }}
.stApp table.ct-table th {{ background: var(--ct-table-head); color: var(--ct-muted); text-transform: uppercase;
  font-size: 1rem !important; letter-spacing: 0.04em; text-align: left; padding: 0.7rem 0.8rem; border-bottom: 1px solid var(--ct-line); }}
.stApp table.ct-table td {{ padding: 0.8rem; border-bottom: 1px solid var(--ct-line); vertical-align: middle;
  color: var(--ct-text); }}
.stApp table.ct-table .ct-mono {{ font-family: {MONO_FONTS}; }}
.stApp table.ct-table .ct-ip {{ color: var(--ct-link); font-family: {MONO_FONTS}; font-weight: 700; }}
.stApp .ct-finding {{ display: inline-block; margin: 0.15rem 0.2rem 0.15rem 0; padding: 0.25rem 0.6rem; border-radius: 10px;
  border: 2px solid var(--ct-st-info); font-weight: 700; }}
{chr(10).join(f'.stApp .ct-finding-{s} {{ border-color: var(--ct-st-{s}); color: var(--ct-st-{s}-text); }}' for s in STATUS[dark])}
.stApp .ct-ref {{ display: inline-block; margin: 0.15rem 0.2rem 0.15rem 0; padding: 0.2rem 0.55rem; border-radius: 10px;
  border: 1px solid var(--ct-line); color: var(--ct-muted); white-space: nowrap; }}

/* Before and after */
.stApp .ct-big-score {{ font-size: 3.2rem !important; font-weight: 900; line-height: 1; }}
.stApp .ct-big-score small {{ font-size: 1.6rem !important; color: var(--ct-muted); }}
.stApp .ct-threat {{ display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; margin: 0.5rem 0;
  padding: 0.6rem 0.9rem; border-radius: 14px; border-left: 6px solid var(--ct-st-high); background: var(--ct-danger-bg); }}
.stApp .ct-threat.ct-resolved {{ border-left-color: var(--ct-st-none); background: var(--ct-ok-bg); }}
/* Istoric: the change banner and its counts, the red delete button, the guide's summary */
.stApp .st-key-{HISTORY_BANNER_KEY} {{ {card} border-left: 7px solid var(--ct-blue); background: var(--ct-bubble); }}
.stApp .ct-chips {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.25rem 0 0.5rem; }}
.stApp .ct-chip {{ display: inline-flex; align-items: center; gap: 0.35rem; border-radius: 999px; padding: 0.3rem 0.9rem;
  background: var(--ct-card); border: 1px solid var(--ct-line); }}
.stApp .st-key-{HISTORY_DELETE_KEY} button {{ background: {DELETE_FILL} !important; border: 2px solid {DELETE_FILL} !important;
  min-height: 52px; }}
.stApp .st-key-{HISTORY_DELETE_KEY} button p {{ color: {DELETE_TEXT} !important; font-weight: 800; }}
.stApp [class*="st-key-{HISTORY_SAY_KEY}-"] {{ background: var(--ct-bubble); border: 2px solid var(--ct-bubble-line);
  border-radius: 22px; padding: 0.5rem 1rem; margin: 0.5rem 0; }}
/* Narrow cards (two side by side in a column): long codes and tags wrap instead of spilling out */
.stApp .ct-threat, .stApp .ct-card-head {{ flex-wrap: wrap; }}
.stApp .ct-threat > span:first-child {{ flex: 1 1 8rem; min-width: 0; overflow-wrap: anywhere; }}
.stApp .ct-card-head .ct-tag {{ overflow-wrap: anywhere; white-space: normal; }}
.stApp .ct-tag.ct-tag-ok {{ background: var(--ct-gain-bg); border: 2px solid var(--ct-ok-line); color: var(--ct-gain-text); }}
/* Despre: the ethical shield's lines */
.stApp .st-key-{ABOUT_SHIELD_KEY} {{ border-top: 6px solid var(--ct-ok-line); }}
.stApp .ct-tag {{ border-radius: 10px; padding: 0.15rem 0.6rem; font-weight: 800; background: var(--ct-card);
  border: 1px solid var(--ct-line); white-space: nowrap; }}

/* Widgets on the page's colours (Cone's dark look needs them; Tuga's keeps them the same) */
.stApp [data-baseweb="select"] > div, .stApp [data-baseweb="input"], .stApp [data-baseweb="base-input"],
.stApp [data-testid="stFileUploaderDropzone"] {{ background: var(--ct-soft) !important; border-color: var(--ct-line) !important; }}
.stApp [data-baseweb="select"] *, .stApp input, .stApp textarea {{ color: var(--ct-text) !important; }}
.stApp input::placeholder {{ color: var(--ct-muted) !important; }}
.stApp [data-testid="stBaseButton-secondary"], .stApp [data-testid="stDownloadButton"] button {{
  background: var(--ct-card) !important; border: 1px solid var(--ct-line) !important; }}
{ALERTS if dark else ""}
.stApp [data-testid="stVegaLiteChart"] {{ background: #FFFFFF; border-radius: 16px; padding: 0.5rem; }}
.stApp [data-testid="stVegaLiteChart"] * {{ color: #1F2937; }}
@media (prefers-reduced-motion: reduce) {{ .stApp, .stApp * {{ transition: none !important; }}
  .stApp .st-key-{FIX_NOW_KEY} a:hover {{ transform: none; }} }}
</style>"""
