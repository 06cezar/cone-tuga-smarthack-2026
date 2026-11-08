"""Motion on Acasă: the score fills its ring and counts up, and one bar per severity grows to its number of findings.

A design idea for the front end (D's branch D-fe-motion). It is plain HTML, CSS and a few lines of JavaScript drawn
with st.components.v1.html: no library and nothing downloaded, so the page still works offline and adds no
dependency (an animation library such as anime.js would need one). Accessibility (NFR-08): the score line under it
stays the text a screen reader and the tests read; every colour comes with its icon and word; and with "reduce
motion" turned on in the operating system, everything is drawn in its final state at once. No scan text goes in:
only the score, counts and our own fixed words, so nothing here needs escaping."""
import html

import streamlit as st

from conetuga.analysis import FileResult
from ui.view import SEVERITY_ICON, TEXT as VIEW_TEXT, light, score_line

RING_RADIUS = 52  # SVG units; the ring is drawn in a 128 x 128 box
RING_STROKE = 12
DURATION_MS = 1200  # long enough to see the score fill, short enough not to delay reading
STAGGER_MS = 120  # each severity bar starts a little after the one above it
HEIGHT_PX = 190  # the component's frame height: the ring plus four bars

SEVERITIES = ("high", "medium", "low", "info")
# Colours with at least 4.5:1 contrast on their background in each theme (WCAG AA), for the ring and the bars.
PALETTE = {
    False: {"bg": "#FFFFFF", "fg": "#1F2328", "track": "#E3E6EA",
            "green": "#1A7F37", "yellow": "#9A6700", "red": "#CF222E",
            "high": "#CF222E", "medium": "#9A6700", "low": "#0969DA", "info": "#57606A"},
    True: {"bg": "#0E1117", "fg": "#E6EDF3", "track": "#30363D",
           "green": "#3FB950", "yellow": "#D29922", "red": "#F85149",
           "high": "#F85149", "medium": "#D29922", "low": "#58A6FF", "info": "#8B949E"},
}


def severity_counts(result: FileResult) -> dict[str, int]:
    """How many findings of each severity the scan has, in the catalog's order."""
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def page_is_dark(settings) -> bool | None:
    """The theme the page is drawn in: our own toggle when there is one, else Streamlit's (the ⋮ menu or the
    system); None when neither says, and the animation then follows the browser."""
    if getattr(settings, "dark", None) is not None and "dark_theme" in st.session_state:
        return bool(settings.dark)
    theme = getattr(getattr(st, "context", None), "theme", None)
    kind = getattr(theme, "type", None)
    return None if kind is None else kind == "dark"


def _variables(colours: dict[str, str]) -> str:
    return " ".join(f"--{name}: {value};" for name, value in colours.items())


def score_motion_html(result: FileResult, lang: str, dark: bool | None = None) -> str:
    """The animated score ring and severity bars for one scan, as a self-contained HTML page. `dark` None follows
    the browser's light or dark preference, as Streamlit's own theme does; True or False forces one."""
    colours = PALETTE[False]
    score = int(result.score)
    icon, word, _sentence = score_line(score, lang)
    ring_colour = f"var(--{light(score)})"
    circumference = 2 * 3.14159265 * RING_RADIUS
    filled = circumference * (1 - score / 100)
    counts = severity_counts(result)
    widest = max(counts.values()) or 1
    bars = "".join(
        f'<div class="row"><span class="label">{SEVERITY_ICON[s]} {html.escape(VIEW_TEXT[lang][f"severity_{s}"])}</span>'
        f'<span class="track"><span class="bar" style="--w:{100 * n / widest:.0f}%;--c:var(--{s});'
        f'--d:{i * STAGGER_MS}ms"></span></span><span class="count">{n}</span></div>'
        for i, (s, n) in enumerate(counts.items()))
    light_vars, dark_vars = _variables(PALETTE[False]), _variables(PALETTE[True])
    forced = "" if dark is None else f":root {{ {dark_vars if dark else light_vars} }}"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><style>
:root {{ color-scheme: light dark; {light_vars} }}
@media (prefers-color-scheme: dark) {{ :root {{ {dark_vars} }} }}
{forced}
body {{ margin: 0; background: transparent; color: var(--fg);
  font: 16px/1.4 "Source Sans Pro", "Segoe UI", sans-serif; }}
.wrap {{ display: flex; gap: 28px; align-items: center; padding: 8px 4px; }}
.ring {{ position: relative; width: 128px; height: 128px; flex: none; }}
.ring svg {{ transform: rotate(-90deg); }}
.ring .value {{ stroke-dasharray: {circumference:.1f}; stroke-dashoffset: {circumference:.1f};
  animation: fill {DURATION_MS}ms cubic-bezier(.2,.8,.2,1) forwards; }}
@keyframes fill {{ to {{ stroke-dashoffset: {filled:.1f}; }} }}
.ring .center {{ position: absolute; inset: 0; display: grid; place-items: center; text-align: center; }}
.ring .number {{ font-size: 34px; font-weight: 700; }}
.ring .word {{ font-size: 16px; }}
.bars {{ flex: 1; display: grid; gap: 8px; max-width: 520px; }}
.row {{ display: grid; grid-template-columns: 170px 1fr 32px; gap: 10px; align-items: center; }}
.track {{ height: 14px; background: var(--track); border-radius: 7px; overflow: hidden; }}
.bar {{ display: block; height: 100%; width: 0; background: var(--c); border-radius: 7px;
  animation: grow {DURATION_MS}ms cubic-bezier(.2,.8,.2,1) var(--d) forwards; }}
@keyframes grow {{ to {{ width: var(--w); }} }}
.count {{ text-align: right; font-weight: 600; }}
@media (prefers-reduced-motion: reduce) {{
  .ring .value {{ animation: none; stroke-dashoffset: {filled:.1f}; }}
  .bar {{ animation: none; width: var(--w); }}
}}
</style></head><body><div class="wrap" role="img" aria-label="{score}/100 {html.escape(word)}">
<div class="ring"><svg width="128" height="128" viewBox="0 0 128 128">
<circle cx="64" cy="64" r="{RING_RADIUS}" fill="none" stroke="var(--track)" stroke-width="{RING_STROKE}"/>
<circle class="value" cx="64" cy="64" r="{RING_RADIUS}" fill="none" stroke="{ring_colour}"
  stroke-width="{RING_STROKE}" stroke-linecap="round"/></svg>
<div class="center"><div><div class="number" id="n">{score}</div><div class="word">{icon} {html.escape(word)}</div></div></div></div>
<div class="bars">{bars}</div></div>
<script>
(() => {{
  const target = {score}, el = document.getElementById("n");
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const start = performance.now();
  const step = now => {{
    const t = Math.min(1, (now - start) / {DURATION_MS});
    el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  }};
  el.textContent = "0";
  requestAnimationFrame(step);
}})();
</script></body></html>"""
