"""The score as a gauge, after the mock-ups: Tuga's half circle that fills from red to the score's traffic-light colour,
with the number and a warning line in words; Cone's three-quarter ring with a shield inside.

Plain SVG, CSS and a few lines of JavaScript drawn with st.components.v1.html, like ui/motion.py: nothing is loaded,
nothing moves with "reduce motion", and only the score and our own words go in. The frame paints the colour behind it
(ui.motion.MATCH_PAGE_BACKGROUND_JS), and its words are real text with an aria-label, so the gauge is never only a
picture (NFR-08)."""
import html
import math

from ui.motion import DURATION_MS, MATCH_PAGE_BACKGROUND_JS
from ui.theme import STATUS, THEMES, LIGHTS
from ui.view import light

ARC_HEIGHT_PX = 236  # Tuga's frame: the half circle, the number inside it and the warning line
RING_HEIGHT_PX = 150  # Cone's frame: the ring only
ARC_RADIUS, ARC_STROKE = 120, 30
RING_RADIUS, RING_STROKE = 52, 14
RING_SWEEP = 0.75  # Cone's ring is three quarters of a circle, open at the bottom

TEXT = {
    "ro": {"green": "✅ ÎN SIGURANȚĂ", "yellow": "⚠️ ATENȚIE: NECESITĂ ACȚIUNE", "red": "⛔ PERICOL: REPARĂ ACUM"},
    "en": {"green": "✅ SAFE", "yellow": "⚠️ WARNING: NEEDS ATTENTION", "red": "⛔ DANGER: FIX IT NOW"},
}


def warning_words(score: int, lang: str) -> str:
    """The line under Tuga's gauge, with its icon: what the score means in a few words."""
    return TEXT[lang][light(score)]


def _count_up(score: int) -> str:
    return f"""<script>
{MATCH_PAGE_BACKGROUND_JS}
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
</script>"""


def _page(body: str, style: str, colours: dict[str, str]) -> str:
    variables = " ".join(f"--{name}: {value};" for name, value in colours.items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
:root {{ {variables} }}
body {{ margin: 0; background: transparent; color: var(--text);
  font: 16px/1.3 "Nunito", "Poppins", "Segoe UI", system-ui, sans-serif; display: grid; justify-items: center; }}
.value {{ animation: fill {DURATION_MS}ms cubic-bezier(.2,.8,.2,1) forwards; }}
{style}
@media (prefers-reduced-motion: reduce) {{ .value {{ animation: none; stroke-dashoffset: var(--left); }} }}
</style></head><body>{body}</body></html>"""


def arc_html(score: int, lang: str) -> str:
    """Tuga's gauge (light): the half circle fills from red to the score's colour; the number sits inside it."""
    theme, status = THEMES[False], LIGHTS[light(score)]
    strong, words_colour = STATUS[False][status]
    length = math.pi * ARC_RADIUS
    left = length * (1 - score / 100)
    width, centre = 2 * (ARC_RADIUS + ARC_STROKE), ARC_RADIUS + ARC_STROKE
    arc = f"M {ARC_STROKE} {centre} A {ARC_RADIUS} {ARC_RADIUS} 0 0 1 {width - ARC_STROKE} {centre}"
    words = warning_words(score, lang)
    body = f"""<div role="img" aria-label="{score}/100. {html.escape(words)}" style="display:grid;justify-items:center">
<svg width="{width}" height="{centre + ARC_STROKE // 2}" viewBox="0 0 {width} {centre + ARC_STROKE // 2}">
<defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="0">
<stop offset="0" stop-color="{STATUS[False]['high'][0]}"/><stop offset="1" stop-color="{strong}"/></linearGradient></defs>
<path d="{arc}" fill="none" stroke="#DCE6F2" stroke-width="{ARC_STROKE}" stroke-linecap="round"/>
<path class="value" d="{arc}" fill="none" stroke="url(#g)" stroke-width="{ARC_STROKE}" stroke-linecap="round"
  stroke-dasharray="{length:.1f}" stroke-dashoffset="{length:.1f}"/>
</svg>
<div class="number"><span id="n">{score}</span><small> / 100</small></div>
<div class="words">{html.escape(words)}</div></div>{_count_up(score)}"""
    style = f"""@keyframes fill {{ to {{ stroke-dashoffset: {left:.1f}; }} }}
:root {{ --left: {left:.1f}; }}
.number {{ margin-top: -{ARC_RADIUS // 2 + 18}px; font-size: 72px; font-weight: 900; letter-spacing: -0.03em; }}
.number small {{ font-size: 40px; font-weight: 800; color: var(--muted); }}
.words {{ margin-top: 6px; font-size: 22px; font-weight: 900; color: var(--words); text-transform: uppercase; }}"""
    return _page(body, style, {"text": theme["text"], "muted": theme["muted"], "words": words_colour})


def ring_html(score: int, lang: str) -> str:
    """Cone's gauge (dark): a three-quarter ring in the score's colour, with a shield inside."""
    theme, status = THEMES[True], LIGHTS[light(score)]
    strong = STATUS[True][status][0]
    circle = 2 * math.pi * RING_RADIUS
    track = circle * RING_SWEEP
    left = track * (1 - score / 100)
    size = 2 * (RING_RADIUS + RING_STROKE)
    centre = RING_RADIUS + RING_STROKE
    rotate = 90 + (1 - RING_SWEEP) * 180  # the gap of the ring at the bottom
    body = f"""<div role="img" aria-label="{score}/100. {html.escape(warning_words(score, lang))}">
<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" style="transform: rotate({rotate}deg)">
<circle cx="{centre}" cy="{centre}" r="{RING_RADIUS}" fill="none" stroke="#1E3A5F" stroke-width="{RING_STROKE}"
  stroke-linecap="round" stroke-dasharray="{track:.1f} {circle:.1f}"/>
<circle class="value" cx="{centre}" cy="{centre}" r="{RING_RADIUS}" fill="none" stroke="{strong}" stroke-width="{RING_STROKE}"
  stroke-linecap="round" stroke-dasharray="{track:.1f} {circle:.1f}" stroke-dashoffset="{track:.1f}"
  style="filter: drop-shadow(0 0 6px {strong})"/>
</svg><div class="shield">🛡️</div><span id="n" hidden>{score}</span></div>{_count_up(score)}"""
    style = f"""@keyframes fill {{ to {{ stroke-dashoffset: {left:.1f}; }} }}
:root {{ --left: {left:.1f}; }}
.shield {{ margin-top: -{size // 2 + 26}px; font-size: 40px; text-align: center; height: {size // 2}px; }}"""
    return _page(body, style, {"text": theme["text"], "muted": theme["muted"]})
