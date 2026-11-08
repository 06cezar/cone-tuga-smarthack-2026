"""Tuga reads aloud 🔊: one button that has the browser say a finding with a voice already on the computer.

For a grandparent or a child who reads slowly (NFR-09). It uses the browser's own speech (speechSynthesis): no library,
no sound file, nothing downloaded, so there is no voice licence to check and nothing to ship. Only voices that run on
this computer are used (localService): the text names the person's devices and addresses, and an online voice (Edge's
"Online (Natural)" ones, Chrome's "Google ..." ones) would send it to a server. With no such voice in the language,
the button says how to add one instead of using an online voice.

The text goes into the page as JSON with <, > and & escaped, so a hostname from the scan can never close the script
(NFR-03)."""
import html
import json

from ui.motion import MATCH_PAGE_BACKGROUND_JS, PALETTE

# Tuga is a calm turtle: a little slower than normal and a little warmer, easier to follow for a child or a grandparent.
TUGA_RATE = 0.9  # 1 is the browser's normal speed
TUGA_PITCH = 1.1  # 1 is the voice's normal pitch
CONE_RATE = 1.1  # Cone is a quick hare, in Advanced mode
CONE_PITCH = 1.0
GUIDE_VOICE = {"tuga": (TUGA_RATE, TUGA_PITCH), "cone": (CONE_RATE, CONE_PITCH)}
HEIGHT_PX = 64  # the component's frame: the button, or the two-line note when there is no voice

# Voices that sound friendly, tried first when the computer has them; any other local voice in the language comes next.
# Windows: Microsoft Andrei (ro-RO), Zira (en-US), Hazel (en-GB). macOS: Ioana (ro-RO), Samantha (en-US), Karen (en-AU).
PREFERRED_VOICES = {"ro": ["Ioana", "Andrei"], "en": ["Samantha", "Zira", "Hazel", "Karen"]}

TEXT = {
    "ro": {
        "listen": "🔊 Ascultă-l pe Tuga",
        "stop": "⏹️ Oprește",
        "no_voice": "Calculatorul nu are o voce în română. O adaugi din Setări → Oră și limbă → Vorbire.",
    },
    "en": {
        "listen": "🔊 Listen to Tuga",
        "stop": "⏹️ Stop",
        "no_voice": "This computer has no English voice. You can add one in Settings → Time & language → Speech.",
    },
}


def script_json(value) -> str:
    """JSON that is safe inside <script>: no <, > or & that could end the script or start a tag."""
    return (json.dumps(value, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


# The browser picks the voice: one of PREFERRED_VOICES that runs on this computer, else any local voice in the language,
# else none (no online voice, see above). Shared by the card button here and the talking guide (ui/talking.py).
PICK_VOICE_JS = """const pickVoice = (speech, lang, preferred) => {
  const local = speech.getVoices().filter(v => v.localService && v.lang.toLowerCase().startsWith(lang));
  return preferred.map(name => local.find(v => v.name.includes(name))).find(Boolean) || local[0] || null;
};"""


def spoken_text(title: str, explanation: str, steps_label: str, steps: list[str]) -> str:
    """What Tuga says for one finding: the title, the explanation, then the steps, numbered as on the page."""
    numbered = " ".join(f"{i}. {step}" for i, step in enumerate(steps, start=1))
    return f"{title}. {explanation} {steps_label}: {numbered}"


def read_aloud_html(text: str, lang: str, dark: bool | None = None) -> str:
    """The read-aloud button for one text, as a self-contained HTML page. `dark` as in ui/motion.py."""
    words = TEXT[lang]
    light_vars = " ".join(f"--{k}: {v};" for k, v in PALETTE[False].items())
    dark_vars = " ".join(f"--{k}: {v};" for k, v in PALETTE[True].items())
    forced = "" if dark is None else f":root {{ {dark_vars if dark else light_vars} }}"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><style>
:root {{ color-scheme: light dark; {light_vars} }}
@media (prefers-color-scheme: dark) {{ :root {{ {dark_vars} }} }}
{forced}
body {{ margin: 0; background: transparent; color: var(--fg); font: 16px/1.4 "Source Sans Pro", "Segoe UI", sans-serif; }}
button {{ font: inherit; font-weight: 600; color: var(--fg); background: transparent; border: 2px solid var(--fg);
  border-radius: 10px; padding: 8px 16px; cursor: pointer; margin: 4px 2px; }}
button:focus-visible {{ outline: 3px solid var(--low); outline-offset: 2px; }}
p {{ margin: 4px 2px; }}
</style></head><body>
<button id="b" type="button" aria-live="polite">{html.escape(words["listen"])}</button>
<p id="n" hidden>{html.escape(words["no_voice"])}</p>
<script>
{MATCH_PAGE_BACKGROUND_JS}
(() => {{
  const text = {script_json(text)}, lang = {script_json(lang)}, preferred = {script_json(PREFERRED_VOICES[lang])};
  const listen = {script_json(words["listen"])}, stop = {script_json(words["stop"])};
  const button = document.getElementById("b"), note = document.getElementById("n");
  const speech = window.speechSynthesis;
  const noVoice = () => {{ button.hidden = true; note.hidden = false; }};
  if (!speech) {{ noVoice(); return; }}
  {PICK_VOICE_JS}
  let speaking = false;
  const reset = () => {{ speaking = false; button.textContent = listen; }};
  button.addEventListener("click", () => {{
    speech.cancel();
    if (speaking) {{ reset(); return; }}
    const chosen = pickVoice(speech, lang, preferred);
    if (!chosen) {{ noVoice(); return; }}
    const say = new SpeechSynthesisUtterance(text);
    Object.assign(say, {{ voice: chosen, lang: chosen.lang, rate: {TUGA_RATE}, pitch: {TUGA_PITCH} }});
    say.onend = say.onerror = reset;
    speaking = true;
    button.textContent = stop;
    speech.speak(say);
  }});
}})();
</script></body></html>"""
