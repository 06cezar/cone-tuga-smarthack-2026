"""The talking guide at the top of Acasă: tap Tuga 🐢 (or Cone 🐇) beside the headline and the guide reads it aloud,
with the score, swaying while it speaks.

The picture stays the page's own st.image with its alternative text (FE-E1, tests/test_ui_guides.py); this module adds
the voice. Its HTML runs in a hidden component frame, which Streamlit serves from the page's own origin: the script
makes the headline's picture a button (keyboard too: Enter or Space) and, while the guide speaks, puts the class
TALKING_CLASS on the headline block, which ui/style.py animates. The voice is chosen as in ui/voice.py: only voices on
this computer. No voice in the language: the block gets NOTE_ATTRIBUTE with how to add one, and ui/style.py shows it.
The text goes into the script as escaped JSON, never as HTML (NFR-03)."""
from ui.style import HEADLINE_KEY, NOTE_ATTRIBUTE, TALKING_CLASS, block_key
from ui.voice import GUIDE_VOICE, PICK_VOICE_JS, PREFERRED_VOICES, TEXT as VOICE_TEXT, script_json

HEIGHT_PX = 0  # nothing to see in the frame itself: the picture beside the headline is the button
# The frame may run before Streamlit has drawn the picture: look for it again every MARK_RETRY_MS, for up to 10 s.
MARK_RETRY_MS = 250
MARK_RETRIES = 40

# The same words in both modes, so the headline stays the same when Cone takes over (tests/test_ui_guides.py).
TEXT = {"ro": "🔊 Apasă pe poză și îți citesc", "en": "🔊 Tap the picture to hear it read"}


def talking_html(text: str, lang: str, speaker: str) -> str:
    """The hidden page that gives the headline's guide its voice. `text` is what the guide says: plain text, not
    Markdown."""
    rate, pitch = GUIDE_VOICE[speaker]
    setup = {"key": block_key(HEADLINE_KEY, speaker), "text": text, "lang": lang, "rate": rate, "pitch": pitch,
             "preferred": PREFERRED_VOICES[lang], "label": TEXT[lang], "note": VOICE_TEXT[lang]["no_voice"],
             "talking": TALKING_CLASS, "noteAttribute": NOTE_ATTRIBUTE}
    return f"""<!doctype html><html><head><meta charset="utf-8"></head><body><script>
(() => {{
  const setup = {script_json(setup)};
  const page = window.parent, doc = page.document;
  {PICK_VOICE_JS}
  page.conetugaGuide = setup;  // the newest text, read when the picture is tapped
  let tries = {MARK_RETRIES};
  const mark = () => {{  // the picture becomes a button a keyboard can reach
    const picture = doc.querySelector(".st-key-" + setup.key + " img");
    if (!picture) {{ if (tries-- > 0) setTimeout(mark, {MARK_RETRY_MS}); return; }}
    Object.assign(picture, {{ tabIndex: 0, title: setup.label }});
    picture.setAttribute("role", "button");
    picture.setAttribute("aria-label", picture.alt + ". " + setup.label);
  }};
  mark();
  const toggle = picture => {{
    const now = page.conetugaGuide, speech = page.speechSynthesis;
    const block = picture.closest(".st-key-" + now.key);
    if (!block) return;
    const stop = () => block.classList.remove(now.talking);
    if (!speech) {{ block.setAttribute(now.noteAttribute, now.note); return; }}
    const wasTalking = block.classList.contains(now.talking);
    speech.cancel();
    stop();
    if (wasTalking) return;
    const voice = pickVoice(speech, now.lang, now.preferred);
    if (!voice) {{ block.setAttribute(now.noteAttribute, now.note); return; }}
    const say = new page.SpeechSynthesisUtterance(now.text);
    Object.assign(say, {{ voice, lang: voice.lang, rate: now.rate, pitch: now.pitch }});
    say.onend = say.onerror = stop;
    block.classList.add(now.talking);
    speech.speak(say);
  }};
  const target = event => event.target.closest && page.conetugaGuide &&
    event.target.closest(".st-key-" + page.conetugaGuide.key + " img");
  const handlers = {{
    click: event => {{ const p = target(event); if (p) toggle(p); }},
    keydown: event => {{
      const p = target(event);
      if (p && (event.key === "Enter" || event.key === " ")) {{ event.preventDefault(); toggle(p); }}
    }},
  }};
  // One listener pair for the page: a rerun with new words draws a new frame, and the old frame's listeners would run
  // in a frame that is gone, so the newest frame takes their place.
  for (const [name, old] of Object.entries(page.conetugaGuideHandlers || {{}})) doc.removeEventListener(name, old);
  for (const [name, handler] of Object.entries(handlers)) doc.addEventListener(name, handler);
  page.conetugaGuideHandlers = handlers;
}})();
</script></body></html>"""
