# ConeTuga front-end plan (owner: D)

The back end is done and verified (656 tests, Validation Set 24/24 and 8/8, lab 0 → 50 → 70, live scan run on the
hotspot). The whole team now works on the front end, under the same rules: `CLAUDE.md`, contract first for anything
another stream calls, one `COMMS.md` inbox per member, Pull Requests reviewed by D, nothing straight on `main` except
team messages. Status lives in `IMPLEMENTATION_PLAN.md`; this file is the design and who does what.

## 1. The vision

- **Two guides.** **Tuga** 🐢 (tortuga, a tortoise) explains each finding to a non-technical person: short sentences, no
  jargon, one thing to do. **Cone** 🐇 (conejito, a hare) speaks to technical users: port, protocol, service and
  version as nmap saw them, the catalog rule that fired, the CIS Controls / OWASP IoT references, precise fix steps.
- **Two modes.** Simple (Tuga) by default; an **"Avansat / Advanced"** toggle switches every page to Cone. The mode,
  the language and the theme are kept for the session and shown in the sidebar.
- **Several pages, not one** (Streamlit `st.navigation`): Acasă (scan, headline, score), Dispozitive, Istoric,
  Întreabă (Q&A, later the chat agent), Wiki amenințări, Despre și siguranță. Light/dark theme toggle.
- **Every Must stays visible** (below), and the first screen still answers the ease-of-use check by itself.

## 2. The brief's limits on this vision (each is a Must, so the design follows it)

| Rule | What it means for us |
|---|---|
| NFR-09: all user-facing text RO/EN at about a 12-year-old's level | Tuga is the default and the reference text. Cone may name ports, services and references, but explains each technical word in a few words, in both languages. |
| NFR-08: 16 px, colour never alone, keyboard, WCAG AA | Both themes are checked for AA contrast; the characters always come with their name and text, never an image alone; every control works from the keyboard. |
| NFR-03: scan text is hostile | Every page escapes scan text (`ui.view.md`); character speech filled with scan values uses B's safe `fill()`. |
| NFR-02: hostnames and history only on this computer | The statistics store (section 5) is local, aggregate, opt-in, and cleared by "Șterge istoricul meu". No server. |
| NFR-04: UI runs unprivileged | No live scan from the browser: the Scan page shows the network (`detect_network`, FR-01) and the exact command; scans run from the CLI land in the history. |
| NFR-06: grounded AI | The chat agent (section 5) answers only through the evidence-checked path; today that is B's retrieval Q&A. |
| NFR-05 and the 30% accuracy | The front end never computes findings or scores; it only orders and explains what `analyse_file` returns. |

## 3. The Musts, checked against the UI

FR-03 devices (IP, masked MAC, vendor, hostname, type) · FR-07 explanations ≤ 2 sentences RO/EN · FR-08 1–5 steps ·
FR-09 standard score (ours may sit beside it, labelled) · FR-10 history with every scan (live scans too, see C) ·
FR-11 score, devices, findings, fixes, history · FR-13 change alerts · FR-12 Q&A · FR-14 report · NFR-02 delete my
history · NFR-08 accessibility · NFR-09 RO/EN. Every page gets an AppTest that checks its Musts in both languages and
both modes.

## 4. Who does what

Each piece starts with its contract entry in `specs/contracts.md` when another stream calls it, and lands as its own
Pull Request. Branches: `<stream>-fe-<topic>`.

**D (Cezar): the shell and the main pages.** `ui/app.py` becomes the entry point with `st.navigation`; `ui/state.py`
(session: scan, language, mode, theme, one place to read and set them); pages Acasă, Dispozitive, Istoric, Despre;
the Advanced toggle and the theme toggle; "not checked" for devices nmap gave up on (`Host.timed_out`); review of
every front-end PR; `requirements.txt` cleanup (B's OK) and pinning before the tag.

**B: what the guides say.** Contract first: `narrate(finding, host, lang, mode) -> Narration(speaker, text, steps,
references, source)`, `speaker` "tuga" or "cone"; Tuga's text may be the current one, Cone's adds the evidence and
references. Content in `data/` (TOML, RO/EN), every value from the scan through `fill()`. Then the **Wiki
amenințări**: one entry per catalog code plus a few concepts (port, encryption, firewall, MAC, UPnP), each in Tuga and
Cone form, behind a small `wiki_entries(lang, mode)` contract. B also owns the chat-agent interface (section 5).

**C: safety of the new pages and FR-10 for live scans.** Yes from D to C's 17:37 (8): after a live scan, `scan`
calls `save_scan`, with a contract line first, so the scan shows in the Istoric page. A **Scan** page that shows the
detected network (FR-01) and the exact `scan --confirm` command, and runs nothing. NFR-07 (a /24 under 5 minutes):
C's call. Extend `tests/test_privacy.py` to every new page and both modes (no raw MAC anywhere).

**A: data for the pages, and the statistics store.** Contract first: `conetuga/insights` with
`record(result)` and `top_codes(n) -> list[(code, count)]`, local SQLite in `.history/` (gitignored), **counts of
catalog codes only, never an IP, MAC, hostname or file name**, opt-in in the UI, and deleted by "Șterge istoricul
meu". It powers a "most common problems" panel on the Wiki page. A also helps D with page data
(`ui/view.py` functions for the Dispozitive filters and sort).

**E: the characters, accessibility and the users.** Original SVG art for Tuga and Cone (our own drawings, small,
inline, with alt text), in `ui/assets/`; an accessibility pass on every page in both themes (16 px, AA contrast,
keyboard, icon + label); `setup.ps1` falling back to any Python 3.11+ like `setup.sh` (C's 17:37 (7)); one test of the
Romanian Tuga texts with a non-technical person (a bonus signal); the demo rehearsal on the new UI.

## 5. Built to grow

- **Chat agent:** `conetuga/explain/assistant.py` defines one call, `reply(messages, result, lang, mode) -> Answer`,
  the same `Answer` as `answer_question`. Today it answers the last message with `answer_question`. A future model
  sits behind the same call, with every sentence checked against the scan (NFR-06) and the retrieval answer as the
  fallback; the UI's Întreabă page never changes.
- **Statistics:** `conetuga/insights` hides where the counts live. Today: a local file. A shared database later would
  be a new back end behind the same two calls, opt-in and anonymous, and needs the team's decision on NFR-02 first.
- **New guides or languages:** speech lives in `data/` TOML keyed by mode and language, so a third guide or a third
  language is data, not code.
- **New pages:** a page is one module in `ui/pages/` registered in the navigation list.

## 6. Order and timing (before hour 20)

1. Contracts: B's `narrate` and `wiki_entries`, A's `insights`, C's `save_scan` after a live scan (one PR each, D's OK).
2. D's shell and state, so every page has a place; E's art in parallel.
3. Pages: D (Acasă, Dispozitive, Istoric, Despre), B (Wiki content), C (Scan page), A (statistics panel).
4. E's accessibility pass and test with a non-technical person; C's privacy test on every page.
5. Code freeze from the Test Set run (`docs/jury-demo.md`); only fixes after that, nothing after the `final` tag.
