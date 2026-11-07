# Implementation plan

Status lives here, not in CLAUDE.md. Milestones are the brief's; hours count from the opening.

## A · parser, rules, score
- [x] Contract `analyse_file` agreed (hour 2): B, C and D confirmed, with `proto` and `points` added
- [x] Parser for nmap XML: hosts, MAC + vendor, hostname, open ports, service, product, version, ssl, `http-title`
- [x] Rules from `data/catalog.toml` and the standard score
- [x] `tests/test_validation_set.py` green: 24/24 rows, no extra rows, every score (hour 10)
- [x] A missing `analyse_file` can't pass unnoticed: the full suite stops with errors, because
  `tests/test_analysis.py` and `tests/test_rules.py` import it (checked by A and D), so no test change is needed

## B · explanations and fixes
- [x] Built-in RO/EN text and 1–5 steps for every catalog code (hour 12): `data/explanations.toml` (PR #6), `explain()`
  and `device_label()` (PR #7)
- [x] Optional LLM explanations: dropped on R Systems' advice (no key, no LLM); the built-in texts and a retrieval-based Q&A instead
- [x] Q&A assistant from scan evidence only (FR-12, Should): `conetuga/explain/qa.py` (PR #41)

## C · guardrail, security, export
- [x] Network detection (FR-01) and `check_scope` (FR-02): public IPs, out-of-scope ranges, hostnames and any network
  other than `RSH-ConeTuga` refused (hour 14)
- [x] CLI `conetuga/__main__.py`: `analyse` and `scan` (PRs #14, #23)
- [x] Live scan with `--confirm`, rate-limited, writing nmap XML (FR-04): run for real on the hotspot, score 70 (PRs #23, #36)
- [x] `export` for a folder: findings.csv and scores.csv (FR-15); MAC masking everywhere; gitleaks clean (PRs #14, #25)

## D · UI, history, pitch
- [x] UI with the most dangerous device and the first step on the first screen; score, devices, findings, fixes (FR-11):
  `ui/app.py`, `ui/view.py` (history comes with the next item)
- [x] History, diff, "delete my history", change alerts (FR-10, FR-13), visible by hour 16: `conetuga/history/`,
  shown under the devices in `ui/app.py`
- [ ] Pitch (5–7 minutes, English, 2+ speakers) and the one-page technical summary

## E · lab and QA
- [x] Hotspot `RSH-<team name>` (ours: `RSH-ConeTuga`), 3+ targets, 5+ catalog codes, three scans saved (hour 3)
- [x] Before/after pair: fix 2+ findings and rescan (0 → 50 → 70)
- [x] The 8 Validation Set XML files copied into `tests/fixtures/validation/scans/` (scan files only there)
- [ ] Rehearse the 7 live checks
- [x] Lab scans used as fixtures: a test checks that our before/after pair shows the score improving

## Front end (design: `docs/frontend-plan.md`; branches `<stream>-fe-<topic>`; tick your own lines)
Order: the contracts first (FE-A1, FE-B1, FE-B3), D's shell (FE-D1) next, then the pages in parallel. A page in
`ui/pages/` that isn't D's starts with one line in `ui/COMMS.md`. Every page: RO/EN, Simple (Tuga) and Advanced
(Cone), both themes, scan text escaped, an AppTest.

**D**
- [ ] FE-D1 `ui/state.py` (scan, language, mode, theme in one place) and `st.navigation` with the pages below; the
  sidebar holds the language, the "Avansat / Advanced" toggle and the light/dark toggle
- [ ] FE-D2 Acasă: pick or upload a scan; the headline said by the current guide; the traffic-light score
- [x] FE-D3 Dispozitive: devices by risk, each finding through `narrate`; "neverificat" for `Host.timed_out`
- [ ] FE-D4 Istoric (today's history, report button) and Despre (how it works, safety, privacy, the rules we keep)
- [ ] FE-D5 Light and dark theme: one set of colour tokens per theme, both WCAG AA (NFR-08)
- [ ] FE-D6 Review every front-end PR; the page AppTests (both languages, both modes) stay green

**B**
- [ ] FE-B1 Contract `narrate(finding, host, lang, mode) -> Narration(speaker, text, steps, references, source)`
- [ ] FE-B2 Tuga's and Cone's texts for the 15 codes, RO/EN, in `data/`; `narrate` with tests (Cone explains each
  technical word, NFR-09)
- [ ] FE-B3 Contract `wiki_entries(lang, mode)`
- [ ] FE-B4 Wiki amenințări: one entry per code plus port, encryption, firewall, MAC, UPnP; page `ui/pages/wiki.py`
- [ ] FE-B5 `conetuga/explain/assistant.py`: `reply(messages, result, lang, mode) -> Answer` through
  `answer_question`; page `ui/pages/ask.py` with a chat box (the future agent plugs in here, NFR-06)
- [ ] FE-B6 The Q&A names devices as the UI does (`ui.view.device_name`)

**A**
- [x] FE-A1 Contract `conetuga/insights`: `set_enabled`, `is_enabled`, `status`, `record(result, scan_id, seen)`,
  `top_codes(n) -> list[(code, count)]` (D's OK, Nov 7 21:40)
- [x] FE-A2 Local store in `.history/`: code counts only (no IP, MAC, hostname, file name), opt-in, cleared by
  "Șterge istoricul meu" (NFR-02)
- [ ] FE-A3 "Cele mai comune probleme" panel on the Wiki page, with B
- [x] FE-A4 Data for the Dispozitive page in `ui/view.py`: filter by risk and type, sort

**C**
- [x] FE-C1 Scan page `ui/pages/scan.py`: the detected network (FR-01) and the exact `scan --confirm` command; it runs
  nothing (NFR-04)
- [ ] FE-C2 NFR-07: a /24 live scan under 5 minutes, or the limitation written down
- [ ] FE-C3 `tests/test_privacy.py` over every page, both modes, both themes
- [ ] FE-C4 Security review of every front-end PR (escaping, uploads, no secret)

**E**
- [ ] FE-E1 Original SVG drawings of Tuga 🐢 and Cone 🐇 in `ui/assets/`, small, with alt text, never shown alone
- [ ] FE-E2 Accessibility pass on every page in both themes: 16 px, AA contrast, keyboard, icon + label
- [ ] FE-E3 Tuga's Romanian texts tested with a non-technical person; findings to B, the result to PITCH.md (D)
- [ ] FE-E4 Rehearse the demo on the new UI; update `docs/jury-demo.md` with the new steps

## Deliverables (the brief's checklist)
- [ ] Rules-of-engagement form signed by every team member (hour 0)
- [ ] Test Set results uploaded by hour 21: `findings.csv`, `scores.csv` and a UI screenshot. Commit a copy of exactly
  what we uploaded in `submission/`, with the `final` tag, so the live re-run can be compared with it
- [ ] Package versions pinned before the tag (`pip freeze` into `requirements.txt`), so the live re-run uses exactly
  the same versions
- [ ] Git release tagged `final` at upload time (hour 22 at the latest); nothing after that tag counts
- [x] README explaining setup, live scan and file analysis, with one-command setup (`setup.ps1`, `setup.sh`)
- [x] Validation Set reproduced: all 24 rows, no extra rows, correct scores (`tests/test_validation_set.py`, PR #5)
- [x] Our hotspot lab scans (nmap XML) in the repo, including one before/after pair (`lab/scans/`, PR #27)
- [x] Simple UI showing score, devices, findings, fixes and history (PRs #20, #22)
- [x] One-page technical summary (`docs/technical-summary.md`): lab setup, architecture, assumptions, limitations, LLM use
- [ ] 5–7 minute pitch in English: problem, demo, numbers, trade-offs, next steps; at least two speakers, juniors and
  seniors both speak
- [ ] Laptop ready for the 7 live checks, rehearsed in order

## The 7 live checks (in the jury's order; have a command ready for each)
1. Re-run: the jury picks a Test Set file; our live result must match the upload (`submission/`).
2. Hands-on: a jury member uses the UI alone to find the most dangerous device and what to do first.
3. Explanations: the explanation and fix for three findings the jury names.
4. Guardrail: we try a public IP and the venue network; the tool refuses both.
5. Broken file: an unreadable file gives a clear error and no crash.
6. History: a before/after from our own hotspot lab, with the score improving.
7. No secrets: `gitleaks detect` on the repo finds nothing.

## After every Must works: only what the brief asks for or rewards (most points for the least effort first)
1. A single "Fă asta primul" card on the first screen: the worst finding, its device, 1–3 steps (live check 2; the
   brief's "one fix at a time" health check).
2. Map every catalog code to CIS Controls and OWASP IoT Top 10, as a small dictionary (bonus signal).
3. "Am rezolvat, verifică din nou": rescan, then before/after with the resolved findings ticked ("Proof"; bonus signal
   for a measured before/after).
4. Friendly device names from vendor + hostname + services ("Camera Hikvision"): FR-03's device-type guess.
5. A traffic light next to the official score, always with an icon and a label (the brief's "traffic-light score",
   NFR-08).
6. Q&A assistant from scan evidence only, with citations and "Scanul nu arată asta" (FR-12, Should).
7. Change alert for a new device or a newly opened port (FR-13, Should).
8. One-page HTML or PDF report for the IT supplier or the insurer, with before/after (FR-14, Could).
9. Fix steps tailored to the detected router or device ("TP-Link: Advanced → NAT Forwarding → UPnP → Off"), generic
   otherwise (the brief's "router-specific remediation guides").
10. Test the Romanian text with a non-technical person (bonus signal).

## Questions for humans
Mentors' note of Nov 7 (all they gave): Samba only on 445; a host with no MAC is UNKNOWN_DEVICE; the same port on
TCP and UDP gives one row, the TCP one; everything else "is okay as assumed", i.e. A's readings below stand.
- What clock times are brief hours 16, 20, 21 and 22?
- Can we use code we wrote before the event, if we declare it?
- Which files in the Test Set folder count: only `*.xml`, or every file (a broken file may have another extension)?
- UNKNOWN_DEVICE: does a host with no MAC address at all count as "no MAC vendor"? (A MAC with no vendor does: V4's .99.)
  A reads: yes. **Mentors (Nov 7): yes, UNKNOWN_DEVICE.**
- OUTDATED_SERVICE: does "OpenSSH 7.2p2 Ubuntu" compare as 7.2? A reads: yes, the leading numbers.
- What do you expect, at minimum, from the device-type guess?
- Is OUTDATED_SERVICE reported when the service has no finding of its own (e.g. Apache 2.2 with no admin title)?
  A reads: yes.
- Old Samba open on 139 and 445: one OUTDATED_SERVICE or two? A reads: one, on 445 (else 139), the port of the
  service's own SMB_EXPOSED. **Mentors (Nov 7): only on 445.**
- Is the title keyword match case-insensitive, and a part of the title ("Configuration" counts for "config")?
  A reads: yes to both.
- Do `http-proxy` and `http-alt` count as `http`? A reads: no, only `http` exactly.
- A valid nmap XML with no hosts: score 100 or ERROR? A reads: 100.
- The same port open on TCP and UDP with the same finding code: one row or two? (`findings.csv` has no protocol
  column; A keeps one, the TCP one.) **Mentors (Nov 7): one row, the TCP one.**
- nmap's uncertain versions ("3.X", "3.X - 4.X"): outdated or not? A reads: only when every version they could
  stand for is outdated ("3.X" Samba yes, "3.X - 4.X" no).
- With `-sV`, nmap's own `mqtt-subscribe` script (category version) writes the broker version into the service
  name (`mqtt-subscribe.nse` line 380): our scan_01 shows an open Mosquitto as service "mosquitto version 1.6.15",
  not "mqtt". Does it still count as MQTT_EXPOSED? A reads: no, the catalog decides by the service name nmap
  reports; the standard files show "mqtt", so only our live scans are affected (a limitation, stated).
- Does the row order in `findings.csv` matter? Our export sorts by IP as a number, then port and code, so 4
  Validation Set rows come out in another order than the answer key's. A reads: no, the brief compares rows
  (correct, extra, missing), not their order; `tests/test_validation_set.py` compares them as a multiset.
