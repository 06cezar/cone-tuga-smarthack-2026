# Implementation plan

Status lives here, not in CLAUDE.md. Milestones are the brief's; hours count from the opening.

## A · parser, rules, score
- [ ] Contract `analyse_file` agreed (hour 2)
- [ ] Parser for nmap XML: hosts, MAC + vendor, hostname, open ports, service, product, version, ssl, `http-title`
- [ ] Rules from `data/catalog.toml` and the standard score
- [ ] `tests/test_validation_set.py` green: 24/24 rows, no extra rows, every score (hour 10)

## B · explanations and fixes
- [ ] Built-in RO/EN text and 1–5 steps for every catalog code (hour 12)
- [ ] Optional LLM explanations, with the grounding check and the fallback
- [ ] Q&A assistant from scan evidence only (FR-12, Should)

## C · guardrail, security, export
- [ ] Network detection (FR-01) and `check_scope` (FR-02): public IPs and out-of-scope ranges refused (hour 14)
- [ ] Live scan with `--confirm`, rate-limited, writing nmap XML (FR-04)
- [ ] `export` for a folder: findings.csv and scores.csv (FR-15); MAC masking everywhere; gitleaks clean

## D · UI, history, pitch
- [ ] UI with the most dangerous device and the first step on the first screen; score, devices, findings, fixes (FR-11)
- [ ] History, diff, "delete my history", change alerts (FR-10, FR-13), visible by hour 16
- [ ] Pitch (5–7 minutes, English, 2+ speakers) and the one-page technical summary

## E · lab and QA
- [ ] Hotspot `RSH-<team number>`, 3+ targets, 5+ catalog codes, three scans saved (hour 3)
- [ ] Before/after pair: fix 2+ findings and rescan
- [ ] Validation Set XML copied into `tests/fixtures/validation/`; rehearse the 7 live checks
- [ ] Lab scans used as fixtures: a test checks that our before/after pair shows the score improving

## Deliverables (the brief's checklist)
- [ ] Rules-of-engagement form signed by every team member (hour 0)
- [ ] Test Set results uploaded by hour 21: `findings.csv`, `scores.csv` and a UI screenshot. Commit a copy of exactly
  what we uploaded in `submission/`, with the `final` tag, so the live re-run can be compared with it
- [ ] Git release tagged `final` at upload time (hour 22 at the latest); nothing after that tag counts
- [ ] README explaining setup, live scan and file analysis, with one-command setup (`setup.ps1`, `setup.sh`)
- [ ] Validation Set reproduced: all 24 rows, no extra rows, correct scores
- [ ] Our hotspot lab scans (nmap XML) in the repo, including one before/after pair
- [ ] Simple UI showing score, devices, findings, fixes and history
- [ ] One-page technical summary (`docs/technical-summary.md`): lab setup, architecture, assumptions, limitations, LLM use
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
- What clock times are brief hours 16, 20, 21 and 22?
- Can we use code we wrote before the event, if we declare it?
- HTTP_ADMIN_CLEARTEXT needs the page title (`http-title`): do the standard files include it?
- UNKNOWN_DEVICE: does a host with no MAC address at all count as "no MAC vendor"?
- OUTDATED_SERVICE: does "OpenSSH 7.2p2 Ubuntu" compare as 7.2?
- What do you expect, at minimum, from the device-type guess?
- Is OUTDATED_SERVICE reported when the service has no finding of its own (e.g. Apache 2.2 with no admin title)?
- Old Samba: do we report OUTDATED_SERVICE on 445 or on 139?
- Is the title keyword match case-insensitive?
- Do `http-proxy` and `http-alt` count as `http`?
- A valid nmap XML with no hosts: score 100 or ERROR?
