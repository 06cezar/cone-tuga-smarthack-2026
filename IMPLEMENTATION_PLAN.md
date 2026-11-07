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

## Ideas, only after every Must works (in this order: most points for the least effort first)
1. A single "Fă asta primul" card on the first screen: the worst finding, its device, 1–3 steps (ease of use, 20%).
2. Map every catalog code to CIS Controls and OWASP IoT Top 10: a small dictionary, an explicit bonus in the brief.
3. "Am rezolvat, verifică din nou": rescan, then a before/after timeline with resolved findings ticked.
4. Friendly device names from vendor + hostname + services ("Camera Hikvision"), which is also FR-03's type guess.
5. A letter grade (A–F) and a traffic light next to the official score, always with an icon and a label.
6. Q&A assistant with citations and "Scanul nu arată asta" (FR-12), plus the visible hallucination check.
7. Change alert for a new device or a newly opened port (FR-13).
8. One-page HTML report for the IT supplier or the insurer, with before/after (FR-14).
9. Fix steps tailored to the detected vendor ("TP-Link: Advanced → NAT Forwarding → UPnP → Off"), generic otherwise.
10. Test the Romanian text with a real parent or grandparent and film 20 seconds (bonus signal in the brief).
- Only with time to spare: a QR code per fix, a "what if I fix this" score preview, passive mDNS/SSDP names.

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
