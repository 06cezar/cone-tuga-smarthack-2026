# Pitch claims (claim → file → test)

Every claim we make on stage has a row here, and no claim goes on stage without a passing test. The pitch is 5–7
minutes, in English, with at least two speakers (juniors and seniors both speak). The jury session is 15 minutes:
7 of pitch, then 8 of live checks. Order: problem, demo, numbers, trade-offs, limitations, next steps.

| Claim | File | Test |
|---|---|---|
| "We reproduce the Validation Set: 24 of 24 rows, no extra rows, every score." | `conetuga/analysis/` | `tests/test_validation_set.py` |
| "Same file, same result, every time: the AI never decides a finding." | `conetuga/analysis/rules.py`, `data/catalog.toml` | `tests/test_analysis.py::test_same_file_gives_the_same_result_every_time` |
| "A hostile scan file can't trick the parser: external entities (XXE), truncated and oversized files are refused with a clear error." | `conetuga/analysis/parser.py` | `tests/test_analysis.py::test_xml_external_entities_are_refused`, `::test_truncated_file_gives_no_findings_from_its_first_half`, `::test_file_larger_than_the_limit_is_an_error` |
| "Every one of the 15 findings is explained in Romanian and English, in at most 2 sentences, with 1–5 fixes, and no hand-written IP, port or CVE." | `data/explanations.toml` | `tests/test_explanations.py` |
| "The tool refuses public IPs and anything outside our hotspot." | `conetuga/guard/scope.py` | `tests/test_guard.py::test_contract_check_scope`, `::test_venue_network_is_refused_while_we_are_on_our_hotspot`, `::test_every_target_is_refused_on_the_venue_wifi` |
| "A broken file shows a clear error, and the other files still run." | `conetuga/guard/export.py` | `tests/test_export.py::test_broken_file_gets_an_error_row_and_the_export_goes_on`, `::test_a_crash_in_the_analysis_becomes_an_error_row`, `tests/test_cli.py::test_analyse_writes_both_files_and_says_what_happened_to_each` |
| "A live scan runs only on our hotspot, with --confirm, at most 100 packets per second, and only nmap gets administrator rights." | `conetuga/guard/scan.py` | `tests/test_scan.py::test_nothing_reaches_nmap_without_the_guardrails_yes`, `::test_rate_is_at_most_100_packets_per_second`, `::test_without_root_on_linux_only_nmap_runs_through_sudo` |
| "MAC addresses are masked everywhere." | `conetuga/analysis/parser.py`, `lab/mask_scan.py` | `tests/test_privacy.py::test_no_raw_mac_on_the_web_page`, `::test_no_raw_mac_in_findings_or_scores_csv`, `::test_no_raw_mac_in_the_history_on_disk` |
| "In our own lab, two fixes took the score from 0 to 70, and the history shows them resolved, with no false alarm." | `lab/scans/`, `conetuga/history/diff.py` | `tests/test_lab_scans.py::test_history_shows_the_fixes_as_resolved_with_no_change_alert` |
| "Ask in plain words: the answer comes only from the scan, cites the finding it relies on, and says when the scan can't answer." | `conetuga/explain/qa.py` | `tests/test_qa.py::test_contract_answer_question`, `::test_what_the_scan_does_not_show_gets_the_fixed_sentence`, `::test_a_device_without_findings_is_not_called_safe` |
| "One click gives a one-page report for your IT supplier, with the before/after." | `ui/report.py` | `tests/test_ui_report.py` |

Planned claims, to move into the table once their test passes: none for now. (The old "the AI can't invent a port:
code checks every sentence" is gone: we use no LLM, so there is nothing to check; say "retrieval-based", not "AI".)

## Numbers for the demo
- Validation Set: 24/24 rows, 0 extra rows, 8/8 scores.
- Our lab (`lab/scans/`, analysed by our own tool): score 0 → 50 → 70. Fix 1 (telnet and FTP off) and fix 2 (Redis
  off) resolved 4 findings and added none. In the UI: pick `scan_01.xml`, then `scan_03.xml`.

## Trade-offs (what we chose, and what we gave up for it)
- **Exact catalog over clever guesses:** findings come only from nmap's service name and the official rules, so the
  Test Set re-run matches our upload byte for byte; the price is that we report only what nmap names (an open
  Mosquitto renamed by nmap's own script isn't MQTT_EXPOSED on a live scan).
- **No LLM:** fixed, reviewed RO/EN texts and a retrieval-based Q&A instead of a model; nothing can be invented and no
  key or secret is needed, but the wording doesn't adapt to the question beyond what the scan shows.
- **Safety over speed:** at most 100 packets per second and a 5-minute limit per device; our 2-device lab takes about
  200 s, so a busy /24 may take longer.
- **Privacy by default:** MACs keep only their vendor part everywhere, the history stays on the computer, and lab
  captures are masked and checked for leaks before they reach the repo.

## Limitations (say them honestly; never claim them as done)
- Live scans miss MQTT_EXPOSED on an open Mosquitto: nmap's `-sV` script renames the service.
- A device whose MAC prefix nmap doesn't know and that shows no hostname is an UNKNOWN_DEVICE (our targets laptop);
  a bare port 21 is called ftp from nmap's port table (our phone).
- The device type is a label guessed from services, vendor and hostname, never a finding.
- History matches devices by IP + hostname: a device that gets a new address from DHCP shows as removed and new.
- The Q&A answers only what the scan shows; anything else gets "Scanul nu arată asta."

## Next steps
- An optional LLM layer that only rephrases the built-in text, with every sentence checked against the scan.
- Fix steps tailored to the detected router model.
- Live scans saved straight into the history, for the loop "fix → rescan → ✅ resolved".

## What we brought, and what we built in 24 hours

## How we used AI
- **In the product: none deciding.** Findings, severities and scores come only from code and the catalog; the Q&A is
  retrieval-based, from the scan and our fixed texts.
- **To build it:** every team member worked with a Claude Code session under the same `CLAUDE.md` rules (contract
  first, tests before "done", no commit on `main`). The sessions talked through one `COMMS.md` inbox per member, and
  every change after hour 1 reached `main` through a reviewed Pull Request with green tests on Linux and Windows.
- **What we can show:** the "who waits for whom" graph with its history of the day, rebuilt from the inboxes and PRs
  every 15 minutes; the PR list; the test count.
