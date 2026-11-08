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
| "Our findings log is tamper-evident: change, delete, swap or clear a row and `ledger verify` names the batch; the CSVs never change." | `conetuga/ledger/`, `contracts/src/FindingsLedger.sol` | `tests/test_ledger.py::test_any_change_to_an_anchored_row_is_found`, `::test_two_rows_swapped_are_found`, `::test_a_cleared_log_is_found`, `::test_analyse_logs_every_finding_and_its_csv_is_unchanged` |
| "Two guides, one answer: Tuga explains in plain words, Cone adds the evidence and the catalog rule; the findings, the score and the headline never change with the mode." | `conetuga/explain/narrate.py`, `ui/cards.py`, `ui/state.py` | `tests/test_narrate.py::test_contract_narrate`, `tests/test_ui_guides.py::test_in_advanced_mode_cone_takes_over_and_the_headline_stays_the_same` |
| "A device nmap gave up on is shown as 'not checked', never as safe." | `ui/view.py`, `ui/cards.py` | `tests/test_ui_devices_page.py::test_a_device_nmap_gave_up_on_is_not_checked_rather_than_safe`, `::test_a_timed_out_device_with_findings_shows_them_and_the_warning` |
| "Hostile text inside a scan stays plain text: a MAC hidden in a banner is masked, and a hostname or a port protocol can't become a link on the page." | `conetuga/analysis/parser.py`, `ui/view.py` | `tests/test_mac_in_text.py::test_a_mac_in_any_other_scan_text_is_masked`, `::test_findings_are_the_same_with_or_without_a_mac_in_the_banner`, `tests/test_traps.py::test_a_protocol_nmap_never_writes_makes_the_file_unreadable`, `tests/test_ui_devices_page.py::test_a_hostile_hostname_is_shown_as_plain_text`, `tests/test_ui_protocol_escaped.py::test_a_hostile_protocol_is_plain_text_in_a_finding_card` |
| "Accessible on both themes: text of at least 16 px, a keyboard focus you can see, colour never alone, and the guides' pictures readable on light and dark." | `ui/style.py`, `ui/view.py`, `ui/assets/` | `tests/test_ui_focus.py`, `tests/test_ui_assets.py::test_a_picture_reads_on_both_themes`, `tests/test_ui_devices_page.py::test_every_device_is_listed_riskiest_first` |
| "Statistics are opt-in, count only kinds of problems (no IP, MAC or name), and 'Delete my history' deletes them." | `conetuga/insights/` | `tests/test_insights.py::test_statistics_are_off_until_the_person_turns_them_on`, `::test_the_store_holds_only_code_counts_and_the_opt_in`, `::test_deleting_the_history_deletes_the_statistics` |
| "A checkup a grandparent can follow: one task at a time, the biggest gain first, at most 3 steps in plain words; tick it and see the estimated score." | `ui/checkup.py`, `ui/cards.py` | `tests/test_ui_checkup.py::test_the_biggest_gain_comes_first`, `::test_only_the_next_task_is_open`, `::test_a_tick_raises_the_estimated_score_and_opens_the_next_task`, `tests/test_ui_simple_mode.py::test_simple_cards_give_at_most_a_few_steps` |
| "Every fix says what it is worth: fixing the camera stream takes our smart-home example from 40 to 60." | `ui/view.py`, `ui/cards.py` | `tests/test_ui_whatif_voice.py::test_fixing_the_camera_stream_raises_v2_from_40_to_60`, `::test_acasa_says_how_much_each_fix_gives`, `::test_the_score_after_a_fix_never_passes_100` |
| "Tap Tuga and he reads the result aloud, with a voice already on your computer: nothing is sent online and nothing is downloaded." | `ui/voice.py`, `ui/talking.py` | `tests/test_ui_whatif_voice.py::test_only_voices_on_this_computer_are_used`, `::test_the_voice_page_loads_nothing_from_outside`, `tests/test_ui_talking.py::test_the_guide_speaks_at_its_own_pace_with_local_voices_only`, `::test_scan_text_never_becomes_html_and_nothing_is_loaded` |
| "Big targets and calm motion: buttons at least 48 px, every colour tint keeps AA contrast on both themes, and with 'reduce motion' nothing moves." | `ui/style.py`, `ui/motion.py` | `tests/test_ui_friendly_style.py::test_buttons_and_card_titles_are_easy_to_hit`, `::test_the_text_keeps_aa_contrast_on_every_tint`, `tests/test_ui_motion.py::test_reduce_motion_draws_the_final_state`, `tests/test_ui_talking.py::test_the_style_animates_the_guide_but_not_for_reduced_motion` |

Planned claims, to move into the table once their test passes: none for now. (The old "the AI can't invent a port:
code checks every sentence" is gone: we use no LLM, so there is nothing to check; say "retrieval-based", not "AI".)

## Numbers for the demo
- Validation Set: 24/24 rows, 0 extra rows, 8/8 scores.
- Our lab (`lab/scans/`, analysed by our own tool): score 0 → 50 → 70. Fix 1 (telnet and FTP off) and fix 2 (Redis
  off) resolved 4 findings and added none. In the UI: pick `scan_01.xml`, then `scan_03.xml`.
- Accessibility (FE-E2, run by hand, not in CI): axe-core 4.10 with the WCAG 2.1 A/AA rules, on Acasă, Dispozitive,
  Scanare and Despre, in Streamlit's light and dark themes: 0 violations, no text under 16 px. It found two things we
  then fixed: a focused menu link you couldn't see (#61) and a 2.69:1 colour in the Scanare command (#64). That run
  was before the new Acasă (#78–#81: checkup, talking Tuga, coloured cards): run it again before quoting it on stage.

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
- Tuga reads aloud only with a voice installed on the computer (Windows: Andrei for Romanian); without one, he says
  how to add it. We never fall back to an online voice, because the text names the person's devices.
- The checkup's estimated score trusts the person's tick: only a new scan proves a fix, and the page says so.

## Next steps
- An optional LLM layer that only rephrases the built-in text, with every sentence checked against the scan.
- Fix steps tailored to the detected router model.
- A one-click "rescan" in the UI for the loop "fix → rescan → ✅ resolved" (live scans already reach the history,
  #47, but they are started from the terminal so the UI never needs administrator rights).

## What we brought, and what we built in 24 hours

## How we used AI
- **In the product: none deciding.** Findings, severities and scores come only from code and the catalog; the Q&A is
  retrieval-based, from the scan and our fixed texts.
- **To build it:** every team member worked with a Claude Code session under the same `CLAUDE.md` rules (contract
  first, tests before "done", no commit on `main`). The sessions talked through one `COMMS.md` inbox per member, and
  every change after hour 1 reached `main` through a reviewed Pull Request with green tests on Linux and Windows.
- **What we can show:** the "who waits for whom" graph with its history of the day, built from the inboxes and PRs;
  the PR list; the test count.
