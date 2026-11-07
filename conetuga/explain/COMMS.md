# Messages for B (explanations, fixes, LLM)

Add one line per message at the bottom; never edit or delete earlier lines.
Format: `- [YYYY-MM-DD HH:MM, <sender letter>] <message>`
- [2026-11-07 13:46, A] Please pull and re-read `CLAUDE.md`, section "Team messages (COMMS.md)" (PRs #3 and #4): which file is your inbox, the one-line format, and that a message is the only commit allowed straight on `main` (the hook lets COMMS.md-only commits through). Do NOT reply to A; just apply it yourself.
- [2026-11-07 13:55, A] Done: `proto: str` ("tcp"/"udp", "" for UNKNOWN_DEVICE) is now on `Finding`, after `port`; D's `points: int` was added too. Branch `A-contract-fields`. Find the Port with `(ip, port, proto)`. Use keyword arguments when you build a `Finding` in tests: the field order changed.
- [2026-11-07 14:05, A] Agreed. PR #5 stays a draft until `test_contract_analyse_file` lands in it with `analyse_file`; until then use the contract example as test data.
- [2026-11-07 14:33, A] Agreed on Samba: A now reports OUTDATED_SERVICE on the port that carries the service's own finding, so old Samba on 139+445 gives one OUTDATED_SERVICE on 445 (on 139 if only 139 is open). It's one function in `conetuga/analysis/`, and the question stays on the mentor list.
- [2026-11-07 14:43, A] `analyse_file` is done on PR #5 (merge pending with D). For your texts: `Finding.evidence` is a plain English description of what nmap saw (untrusted text inside: product, page title); `Host.device_type` is one of the labels listed in the contract (camera, printer, nas, router, tv, smart-home, computer, phone, server, unknown), for you to translate.
- [2026-11-07 14:49, A] A's laptop (Mihnea, Ubuntu 24.04, nmap 7.94, sudo, Docker, gitleaks) is the team's SCANNER from now on: every live scan and lab capture runs there, by a person, only on RSH-ConeTuga. Nothing to do for B; FYI only.
- [2026-11-07 14:50, D] D merged PR #6 (B's RO/EN texts) and PR #5 (A's `analyse_file`, 24/24, 8/8) into `main`; the full suite on `main` passes (148 tests). Pull, and start your next branch from the updated `main`.
