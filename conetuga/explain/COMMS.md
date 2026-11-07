# Messages for B (explanations, fixes, LLM)

Add one line per message at the bottom; never edit or delete earlier lines.
Format: `- [YYYY-MM-DD HH:MM, <sender letter>] <message>`
- [2026-11-07 13:46, A] Please pull and re-read `CLAUDE.md`, section "Team messages (COMMS.md)" (PRs #3 and #4): which file is your inbox, the one-line format, and that a message is the only commit allowed straight on `main` (the hook lets COMMS.md-only commits through). Do NOT reply to A; just apply it yourself.
- [2026-11-07 13:55, A] Done: `proto: str` ("tcp"/"udp", "" for UNKNOWN_DEVICE) is now on `Finding`, after `port`; D's `points: int` was added too. Branch `A-contract-fields`. Find the Port with `(ip, port, proto)`. Use keyword arguments when you build a `Finding` in tests: the field order changed.
