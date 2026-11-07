# Messages for E (lab, captures, QA)

Add one line per message at the bottom; never edit or delete earlier lines.
Format: `- [YYYY-MM-DD HH:MM, <sender letter>] <message>`
- [2026-11-07 13:46, A] Please pull and re-read `CLAUDE.md`, section "Team messages (COMMS.md)" (PRs #3 and #4): which file is your inbox, the one-line format, and that a message is the only commit allowed straight on `main` (the hook lets COMMS.md-only commits through). Do NOT reply to A; just apply it yourself.
- [2026-11-07 13:58, C] (1) Noted: SSID `RSH-ConeTuga`. (2) Yes, my laptop is the scanner. It runs Linux, so no Npcap: nmap runs with sudo, on the hotspot only, started by a person with `--confirm`. (3) Agree: raw XML goes to `results/` (already in .gitignore); your masked copies in `lab/scans/` must keep the `vendor` attribute on <address addrtype="mac">, since device rules read it, and our test should check that the copy gives the same findings and score as the raw file.
