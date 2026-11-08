# ConeTuga: technical summary (one page)

## Lab setup
- **Network:** Stefan's iPhone hotspot `RSH-ConeTuga` (WPA2/WPA3), `172.20.10.0/28`; only team devices join it.
- **Targets** (brief setups A + C, no real data behind any weak service), on Stefan's Windows laptop: Docker Redis on
  6380, Mosquitto 1.6 on 1883 and nginx "Admin Login" on 8080; banner-only fakes for telnet (2323), FTP saying
  vsFTPd 2.3.4 (21) and a printer port (9100).
- **Scanner:** Mihnea's Ubuntu laptop, nmap 7.94, started by a person: `-sS -sU -sV --script http-title --max-rate 100`,
  scanner excluded. Raw XML stays on it (gitignored); `lab/mask_scan.py` writes the repo copy and refuses it if any
  original MAC or hostname is still inside.
- **Measured** (`lab/scans/`): `scan_01` scores 0 (7 catalog codes, 2 devices); fix 1 (telnet and FTP off) gives
  `scan_02` = 50; fix 2 (Redis off) gives `scan_03` = 70: 4 findings resolved, none new.

## Architecture
`nmap XML → parser → catalog rules → standard score → explanations → CLI / CSV export / UI + history` (Python 3.13).
- `conetuga/analysis`: `analyse_file()` parses with `defusedxml` (no entities, 20 MB limit, a broken file is an error),
  masks MACs to their vendor part, applies the 15 codes of `data/catalog.toml` by nmap's service name on `open` ports,
  and scores `max(0, 100 − points)`.
- `conetuga/explain`: `explain()` fills the built-in RO/EN text (≤ 2 sentences, 1–5 steps, CIS Controls v8.1 and OWASP
  IoT references) with values from the scan only.
- `conetuga/guard`: `detect_network()`; `check_scope()` refuses public, carrier, multicast and out-of-subnet targets,
  any Wi-Fi but our hotspot, and anything without `--confirm`; `live_scan()` asks it first and gives only nmap sudo;
  `export()` writes `findings.csv` and `scores.csv`, one `ERROR` row per unreadable file.
- `conetuga/history`: local `.history/` (gitignored), one record per scan file; `diff()` gives new/removed devices,
  opened/closed ports, resolved findings, score trend; one button deletes it all.
- `conetuga/ledger` (findings log): every finding `analyse` or `scan` detects is a SQLite row in `.history/`, deleted
  with "Șterge istoricul meu". Every 10 rows, the SHA-256 of the batch and of the batch before it goes into a
  write-once Solidity contract (`contracts/`, owner-only, through Foundry's `cast`); `ledger verify` recomputes the
  hashes and names any changed, deleted, swapped or cleared batch. Only those hashes leave the computer, and only
  when a person sets the three `CONETUGA_CHAIN_*` variables; the demo uses a local Anvil, Sepolia needs a
  testnet-only key.
- `ui/` (Streamlit): "Cel mai periculos: <device>. Fă asta întâi: <step>" first, then the traffic-light score, devices
  by risk with explanations, and the history with change alerts. Scan text is escaped.
- Calls between streams are fixed in `specs/contracts.md`, each with an example and a test. CI runs every test on Linux
  and Windows plus `gitleaks`; the Validation Set gives 24 of 24 rows, no extra rows, 8 of 8 scores.

## Security (each line has a test; the full list is in `PITCH.md`, "Security")
- **Scope:** `check_scope` before nmap starts (public, carrier, mapped, multicast, other Wi-Fi, outside the subnet,
  no `--confirm` or tick: refused); a fixed nmap argument list, no shell; only nmap gets administrator rights.
- **Hostile input:** `defusedxml` with a 20 MB limit; values nmap never writes (a protocol, an IPv6 zone) make the
  file an error; scan text is escaped on the page (`md()`), in the report (`escape()`) and in the voice (JSON).
- **Privacy and secrets:** the UI listens only on 127.0.0.1 and sends no usage statistics; MACs masked; history local,
  deleted with one click; keys only in `.env`, `gitleaks` on every commit in CI.
- **AI:** nothing decides a finding; the optional local model (off by default, 127.0.0.1 only) gets only the cited
  findings, and every answer is checked against them.

## Assumptions (one named constant or function each; the mentors have the list)
Outdated products match by name inside nmap's product, versions by leading numbers ("7.2p2" is 7.2), uncertain ones
("3.X - 4.X") only if every reading is outdated; OUTDATED_SERVICE goes on the port of the service's own finding (old
Samba: one row, on 445); title keywords match as part of the title, any case; `http-alt` is not `http`; no hosts
scores 100; no MAC means "no vendor"; one row when TCP and UDP give the same code; every non-hidden file counts.

## Limitations
- nmap's `mqtt-subscribe` (run by `-sV`) renames an open Mosquitto to its version, so live scans miss MQTT_EXPOSED;
  the standard files say "mqtt".
- Findings follow nmap's names: an unknown MAC prefix with no hostname is an UNKNOWN_DEVICE (our targets laptop); a
  bare port 21 is called ftp from nmap's port table (our phone).
- The device type is a label guessed from services, vendor and hostname, never a finding.
- History matches devices by IP + hostname: a new DHCP address shows as a removed and a new device.
- The findings log protects a row once its batch of 10 is full (up to 9 rows wait), and a deleted history needs a
  new contract (`ledger deploy`).

## LLM use
No model decides anything: findings, severities and scores come only from code and the catalog, so the same file
always gives the same result. Today every explanation is the built-in, reviewed text; an optional LLM would only
rephrase it from the scan's evidence, checked sentence by sentence, with the built-in text as the fallback. We built
the tool with Claude Code: every session followed the same `CLAUDE.md` rules, the sessions coordinated through one
`COMMS.md` inbox per member, and after hour 1 every other change reached `main` through a reviewed Pull Request with
green tests.
