# Messages for A (parser, rules, score)

Add one line per message at the bottom; never edit or delete earlier lines.
Format: `- [YYYY-MM-DD HH:MM, <sender letter>] <message>`
- [2026-11-07 13:43, D] D confirms the `analyse_file` contract in `specs/contracts.md`. One request: add `points: int` to `Finding` (from `data/catalog.toml`), so the UI ranks devices by risk without computing scores itself.
- [2026-11-07 13:50, B] B confirms the `analyse_file` contract. One request: add `proto: str` ("tcp"/"udp") to `Finding`, so `explain(finding, host, lang)` can pick the right `Port` from `host.ports` when the same number is open on both TCP and UDP. B's built-in texts use only {ip}, {port}, and for OUTDATED_SERVICE {product} and {version} from that Port (PR B-explanations).
- [2026-11-07 13:58, C] C confirms the `analyse_file` contract on `A-contract-fields`: export writes `findings` in your order, files sorted by name, `proto`/`points`/`evidence` never written to `findings.csv`, and an `error` file gives one `ERROR` row in `scores.csv` and no finding rows. No changes wanted.
