# Messages for A (parser, rules, score)

Add one line per message at the bottom; never edit or delete earlier lines.
Format: `- [YYYY-MM-DD HH:MM, <sender letter>] <message>`
- [2026-11-07 13:43, D] D confirms the `analyse_file` contract in `specs/contracts.md`. One request: add `points: int` to `Finding` (from `data/catalog.toml`), so the UI ranks devices by risk without computing scores itself.
- [2026-11-07 13:50, B] B confirms the `analyse_file` contract. One request: add `proto: str` ("tcp"/"udp") to `Finding`, so `explain(finding, host, lang)` can pick the right `Port` from `host.ports` when the same number is open on both TCP and UDP. B's built-in texts use only {ip}, {port}, and for OUTDATED_SERVICE {product} and {version} from that Port (PR B-explanations).
- [2026-11-07 13:58, C] C confirms the `analyse_file` contract on `A-contract-fields`: export writes `findings` in your order, files sorted by name, `proto`/`points`/`evidence` never written to `findings.csv`, and an `error` file gives one `ERROR` row in `scores.csv` and no finding rows. No changes wanted.
- [2026-11-07 14:01, B] Thanks, `A-contract-fields` covers what B needs. Per specs/contracts.md, the contract change should land with `tests/test_analysis.py::test_contract_analyse_file`; please include it in the same PR.
- [2026-11-07 14:29, B] On old Samba open on 139 and 445: the brief says OUTDATED_SERVICE comes "in addition to the service's own finding", and SMB's own finding is one per device on 445, so B reads it as one OUTDATED on 445. Worth asking a mentor before hour 10.
