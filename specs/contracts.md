# Contracts between streams

Write a contract before the code, for anything another stream calls. Keep it short: the call, one real example, the
errors. The example becomes a test named `test_contract_<name>`; `pytest -k contract` runs them all. Until a feature
lands, callers use the example as test data, never a stub. A contract changes only when its users agree, in one commit
with its test.

## Fixed by the brief (nobody changes these)

### findings.csv and scores.csv · owner: C · used by: the jury
- `findings.csv`: header `file,ip,port,finding_code,severity`, one row per finding; `port` is empty for
  UNKNOWN_DEVICE; severities in lowercase (`high`, `medium`, `low`, `info`), as in the brief's sample row.
- `scores.csv`: header `file,network_score`, one row per file; `ERROR` when the file can't be read.
- Example (brief, page 8): `V1_home_basic.xml,192.168.1.1,80,HTTP_ADMIN_CLEARTEXT,medium` and `V1_home_basic.xml,90`.
- The expected results for the whole Validation Set: `tests/fixtures/validation/expected_*.csv` (24 finding rows).

## Proposed at hour 1–2 (agree, then build)

### analyse_file · owner: A · used by: C (export), D (UI, history), B (explanations)
- Call: `analyse_file(path: Path) -> FileResult`
  - `FileResult(file: str, hosts: list[Host], findings: list[Finding], score: int | None, error: str)`
  - `Finding(file: str, ip: str, port: int | None, code: str, severity: str, evidence: str)`
  - `Host(ip: str, mac_masked: str, vendor: str, hostname: str, device_type: str, ports: list[Port])`
  - `Port(port: int, proto: str, service: str, product: str, version: str, ssl: bool, title: str)`, open ports only
- Input (real example): `V1_home_basic.xml` from the Validation Set.
- Output: `findings == [Finding("V1_home_basic.xml", "192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT", "medium", ...)]`,
  `score == 90`, `error == ""`.
- Errors: an unreadable or truncated file (V7) returns `score=None` and a clear `error`, and never raises. Findings are
  sorted by ip, port and code, so two runs give the same result.
- Test: `tests/test_analysis.py::test_contract_analyse_file`

### export · owner: C · used by: the CLI, the upload at hour 21
- Call: `export(folder: Path, out: Path) -> None`, also `python -m conetuga analyse <folder> --out <out>`
- Input: the Validation Set folder. Output: `out/findings.csv` and `out/scores.csv`, exactly as above.
- Errors: a broken file adds an `ERROR` row and the export goes on.
- Test: `tests/test_export.py::test_contract_export`

### check_scope · owner: C · used by: the live scan
- Call: `check_scope(target: str, allowlist: list[str], confirmed: bool) -> ScopeDecision(allowed: bool, reason: str)`
- Examples, with the laptop on `172.20.10.0/28`: `8.8.8.8` is refused (public IP); `192.168.1.0/24` is refused
  (outside the allowlist); `172.20.10.0/28` with `confirmed=False` is refused (needs `--confirm`); with
  `confirmed=True` it is allowed.
- Test: `tests/test_guard.py::test_contract_check_scope`

### explain · owner: B · used by: D (UI)
- Call: `explain(finding: Finding, lang: str) -> Explanation(text: str, steps: list[str], source: str)`
- Example: HTTP_ADMIN_CLEARTEXT on 192.168.1.1:80 with `lang="ro"` gives at most 2 sentences, 1–5 steps, and
  `source="template"` when there's no LLM.
- Errors: an unknown code or language raises `KeyError`; an LLM failure falls back to the template and never raises.
- Test: `tests/test_explain.py::test_contract_explain`

### diff · owner: D · used by: the UI, change alerts (FR-13)
- Call: `diff(before: FileResult, after: FileResult) -> Diff(new_devices, removed_devices, opened_ports, closed_ports,
  resolved_findings, score_before, score_after)`
- Example: `V6a_before.xml` → `V6b_after.xml` gives 3 resolved findings and a score going from 60 to 100, with no
  new or removed devices.
- Errors and edge cases: devices are matched by IP + hostname, never by MAC (the same device can show a different MAC).
- Test: `tests/test_history.py::test_contract_diff`

## Template (copy it)

### <name> · owner: <stream> · used by: <streams>
- Call: `<function(arg: Type) -> Type>`
- Input (real example): <...>
- Output (for that input): <...>
- Errors and edge cases: <...>
- Test: `tests/<file>.py::test_contract_<name>`
