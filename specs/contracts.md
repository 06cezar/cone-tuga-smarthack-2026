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
- Errors: an unreadable or truncated file (V7) returns `hosts=[]`, `findings=[]`, `score=None` and a clear `error`,
  and never raises. Findings are sorted by IP (as a number), port (`None` as -1) and code, so two runs give the same
  result; no finding appears twice.
- Test: `tests/test_analysis.py::test_contract_analyse_file`

### export · owner: C · used by: the CLI, the upload at hour 21
- Call: `export(folder: Path, out: Path) -> None`, also `python -m conetuga analyse <folder> --out <out>`
- Input: `tests/fixtures/validation/scans/`. Output: `out/findings.csv` and `out/scores.csv`, exactly as above.
- Which files count: every file in the folder except hidden ones (names starting with `.`), whatever the extension,
  sorted by name, so a broken file named `.txt` still gets its `ERROR` row. Ask a mentor; change this only on their answer.
- Errors: a broken file adds an `ERROR` row and the export goes on.
- Test: `tests/test_export.py::test_contract_export`

### detect_network · owner: C · used by: check_scope (the default allowlist), D (the UI shows the network)
- Call: `detect_network() -> Network(interface: str, ip: str, subnet: str, gateway: str)`, with no manual input (FR-01)
- Example, on an iPhone hotspot: `Network("Wi-Fi", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")`.
- Errors: with no active interface it raises `NetworkNotFound` with a clear message; the subnet is never hard-coded.
- Test: `tests/test_guard.py::test_contract_detect_network`, with the output of the OS commands saved as fixtures

### check_scope · owner: C · used by: the live scan
- Call: `check_scope(target: str, allowlist: list[str], confirmed: bool, ssid: str) -> ScopeDecision(allowed: bool,
  reason: str)`
- Examples, with the laptop on `172.20.10.0/28` and `ssid="RSH-ConeTuga"`: `8.8.8.8` is refused (public IP);
  `100.64.0.1` is refused (the mobile carrier's shared range); `192.168.1.0/24` is refused (outside the allowlist,
  like the venue network); `172.20.0.0/16` is refused (larger than our subnet); `router.local` is refused (not an IP
  or a CIDR); `172.20.10.0/28` with `confirmed=False` is refused (needs `--confirm`); with `confirmed=True` it is
  allowed. With `ssid="Venue-WiFi"`, every target is refused, the connected subnet too.
- Test: `tests/test_guard.py::test_contract_check_scope`

### explain · owner: B · used by: D (UI)
- Call: `explain(finding: Finding, host: Host, lang: str) -> Explanation(title: str, text: str, steps: list[str],
  references: list[str], source: str)`.
  - `lang` is `"ro"` or `"en"`; `source` is `"template"` (built-in text from `data/explanations.toml`) or `"llm"`.
  - The finding's port is the `Port` in `host.ports` with `(port, proto) == (finding.port, finding.proto)`; it gives
    the structured evidence (service, product, version) that the LLM check needs.
  - The text holds only values from the finding and the host: `{ip}`, `{port}`, and for OUTDATED_SERVICE `{product}`
    and `{version}` from that `Port`. Scan values are inserted as plain text, never read as a template.
  - Depends on `Finding.proto`, added in PR #5 (`A-contract-fields`, still a draft): until it lands on `main`, callers
    use this example as test data.
- Example: `Finding(file="V1_home_basic.xml", ip="192.168.1.1", port=80, proto="tcp", code="HTTP_ADMIN_CLEARTEXT",
  severity="medium", points=10, evidence=...)` with its host and `lang="ro"` gives a text of at most 2 sentences that
  contains `192.168.1.1`, 1–5 steps, and `source="template"` when there's no LLM.
- Errors: an unknown code or language raises `KeyError`; an LLM failure falls back to the template and never raises.
  If no `Port` in `host.ports` matches `(finding.port, finding.proto)` for OUTDATED_SERVICE, `explain` raises
  `LookupError`: that means analyse_file returned inconsistent data, a bug to fix, not a case to hide.
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
