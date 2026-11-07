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
  - `Finding(file: str, ip: str, port: int | None, proto: str, code: str, severity: str, points: int, evidence: str)`
    - `proto` is `"tcp"` or `"udp"`: with `ip`, `port` and `proto`, B finds the finding's `Port` in `host.ports` even
      when the same number is open on both. UNKNOWN_DEVICE has `port=None` and `proto=""`.
    - `points` is the catalog's points for `severity` (`data/catalog.toml`, `[severity_points]`), so the UI ranks by
      risk without computing anything; `score == max(0, 100 - sum(f.points for f in findings))`.
  - `Host(ip: str, mac_masked: str, vendor: str, hostname: str, device_type: str, ports: list[Port],
    timed_out: bool = False)`
    - `timed_out` is True when nmap gave up on the device (`<host timedout="true">`, e.g. a live scan's
      `--host-timeout`): nmap writes none of its ports, so it has no findings because it wasn't checked, not
      because it's safe. The UI and the CLI say so next to it; findings and the score don't change.
    - `device_type` is one of `camera`, `printer`, `nas`, `router` (also access points), `tv`, `smart-home`,
      `computer`, `phone`, `server`, `unknown` (the `DEVICE_*` constants in `conetuga/analysis/devices.py`); B and D
      translate them. A label only: it never changes a finding or the score.
  - `Port(port: int, proto: str, service: str, product: str, version: str, ssl: bool, title: str)`, open ports only
- Input (real example): `V1_home_basic.xml` from the Validation Set.
- Output: `findings == [Finding(file="V1_home_basic.xml", ip="192.168.1.1", port=80, proto="tcp",
  code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10, evidence=...)]`, `score == 90`, `error == ""`.
- Errors: an unreadable or truncated file (V7) returns `hosts=[]`, `findings=[]`, `score=None` and a clear `error`,
  and never raises. Findings are sorted by IP (as a number), port (`None` as -1) and code, so two runs give the same
  result. No two findings share `(file, ip, port, code)`, the columns of `findings.csv`, so the export never
  writes a duplicate row; if both protocols of one port would give the same code, only the TCP one is kept.
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
  - Privacy (NFR-02): `host.hostname`, when not empty, is replaced (ignoring case) inside every scan value
    (`product`, `version`, `service`) with "nume ascuns" / "hidden name" before `fill()`, so a hostname inside a
    banner never reaches the text. MAC-shaped text is masked by the parser when the file is read (A, as C asked at
    21:59). Hosts with no hostname inside a banner get the same explanation as before.
- Example: `Finding(file="V1_home_basic.xml", ip="192.168.1.1", port=80, proto="tcp", code="HTTP_ADMIN_CLEARTEXT",
  severity="medium", points=10, evidence=...)` with its host and `lang="ro"` gives a text of at most 2 sentences that
  contains `192.168.1.1`, 1–5 steps, and `source="template"` when there's no LLM.
- Errors: an unknown code or language raises `KeyError`; an LLM failure falls back to the template and never raises.
  If no `Port` in `host.ports` matches `(finding.port, finding.proto)` for OUTDATED_SERVICE, `explain` raises
  `LookupError`: that means analyse_file returned inconsistent data, a bug to fix, not a case to hide.
- Test: `tests/test_explain.py::test_contract_explain`
- Also: `device_label(device_type: str, lang: str) -> str`, the label people read for `Host.device_type`, from
  `[device_types]` in `data/explanations.toml`. The types are the 10 values of `Host.device_type` in analyse_file
  (`camera`, `printer`, `nas`, `router`, `tv`, `smart-home`, `computer`, `server`, `phone`, `unknown`).
  - Example: `device_label("nas", "ro") == "Dispozitiv de stocare în rețea (NAS)"`,
    `device_label("nas", "en") == "Network storage (NAS)"`.
  - Errors: an unknown device type or language raises `KeyError`.
  - Test: `tests/test_explain.py::test_contract_device_label`

### diff · owner: D · used by: the UI, change alerts (FR-13)
- Call: `diff(before: FileResult, after: FileResult) -> Diff(new_devices: list[Host], removed_devices: list[Host],
  opened_ports: list[tuple[Host, Port]], closed_ports: list[tuple[Host, Port]], resolved_findings: list[Finding],
  score_before: int, score_after: int)`, from `conetuga.history`. A port is `(port, proto)`; a finding is resolved when
  its device, port and code are gone from `after`. `new_devices` and `opened_ports` are the change alerts (FR-13).
- Example: `V6a_before.xml` → `V6b_after.xml` gives 3 resolved findings (HTTP_ADMIN_CLEARTEXT and UPNP_EXPOSED on
  the router, TELNET_OPEN on the plug), a score going from 60 to 100, no new or removed devices, and one opened port
  (443/tcp on the router).
- Errors and edge cases: devices are matched by IP + hostname, never by MAC (the same device can show a different MAC).
  A result with an `error` can't be compared: `diff` raises `ValueError`.
- Also, the local store (`.history/`, gitignored, NFR-02): `save_scan(result, content) -> bool` (False when the same
  file content is already saved, or the result has an error), `load_history() -> list[Record(saved_at: str, file: str,
  digest: str, result: FileResult)]` oldest first, `delete_history()` removes the folder and everything in it.
  `python -m conetuga scan` calls `save_scan` after every live scan it analyses (FR-10: every scan), with the raw XML's
  bytes as `content`; the stored result holds masked MACs only, and devices nmap gave up on keep `timed_out=True`.
- Test: `tests/test_history.py::test_contract_diff`

### answer_question · owner: B · used by: D (UI)
- Call: `answer_question(question: str, result: FileResult, lang: str) -> Answer(text: str, citations: list[str],
  source: str)`, from `conetuga.explain`. The Q&A assistant (FR-12), with no network and no key.
  - `lang` is `"ro"` or `"en"`, the language of the answer (the question may be in either). `source` is `"retrieval"`:
    the answer is built only from `result`'s findings and hosts, `explain()` and fixed texts in `data/` (later maybe
    `"llm"`, only behind the NFR-06 check).
  - Every citation is a finding the text relies on, written `[ip:port CODE]` (`[ip CODE]` for UNKNOWN_DEVICE), and
    appears in `text`. When the scan can't answer, `text` is exactly "Scanul nu arată asta." (ro) / "The scan doesn't
    show this." (en) and `citations == []`. When the question names something the scan shows but no finding is on it,
    the answer says the scan found no catalog problem there, never that it is safe.
  - A question about something no scan shows (WPS, a password, firmware, the SSID…) gets the cannot-answer sentence,
    even when it names a device, unless it also names a service the scan checks.
  - A device nmap gave up on (`Host.timed_out`) is never called problem-free: the answer never says "no catalog
    problem" about a question that names it, or that names only a service while any device timed out; findings the
    scan does have are still shown, and with none to show the answer is the cannot-answer sentence.
  - A number counts as a port after a word starting with "port", as `ip:port`, as `N/tcp` or `N/udp`, or when it is
    an open port in `result`. `N/tcp` or `N/udp` matches only that protocol.
  - "Most dangerous" / "what do I fix first" follows the UI's rule (`ui/view.py`, `devices_by_risk` and `headline`):
    the device with the highest sum of `points` (ties: the lower IP as a number), then its finding with the most
    `points` (ties: `analyse_file`'s order); "fix first" is that finding's `steps[0]`. When that device has 0 points,
    the answer says the scan found nothing dangerous. On `V6a_before.xml`, the router at 192.168.1.1 (10 + 10) beats
    192.168.1.30 (20) on IP, and its finding is HTTP_ADMIN_CLEARTEXT.
  - The question is untrusted text (NFR-03): no part of it is ever copied into the answer. Same inputs, same answer.
- Input (real example): `analyse_file("V3_small_office.xml")`, the brief's question
  "is it safe that my printer has port 9100 open?", `lang="en"`.
- Output: `citations == ["[192.168.1.10:9100 PRINTER_RAW_EXPOSED]"]`, `text` contains `192.168.1.10` and that
  citation, `source == "retrieval"`. On the same result, "Is WPS turned on?" with `lang="en"` gives
  `text == "The scan doesn't show this."` and `citations == []`.
- Errors and edge cases: an unknown language raises `KeyError`; an empty question (only spaces) or one longer than
  `MAX_QUESTION_CHARS` (300, a named constant) raises `ValueError`; a result with an `error` raises `ValueError`
  (nothing to answer from, as in `diff`), so the UI offers no question box for such a file.
- Test: `tests/test_qa.py::test_contract_answer_question`; `tests/test_qa.py` also checks that "most dangerous"
  names the same device and finding as `ui.view.devices_by_risk` on V1–V6.

### narrate · owner: B · used by: D (Dispozitive, Acasă), later B's assistant
- Call: `narrate(finding: Finding, host: Host, lang: str, mode: str) -> Narration(speaker: str, title: str, text: str,
  evidence: list[str], steps: list[str], references: list[str], source: str)`, from `conetuga.explain`.
  - `mode` is `"simple"` or `"advanced"`; the UI passes `"advanced" if current().advanced else "simple"`
    (`ui/state.py`). `speaker` is `"tuga"` for simple and `"cone"` for advanced; a third guide would be a new mode,
    not a UI change. `source` is `"template"`.
  - Simple (Tuga, the default) is exactly today's `explain(finding, host, lang)`: the same `title`, `text`, `steps`
    and `references` (the CIS Controls / OWASP IoT bonus is visible without switching modes); `evidence == []`.
    So Tuga's `text` is at most 2 sentences (FR-07), with no unexplained technical term.
  - Advanced (Cone), from `data/cone.toml`: its own `title`, a `text` of at most 2 sentences that names the technical
    terms and explains each in a few words (NFR-09), 1–5 precise `steps`, and the same `references` as `explain`.
    These texts hold no scan value and no placeholder; scan values appear only in `evidence`.
  - `evidence` (Advanced only): short lines built by code from the scan and the catalog: the port and protocol
    (`9100/tcp`), nmap's service, the product and version when nmap gave them, and the catalog rule that fired
    (code, severity, points and what it means, translated). For UNKNOWN_DEVICE, which has no port: the IP, "no
    vendor", "no name", the number of open ports, and "private (locally administered) MAC address" when the second
    hex digit of `mac_masked` is 2, 6, A or E; never the MAC itself.
  - Every evidence line starts with a label that says in plain words what the line is (e.g. "Service: the name nmap
    gave the program that answers"), translated; the labels live in `data/cone.toml`. The value after the label is
    the scan's own word, so a technical term in a value (e.g. `jetdirect`, `ms-wbt-server`) is explained in that
    code's Cone `text` (NFR-09).
  - Every scan value (ip, port, proto, service, product, version) enters `evidence` through `fill()` as plain text,
    never read as a template (NFR-03); the UI still escapes everything with `md()`. No hostname, no MAC, no page title.
  - Privacy (NFR-02): no MAC address and no hostname reaches `title`, `text`, `evidence` or `steps`, in either mode,
    even when the scan puts one inside a banner (`product`, `version`, `service`). MAC-shaped text is masked by the
    parser when the file is read (A, as C asked at 21:59), so `narrate` receives it masked. Simple is `explain()`,
    which hides `host.hostname` itself (section explain); in Advanced, `narrate` applies the same hiding to every scan
    value in `evidence`, with the same function, before the value reaches `fill()`.
- Input (real example): `analyse_file("V3_small_office.xml")`, the finding PRINTER_RAW_EXPOSED on
  `192.168.1.10:9100/tcp` and its host (service `jetdirect`, no product).
- Output: with `lang="ro"`, `mode="simple"`: `speaker == "tuga"`; `title`, `text`, `steps` and `references` equal
  `explain()`'s; `evidence == []`. With `lang="en"`, `mode="advanced"`: `speaker == "cone"`; `evidence` contains
  `9100/tcp`, `jetdirect` and `PRINTER_RAW_EXPOSED` and no line about a product;
  `references == explain(...).references`; 1–5 steps; `source == "template"`.
- Errors and edge cases: an unknown code, language or mode raises `KeyError`; in Advanced, when no `Port` in
  `host.ports` matches `(finding.port, finding.proto)` for a finding that has a port, `narrate` raises `LookupError`
  (as `explain` does for OUTDATED_SERVICE: analyse_file returned inconsistent data).
- Test: `tests/test_narrate.py::test_contract_narrate`

### wiki_entries · owner: B · used by: the Wiki page, A (the "most common problems" panel links to entries)
- Call: `wiki_entries(lang: str, mode: str) -> list[WikiEntry(id: str, kind: str, speaker: str, title: str, text: str,
  references: list[str], related_codes: list[str])]`, from `conetuga.explain`. No scan needed: no entry holds an IP,
  a port number, a version or any other scan value.
  - `kind` is `"code"` (one entry per catalog code; `id` is the code, e.g. `"TELNET_OPEN"`, so `top_codes()` links
    straight to it) or `"concept"` (`id` is `"port"`, `"encryption"`, `"firewall"`, `"mac"` or `"upnp"`).
  - Order: the 15 codes in `data/catalog.toml`'s order, then the 5 concepts in the order above; the same every time.
  - `mode` and `speaker` as in `narrate`. Simple: texts from `data/wiki.toml`, at most 3 sentences (a glossary entry,
    not the explanation of a finding: FR-07's 2 sentences apply to `narrate`), no unexplained term. Advanced: for
    the 15 codes, `title` and `text` are Cone's from `data/cone.toml`; the 5 concepts have their own Advanced text in
    `data/wiki.toml`, at most 4 sentences, technical terms explained in a few words.
  - `references` (CIS Controls / OWASP IoT, as in `explain`) for codes in both modes; `[]` for concepts.
  - `related_codes`: the catalog codes an entry leads to, for the Wiki's links (e.g. `encryption` →
    `TELNET_OPEN`, `FTP_CLEARTEXT`, ...), from `data/wiki.toml`; every id is a valid catalog code, never the entry's
    own id; `[]` when none. The same in every language and mode.
- Input (real example): `wiki_entries("ro", "simple")`.
- Output: 20 entries; the first has `id == "TELNET_OPEN"`, `kind == "code"`, `speaker == "tuga"`; the last 5 are the
  concepts in the order above; every `title` and `text` is non-empty and has no `{` or `}`; the `encryption` entry's
  `related_codes` contains `FTP_CLEARTEXT`, and every `related_codes` id is a catalog code.
- Errors and edge cases: an unknown language or mode raises `KeyError`. The ids and their order are the same in every
  language and mode.
- Test: `tests/test_wiki.py::test_contract_wiki_entries`

## Template (copy it)

### <name> · owner: <stream> · used by: <streams>
- Call: `<function(arg: Type) -> Type>`
- Input (real example): <...>
- Output (for that input): <...>
- Errors and edge cases: <...>
- Test: `tests/<file>.py::test_contract_<name>`
