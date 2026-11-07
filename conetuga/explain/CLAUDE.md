# Rules for conetuga/explain (stream B: explanations, fixes, Q&A)

- Every catalog code has built-in text in Romanian and English (`data/explanations.toml`): it's what the user
  reads for every finding.
- An explanation is at most 2 sentences, with no unexplained technical term, at about a 12-year-old's reading level.
  Words like "port" or "Telnet" get a few plain words of explanation the first time.
- Fixes are 1–5 ordered, concrete steps a non-expert can follow, most important first.
- No LLM in this version (team decision, 2026-11-07): the next three rules apply only if one is added later.
- The LLM only explains a finding that code already produced; it never adds, removes or re-rates findings.
- A prompt gets only the evidence for that finding (code, IP, port, service, product, version), wrapped as untrusted
  data.
  MAC addresses and hostnames never reach the model.
- Code checks every AI answer against the evidence: an IP, port, version, CVE or phone number that isn't in it fails
  the check. After two failed checks, the built-in text answers.
- The Q&A assistant (FR-12) answers only from the scan and cites the finding it relies on, e.g.
  `[192.168.1.10:9100 PRINTER_RAW_EXPOSED]`. When the scan can't answer ("is WPS on?"), it says "Scanul nu arată asta".
- UNKNOWN_DEVICE with a locally administered MAC (second hex digit 2, 6, A or E): the text may say it's probably a phone
  using a private MAC, not an intruder. The finding itself stays.
