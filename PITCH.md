# Pitch claims (claim → file → test)

Every claim we make on stage has a row here, and no claim goes on stage without a passing test. The pitch is 5–7
minutes, in English, with at least two speakers (juniors and seniors both speak). The jury session is 15 minutes:
7 of pitch, then 8 of live checks. Order: problem, demo, numbers, trade-offs, limitations, next steps.

| Claim | File | Test |
|---|---|---|
| "We reproduce the Validation Set: 24 of 24 rows, no extra rows, every score." | `conetuga/analysis/` | `tests/test_validation_set.py` |
| "Same file, same result, every time: the AI never decides a finding." | `conetuga/analysis/rules.py`, `data/catalog.toml` | `tests/test_analysis.py::test_same_file_gives_the_same_result_every_time` |
| "A hostile scan file can't trick the parser: external entities (XXE), truncated and oversized files are refused with a clear error." | `conetuga/analysis/parser.py` | `tests/test_analysis.py::test_xml_external_entities_are_refused`, `::test_truncated_file_gives_no_findings_from_its_first_half`, `::test_file_larger_than_the_limit_is_an_error` |
| "Every one of the 15 findings is explained in Romanian and English, in at most 2 sentences, with 1–5 fixes, and no hand-written IP, port or CVE." | `data/explanations.toml` | `tests/test_explanations.py` |

Planned claims, to move into the table once their test passes:
- "The tool refuses public IPs and anything outside our hotspot."
- "A broken file shows a clear error, and the other files still run."
- "The AI can't invent a port or a CVE: code checks every sentence."
- "MAC addresses are masked everywhere."

## Numbers for the demo
- Validation Set: 24/24 rows, 0 extra rows, 8/8 scores.
- Our lab: score before _ → after _.

## Trade-offs (what we chose, and what we gave up for it)

## Limitations (say them honestly; never claim them as done)

## Next steps

## What we brought, and what we built in 24 hours

## How we used AI
