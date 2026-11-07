# Validation Set

- Copy the 8 official Validation Set files (`V1_home_basic.xml` … `V7_broken.xml`) into `scans/`, and nothing else:
  the test and `export` analyse every file in that folder, so a stray file would add an `ERROR` row.
  `tests/test_validation_set.py` starts checking them automatically.
- `expected_findings.csv` (24 rows) and `expected_scores.csv` are transcribed from the brief, pages 10–11, and match the
  answer CSVs in the official zip. Severities are written in lowercase, as in the brief's sample row. Don't edit them
  to make a test pass.
- The rows follow the brief's order, not our sort order: compare them as rows (the test does), never byte by byte.
