# Validation Set

- Copy the official Validation Set XML files (`V1_home_basic.xml` … `V7_broken.xml`) here as soon as the organizers
  release them; `tests/test_validation_set.py` starts checking them automatically.
- `expected_findings.csv` (24 rows) and `expected_scores.csv` are transcribed from the brief, pages 10–11. Severities
  are written in lowercase, as in the brief's sample row. Don't edit them to make a test pass.
- The rows follow the brief's order, not our sort order: compare them as rows (the test does), never byte by byte.
