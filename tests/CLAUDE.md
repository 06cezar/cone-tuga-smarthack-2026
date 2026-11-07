# Rules for tests

- Tests never use the network and never run nmap: they read XML fixtures.
- `tests/fixtures/validation/` holds the official Validation Set (copied in at kickoff) and the expected results from
  the brief (`expected_findings.csv`, `expected_scores.csv`). Never edit the expected files to make a test pass.
- A test for a contract is named `test_contract_<name>` and uses the example from `specs/contracts.md`.
- One behaviour per test, named after it (e.g. `test_https_on_8443_is_not_admin_cleartext`).
