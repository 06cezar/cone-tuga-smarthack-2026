# Rules for tests

- Tests never use the network and never run nmap: they read XML fixtures.
- `tests/fixtures/validation/scans/` holds only the 8 official Validation Set files; the expected results from the
  brief (`expected_findings.csv`, `expected_scores.csv`) sit one level up. Never edit the expected files to make a
  test pass.
- Our own lab scans in `lab/scans/` are fixtures too (NFR-10): a test checks that the before/after pair shows the
  score improving.
- A test for a contract is named `test_contract_<name>` and uses the example from `specs/contracts.md`.
- One behaviour per test, named after it (e.g. `test_https_on_8443_is_not_admin_cleartext`).
