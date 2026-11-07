"""The oracle: the Validation Set reproduced exactly (24 finding rows, no extra rows, every score).

Rows are compared as a multiset: a duplicated row is an extra row, and the jury counts it as one. Every file in
scans/ is analysed, whatever its extension, the way export treats a folder. It skips until the official files are in
tests/fixtures/validation/scans/ and stream A's `analyse_file` exists (contract in specs/contracts.md)."""
import csv
from collections import Counter
from pathlib import Path

import pytest

VALIDATION = Path(__file__).resolve().parent / "fixtures" / "validation"
SCANS = VALIDATION / "scans"
SCAN_FILES = sorted(p for p in SCANS.iterdir() if p.is_file() and not p.name.startswith(".")) if SCANS.is_dir() else []


def read_csv(name: str) -> list[dict]:
    with (VALIDATION / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


@pytest.mark.skipif(not SCAN_FILES, reason="copy the 8 official Validation Set files into tests/fixtures/validation/scans/")
def test_validation_set_is_reproduced_exactly():
    analysis = pytest.importorskip("conetuga.analysis")
    analyse_file = getattr(analysis, "analyse_file", None)
    if analyse_file is None:
        pytest.skip("stream A: conetuga.analysis.analyse_file doesn't exist yet (see specs/contracts.md)")

    found, scores = Counter(), {}
    for path in SCAN_FILES:
        result = analyse_file(path)
        scores[path.name] = "ERROR" if result.error else str(result.score)
        found.update((f.file, f.ip, "" if f.port is None else str(f.port), f.code, f.severity) for f in result.findings)

    expected = Counter(
        (r["file"], r["ip"], r["port"], r["finding_code"], r["severity"]) for r in read_csv("expected_findings.csv")
    )
    assert found - expected == Counter(), "extra or duplicated rows cost as much as missing ones"
    assert expected - found == Counter(), "missing rows"
    assert scores == {r["file"]: r["network_score"] for r in read_csv("expected_scores.csv")}
