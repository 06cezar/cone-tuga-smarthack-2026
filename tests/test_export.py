"""The standard export (FR-15): findings.csv and scores.csv, exactly as the jury's answer key reads them.

The expected rows follow the brief's order, not ours, so findings are compared as rows (as in test_validation_set.py),
while the bytes we write are checked separately: header, line endings, encoding, and the same bytes on every run."""
import csv
import shutil
from collections import Counter
from pathlib import Path

import pytest

import conetuga.guard.export as export_module
from conetuga.guard.export import ExportError, export, export_results, scan_files

VALIDATION = Path(__file__).resolve().parent / "fixtures" / "validation"
SCANS = VALIDATION / "scans"
V1 = SCANS / "V1_home_basic.xml"
V7_BROKEN = SCANS / "V7_broken.xml"


def read_rows(path: Path) -> list[list[str]]:
    with path.open(encoding="utf-8", newline="") as file:
        return list(csv.reader(file))


def folder_with(tmp_path: Path, files: dict[str, Path]) -> Path:
    """A scan folder holding copies of official files under new names."""
    folder = tmp_path / "scans"
    folder.mkdir()
    for name, source in files.items():
        shutil.copyfile(source, folder / name)
    return folder


def scores(out: Path) -> list[list[str]]:
    return read_rows(out / "scores.csv")[1:]


def test_contract_export(tmp_path):
    """The contract's example: the Validation Set folder gives the brief's 24 finding rows, no extra row, and every
    score, with V7 as ERROR."""
    export(SCANS, tmp_path)
    findings = read_rows(tmp_path / "findings.csv")
    expected_findings = read_rows(VALIDATION / "expected_findings.csv")
    assert findings[0] == ["file", "ip", "port", "finding_code", "severity"]
    assert Counter(map(tuple, findings[1:])) == Counter(map(tuple, expected_findings[1:]))
    assert read_rows(tmp_path / "scores.csv") == read_rows(VALIDATION / "expected_scores.csv")


def test_files_have_the_exact_header_unix_line_endings_and_no_bom(tmp_path):
    export(SCANS, tmp_path)
    findings = (tmp_path / "findings.csv").read_bytes()
    assert findings.startswith(b"file,ip,port,finding_code,severity\n")
    assert (tmp_path / "scores.csv").read_bytes().startswith(b"file,network_score\nV1_home_basic.xml,90\n")
    for name in ("findings.csv", "scores.csv"):
        data = (tmp_path / name).read_bytes()
        assert b"\r" not in data and data.endswith(b"\n"), name


def test_unknown_device_has_an_empty_port_and_severities_are_lowercase(tmp_path):
    export(SCANS, tmp_path)
    text = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "V4_legacy.xml,192.168.1.99,,UNKNOWN_DEVICE,low\n" in text
    assert {row[4] for row in read_rows(tmp_path / "findings.csv")[1:]} <= {"high", "medium", "low", "info"}


def test_same_folder_gives_the_same_bytes_every_time(tmp_path):
    """Live check 1: the jury's re-run must match our upload."""
    export(SCANS, tmp_path / "first")
    export(SCANS, tmp_path / "second")
    for name in ("findings.csv", "scores.csv"):
        assert (tmp_path / "first" / name).read_bytes() == (tmp_path / "second" / name).read_bytes(), name


def test_broken_file_gets_an_error_row_and_the_export_goes_on(tmp_path):
    """The broken file sorts first here, so every file after it proves the export went on."""
    folder = folder_with(tmp_path, {"A_broken.xml": V7_BROKEN, "B_home.xml": V1})
    export(folder, tmp_path / "out")
    assert scores(tmp_path / "out") == [["A_broken.xml", "ERROR"], ["B_home.xml", "90"]]
    assert read_rows(tmp_path / "out" / "findings.csv")[1:] == [
        ["B_home.xml", "192.168.1.1", "80", "HTTP_ADMIN_CLEARTEXT", "medium"]
    ]


def test_every_extension_counts_so_a_broken_txt_file_gets_its_error_row(tmp_path):
    folder = folder_with(tmp_path, {"T1.xml": V1, "T9_broken.txt": V7_BROKEN, "T2.scan": V1})
    export(folder, tmp_path / "out")
    assert scores(tmp_path / "out") == [["T1.xml", "90"], ["T2.scan", "90"], ["T9_broken.txt", "ERROR"]]


def test_hidden_files_and_subfolders_are_not_scan_files(tmp_path):
    folder = folder_with(tmp_path, {"T1.xml": V1, ".DS_Store": V7_BROKEN, ".gitkeep": V7_BROKEN})
    (folder / "old").mkdir()
    shutil.copyfile(V7_BROKEN, folder / "old" / "T0.xml")
    export(folder, tmp_path / "out")
    assert scores(tmp_path / "out") == [["T1.xml", "90"]]


def test_files_are_sorted_by_name(tmp_path):
    folder = folder_with(tmp_path, {"b.xml": V1, "a.xml": V1, "C.xml": V1})
    assert [path.name for path in scan_files(folder)] == ["C.xml", "a.xml", "b.xml"]


def test_a_crash_in_the_analysis_becomes_an_error_row(tmp_path, monkeypatch):
    """analyse_file promises never to raise; if a Test Set trap ever made it, the upload must still be written."""
    real_analyse_file = export_module.analyse_file

    def crashes_on_trap(path):
        if path.name == "T1_trap.xml":
            raise RecursionError("maximum recursion depth exceeded")
        return real_analyse_file(path)

    monkeypatch.setattr(export_module, "analyse_file", crashes_on_trap)
    folder = folder_with(tmp_path, {"T1_trap.xml": V1, "T2.xml": V1})
    results = export_results(folder, tmp_path / "out")
    assert scores(tmp_path / "out") == [["T1_trap.xml", "ERROR"], ["T2.xml", "90"]]
    assert "T1_trap.xml" in results[0].error and "maximum recursion depth" in results[0].error


def test_empty_folder_gives_the_headers_only(tmp_path):
    folder = folder_with(tmp_path, {})
    export(folder, tmp_path / "out")
    assert (tmp_path / "out" / "findings.csv").read_bytes() == b"file,ip,port,finding_code,severity\n"
    assert (tmp_path / "out" / "scores.csv").read_bytes() == b"file,network_score\n"


def test_output_folder_is_created(tmp_path):
    export(SCANS, tmp_path / "results" / "test-set")
    assert (tmp_path / "results" / "test-set" / "scores.csv").is_file()


def test_missing_folder_is_an_export_error(tmp_path):
    with pytest.raises(ExportError, match="doesn't exist"):
        export(tmp_path / "no-such-folder", tmp_path / "out")


def test_writing_into_the_scan_folder_is_refused(tmp_path):
    """Otherwise the next run would read our two CSVs as broken scans: two extra ERROR rows in an upload."""
    folder = folder_with(tmp_path, {"T1.xml": V1})
    with pytest.raises(ExportError, match="another folder"):
        export(folder, folder)
    assert sorted(path.name for path in folder.iterdir()) == ["T1.xml"]


def test_unwritable_output_is_an_export_error(tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a folder", encoding="utf-8")
    with pytest.raises(ExportError, match="Can't write"):
        export(SCANS, blocker)
