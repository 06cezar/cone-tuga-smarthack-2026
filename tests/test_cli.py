"""The command line: `python -m conetuga analyse <folder> --out <dir>` (FR-15, the brief's "CLI first").

Every test writes into tmp_path only, never into tests/fixtures/, even when the code under test is broken."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import conetuga.__main__ as cli
from conetuga.analysis import FileResult

ROOT = Path(__file__).resolve().parent.parent
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"


def test_analyse_writes_both_files_and_says_what_happened_to_each(tmp_path, capsys):
    assert cli.main(["analyse", str(SCANS), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "findings.csv").is_file() and (tmp_path / "scores.csv").is_file()
    output = capsys.readouterr().out
    assert "V1_home_basic.xml: scor 90, 1 problemă / score 90, 1 finding" in output
    assert "V2_smart_home.xml: scor 40, 5 probleme / score 40, 5 findings" in output
    assert "V7_broken.xml: EROARE / ERROR: V7_broken.xml: the file is not complete" in output
    assert "(24 de rânduri / 24 rows)" in output and "(8 rânduri / 8 rows)" in output


def test_romanian_counts_follow_romanian_grammar():
    """A's note on scan_01: "1 rânduri" isn't Romanian. From 20 up, "de" comes in, except after 01 to 19."""
    counts = {count: cli._ro_count(count, "rând", "rânduri") for count in [0, 1, 2, 19, 20, 24, 100, 101, 119, 120]}
    assert counts == {0: "0 rânduri", 1: "1 rând", 2: "2 rânduri", 19: "19 rânduri", 20: "20 de rânduri",
                      24: "24 de rânduri", 100: "100 de rânduri", 101: "101 rânduri", 119: "119 rânduri",
                      120: "120 de rânduri"}
    assert [cli._en_count(count, "row") for count in (0, 1, 2)] == ["0 rows", "1 row", "2 rows"]


def test_python_m_conetuga_runs_end_to_end(tmp_path):
    """The exact command we run at hour 20 on the Test Set, in a fresh process, its output read as UTF-8."""
    completed = subprocess.run([sys.executable, "-m", "conetuga", "analyse", str(SCANS), "--out", str(tmp_path)],
                               cwd=ROOT, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert "rânduri" in completed.stdout.decode("utf-8")
    assert (tmp_path / "scores.csv").read_text(encoding="utf-8").endswith("V7_broken.xml,ERROR\n")


def test_missing_folder_exits_with_a_clear_message_in_both_languages(tmp_path, capsys):
    assert cli.main(["analyse", str(tmp_path / "no-such-folder"), "--out", str(tmp_path / "out")]) == cli.EXIT_ERROR
    romanian, english = capsys.readouterr().err.strip().split("\n")
    assert "nu există" in romanian and "doesn't exist" in english
    assert not (tmp_path / "out").exists()


def test_refuses_to_write_into_the_scan_folder(tmp_path, capsys):
    """On a copy: if this refusal ever broke, the test must not write CSVs among the official fixtures."""
    folder = tmp_path / "scans"
    folder.mkdir()
    shutil.copyfile(SCANS / "V1_home_basic.xml", folder / "V1_home_basic.xml")
    assert cli.main(["analyse", str(folder), "--out", str(folder)]) == cli.EXIT_ERROR
    assert "another folder" in capsys.readouterr().err
    assert sorted(path.name for path in folder.iterdir()) == ["V1_home_basic.xml"]


def test_out_is_required(capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["analyse", str(SCANS)])
    assert stopped.value.code == 2 and "--out" in capsys.readouterr().err


def test_hostile_file_name_is_printed_escaped(tmp_path, capsys, monkeypatch):
    """A file name can hide a terminal escape sequence or a line break (NFR-03): neither reaches the terminal."""
    name = "T1\x1b[2J\nV9_fake.xml: scor 100.xml"
    broken = FileResult(file=name, hosts=[], findings=[], score=None, error=f"{name}: the file is empty")
    monkeypatch.setattr(cli, "export_results", lambda folder, out: [broken])
    assert cli.main(["analyse", str(tmp_path), "--out", str(tmp_path / "out")]) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output and "\\x1b" in output
    assert len(output.strip().split("\n")) == 2  # one line for the file, one for the summary
