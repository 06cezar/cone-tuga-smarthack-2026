"""The standard export (FR-15): findings.csv and scores.csv for a whole folder of scan files, in one command.

These two files are what we upload at hour 21, and the jury compares every cell with its answer key, then re-runs
one file live (check 1). So they hold exactly the brief's columns and values (page 8), with nothing added, and the
same folder always gives the same bytes, on Windows and on Linux (NFR-05)."""
import csv
from pathlib import Path

from conetuga.analysis import FileResult, analyse_file

FINDINGS_FILE = "findings.csv"
SCORES_FILE = "scores.csv"
FINDINGS_HEADER = ["file", "ip", "port", "finding_code", "severity"]  # brief, page 8
SCORES_HEADER = ["file", "network_score"]  # brief, page 8
ERROR_SCORE = "ERROR"  # the score of a file that can't be read (brief, page 8)
HIDDEN_PREFIX = "."  # ".DS_Store", ".gitkeep": hidden files are not scan files (contract "export")
LINE_END = "\n"  # the same bytes on both systems: Windows would otherwise write "\r\n"


class ExportError(Exception):
    """The export can't run at all (missing folder, unwritable output). The message is one Romanian line, then the
    same in English. A single unreadable scan file is never an ExportError: it gets its ERROR row."""


def export(folder: Path, out: Path) -> None:
    """The contract call (specs/contracts.md, "export"): writes out/findings.csv and out/scores.csv for `folder`."""
    export_results(folder, out)


def export_results(folder: Path, out: Path) -> list[FileResult]:
    """`export`, also returning each file's result, so the command line can say which files had an error."""
    folder, out = Path(folder), Path(out)
    if not folder.is_dir():
        raise ExportError(
            f"Folderul {str(folder)!r} nu există sau nu este un folder.\n"
            f"The folder {str(folder)!r} doesn't exist or isn't a folder."
        )
    if out.resolve() == folder.resolve():
        # The CSVs would land among the scans, and the next run would read them as two broken scan files: two extra
        # ERROR rows in an upload.
        raise ExportError(
            "Scrie rezultatele în alt folder decât cel cu scanările (de ex. --out results/).\n"
            "Write the results to another folder than the scans' one (e.g. --out results/)."
        )
    results = [_analyse(path) for path in scan_files(folder)]
    _write_csvs(results, out)
    return results


def scan_files(folder: Path) -> list[Path]:
    """The files that count (contract "export"): every file in the folder except hidden ones, whatever the extension,
    so a broken file named ".txt" still gets its ERROR row; sorted by name, so every run writes the same order.
    Subfolders are not read."""
    files = [path for path in folder.iterdir() if path.is_file() and not path.name.startswith(HIDDEN_PREFIX)]
    return sorted(files, key=lambda path: path.name)


def _analyse(path: Path) -> FileResult:
    """analyse_file never raises (contract "analyse_file"). If a trap in the Test Set ever made it raise, that file
    still gets its ERROR row and the other files still run: the brief's "must not crash and must continue"."""
    try:
        return analyse_file(path)
    except Exception as exc:
        return FileResult(file=path.name, hosts=[], findings=[], score=None,
                          error=f"{path.name}: the analysis failed ({exc})")


def _write_csvs(results: list[FileResult], out: Path) -> None:
    """One findings row per finding, one scores row per file. A file in error gives no finding rows."""
    findings_rows = [
        [finding.file, finding.ip, "" if finding.port is None else finding.port, finding.code, finding.severity]
        for result in results if not result.error
        for finding in result.findings
    ]
    scores_rows = [
        [result.file, ERROR_SCORE if result.error or result.score is None else result.score] for result in results
    ]
    try:
        out.mkdir(parents=True, exist_ok=True)
        _write_csv(out / FINDINGS_FILE, FINDINGS_HEADER, findings_rows)
        _write_csv(out / SCORES_FILE, SCORES_HEADER, scores_rows)
    except OSError as exc:
        raise ExportError(
            f"Nu pot scrie rezultatele în {str(out)!r} ({exc.strerror or exc}).\n"
            f"Can't write the results to {str(out)!r} ({exc.strerror or exc})."
        ) from exc


def _write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file, lineterminator=LINE_END)
        writer.writerow(header)
        writer.writerows(rows)
