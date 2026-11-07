"""The command line, built first as the brief asks: `python -m conetuga analyse <folder> --out <dir>`.

`analyse` writes the standard findings.csv and scores.csv for a whole folder (FR-15) and tells the user, file by
file, what happened. It needs no network and no administrator rights."""
import argparse
import io
import sys
from pathlib import Path

from conetuga.guard.export import FINDINGS_FILE, SCORES_FILE, ExportError, export_results

EXIT_OK = 0
EXIT_ERROR = 2  # the export couldn't run at all; argparse uses the same code for a wrong command


def main(argv: list[str] | None = None) -> int:
    _write_utf8()
    parser = argparse.ArgumentParser(
        prog="python -m conetuga",
        description="ConeTuga: verifică rețeaua ta și explică riscurile / checks your network and explains the risks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    analyse = commands.add_parser(
        "analyse",
        help="scrie findings.csv și scores.csv pentru un folder de scanări / "
             "writes findings.csv and scores.csv for a folder of scans",
    )
    analyse.add_argument("folder", type=Path, help="folderul cu scanări nmap XML / the folder of nmap XML scans")
    analyse.add_argument("--out", type=Path, required=True,
                         help="folderul pentru rezultate, de ex. results/ / the folder for the results, e.g. results/")
    args = parser.parse_args(argv)
    return _analyse(args.folder, args.out)


def _analyse(folder: Path, out: Path) -> int:
    """Runs the export, then prints one line per file: its score, or why it couldn't be read."""
    try:
        results = export_results(folder, out)
    except ExportError as exc:
        for line in str(exc).split("\n"):  # our message: one Romanian line, then one English line
            print(_printable(line), file=sys.stderr)
        return EXIT_ERROR
    for result in results:
        if result.error:
            print(f"{_printable(result.file)}: EROARE / ERROR: {_printable(result.error)}")
        else:
            print(f"{_printable(result.file)}: scor / score {result.score}, "
                  f"{len(result.findings)} probleme / findings")
    findings = sum(len(result.findings) for result in results if not result.error)
    print(f"Scris / written: {_printable(str(out / FINDINGS_FILE))} ({findings} rânduri / rows), "
          f"{_printable(str(out / SCORES_FILE))} ({len(results)} rânduri / rows)")
    return EXIT_OK


def _printable(text: str) -> str:
    """File names and error messages come from the scan folder: hostile text (NFR-03). A control character, such as
    a terminal escape sequence or a line break hidden in a file name, is shown escaped ("\\x1b", "\\n") instead of
    being run by the terminal or faking a line of output."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _write_utf8() -> None:
    """Romanian needs "ș" and "ț", which Windows' cp1252 can't encode when the output goes to a file or a pipe: print
    would crash. UTF-8 can encode every character."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
