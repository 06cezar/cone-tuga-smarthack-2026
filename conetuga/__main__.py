"""The command line, built first as the brief asks.

- `python -m conetuga analyse <folder> --out <dir>` writes the standard findings.csv and scores.csv for a whole folder
  (FR-15) and says, file by file, what happened. No network, no administrator rights.
- `python -m conetuga scan [target] --confirm` runs a live scan of our hotspot (FR-04), only when the guardrail allows
  it (FR-02), then shows the same analysis. Only nmap gets administrator rights."""
import argparse
import io
import sys
from pathlib import Path

from conetuga.analysis import analyse_file
from conetuga.guard.export import FINDINGS_FILE, SCORES_FILE, ExportError, export_results, scan_files
from conetuga.guard.network import NetworkNotFound
from conetuga.guard.scan import DEFAULT_MINUTES, DEFAULT_OUT, MIN_MINUTES, ScanError, ScanRefused, live_scan
from conetuga.history import save_scan

EXIT_OK = 0
EXIT_ERROR = 2  # the command couldn't run; argparse uses the same code for a wrong command
EXIT_REFUSED = 3  # the guardrail refused the scan: nmap never started
EXIT_PARTIAL = 4  # the scan finished, but nmap gave up on some devices: their findings are missing
RETRY_FACTOR = 2  # a device that ran out of time gets this many times as long on the next try
FOLDERS_SHOWN = 3  # subfolders named when the scans sit deeper than the folder given; one is the usual case


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
    scan = commands.add_parser(
        "scan",
        help="scanare live a hotspotului nostru, doar cu --confirm / live scan of our hotspot, only with --confirm",
    )
    scan.add_argument("target", nargs="?", default=None,
                      help="un IP sau un interval; implicit subrețeaua la care suntem conectați / "
                           "an IP or a range; by default the subnet we are connected to")
    scan.add_argument("--confirm", action="store_true",
                      help="confirm că scanez rețeaua noastră acum / I confirm I am scanning our network now")
    scan.add_argument("--out", type=Path, default=DEFAULT_OUT,
                      help="folderul pentru fișierul nmap XML (implicit results/) / "
                           "the folder for nmap's XML file (default results/)")
    scan.add_argument("--minutes", type=_minutes, default=DEFAULT_MINUTES,
                      help=f"cât timp poate lucra nmap pe un dispozitiv, minimum {MIN_MINUTES} (implicit "
                           f"{DEFAULT_MINUTES}) / how long nmap may spend on one device, at least {MIN_MINUTES} "
                           f"(default {DEFAULT_MINUTES})")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.target, args.confirm, args.out, args.minutes)
    return _analyse(args.folder, args.out)


def _analyse(folder: Path, out: Path) -> int:
    """Runs the export, then prints one line per file: its score, or why it couldn't be read. A folder with no scan
    file is refused before anything is written: its CSVs would be empty, an empty upload at hour 21."""
    if folder.is_dir() and not scan_files(folder):
        _print_message(_no_scan_files_message(folder))
        return EXIT_ERROR
    try:
        results = export_results(folder, out)
    except ExportError as exc:
        _print_message(str(exc))
        return EXIT_ERROR
    for result in results:
        if result.error:
            print(f"{_printable(result.file)}: EROARE / ERROR: {_printable(result.error)}")
        else:
            found = len(result.findings)
            print(f"{_printable(result.file)}: scor {result.score}, {_ro_count(found, 'problemă', 'probleme')} / "
                  f"score {result.score}, {_en_count(found, 'finding')}")
    rows = sum(len(result.findings) for result in results if not result.error)
    files = len(results)
    print(f"Scris / written: {_printable(str(out / FINDINGS_FILE))} "
          f"({_ro_count(rows, 'rând', 'rânduri')} / {_en_count(rows, 'row')}), "
          f"{_printable(str(out / SCORES_FILE))} ({_ro_count(files, 'rând', 'rânduri')} / {_en_count(files, 'row')})")
    return EXIT_OK


def _minutes(text: str) -> int:
    """--minutes: a whole number of minutes, at least MIN_MINUTES; anything else stops before the scan."""
    try:
        minutes = int(text)
    except ValueError:
        minutes = 0
    if minutes < MIN_MINUTES:
        raise argparse.ArgumentTypeError(
            f"{text!r}: un număr întreg de minute, cel puțin {MIN_MINUTES} / "
            f"a whole number of minutes, at least {MIN_MINUTES}")
    return minutes


def _scan(target: str | None, confirmed: bool, out: Path, minutes: int = DEFAULT_MINUTES) -> int:
    """Runs the live scan (the guardrail first, always), then shows its analysis: score, devices, each finding,
    and every device nmap gave up on, since "no findings" isn't true for those."""
    # flush: nmap writes to the same terminal or log, and this line must come before its output and our refusals
    print("Verific rețeaua și limitele scanării... / Checking the network and the scan's limits...", flush=True)
    try:
        scan = live_scan(target, confirmed, out, minutes)
    except ScanRefused as exc:
        _print_message(str(exc))
        return EXIT_REFUSED
    except (NetworkNotFound, ScanError) as exc:
        _print_message(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _print_message("Scanarea a fost oprită.\nThe scan was stopped.")
        return EXIT_ERROR
    print(f"Scanat / scanned: {scan.scanned} prin / through {_printable(scan.network.interface)} "
          f"(Wi-Fi {_printable(repr(scan.ssid))}), fără scanner / without the scanner {scan.network.ip}")
    print(f"Fișier / file: {_printable(str(scan.xml))} (rămâne pe acest calculator: MAC-uri și nume reale / "
          f"stays on this computer: real MACs and names)")
    result = analyse_file(scan.xml)
    if result.error:
        print(f"EROARE / ERROR: {_printable(result.error)}", file=sys.stderr)
        return EXIT_ERROR
    devices, found = len(result.hosts), len(result.findings)
    print(f"scor {result.score}, {_ro_count(devices, 'dispozitiv', 'dispozitive')}, "
          f"{_ro_count(found, 'problemă', 'probleme')} / score {result.score}, {_en_count(devices, 'device')}, "
          f"{_en_count(found, 'finding')}")
    for finding in result.findings:
        where = finding.ip if finding.port is None else f"{finding.ip}:{finding.port}"
        print(f"  {_printable(where)} {finding.code} ({finding.severity})")
    # FR-10, every scan in the history: the stored result has masked MACs only, and it stays on this computer.
    if save_scan(result, scan.xml.read_bytes()):
        print("Salvat în istoric (deschide UI-ul să vezi înainte/după) / saved to the history (open the UI for before/after)")
    if not scan.timed_out:
        return EXIT_OK
    for device in scan.timed_out:
        _print_message(
            f"ATENȚIE: {device} nu a terminat în {scan.minutes} minute, deci rezultatele lui lipsesc: „nicio problemă” "
            f"nu e adevărat pentru el. Rulează din nou cu --minutes {scan.minutes * RETRY_FACTOR}.\n"
            f"WARNING: {device} didn't finish within {scan.minutes} minutes, so its results are missing: \"no "
            f"findings\" isn't true for it. Run again with --minutes {scan.minutes * RETRY_FACTOR}.")
    return EXIT_PARTIAL


def _no_scan_files_message(folder: Path) -> str:
    """Why the folder is refused, naming the subfolders that do hold scans: a zip often unpacks into
    TestSet/TestSet/, and the person then gave the outer folder."""
    deeper = _folders_with_scans(folder)
    if not deeper:
        return (f"Folderul {str(folder)!r} nu conține niciun fișier de scanare; nu am scris nimic.\n"
                f"The folder {str(folder)!r} holds no scan file; nothing was written.")
    shown = ", ".join(repr(str(path)) for path in deeper)
    return (f"Folderul {str(folder)!r} nu conține direct niciun fișier de scanare; scanările sunt în {shown}. "
            "Rulează din nou cu acel folder; nu am scris nimic.\n"
            f"The folder {str(folder)!r} holds no scan file itself; the scans are in {shown}. "
            "Run again with that folder; nothing was written.")


def _folders_with_scans(folder: Path) -> list[Path]:
    """Subfolders at any depth, hidden ones left out, that hold files `analyse` would read; the nearest first."""
    found = [path for path in folder.rglob("*")
             if path.is_dir() and not any(part.startswith(".") for part in path.relative_to(folder).parts)
             and scan_files(path)]
    return sorted(found, key=lambda path: (len(path.parts), str(path)))[:FOLDERS_SHOWN]


def _ro_count(count: int, one: str, many: str) -> str:
    """A number with its noun, in Romanian: "1 rând", "8 rânduri", "24 de rânduri". From 20 up, "de" comes in,
    except when the last two digits are 01 to 19 ("101 rânduri")."""
    if count == 1:
        return f"1 {one}"
    if count >= 20 and (count % 100 == 0 or count % 100 >= 20):
        return f"{count} de {many}"
    return f"{count} {many}"


def _en_count(count: int, one: str) -> str:
    return f"{count} {one}" if count == 1 else f"{count} {one}s"


def _print_message(message: str) -> None:
    """Our two-line messages (Romanian, then English) to stderr, each line made printable."""
    for line in message.split("\n"):
        print(_printable(line), file=sys.stderr)


def _printable(text: str) -> str:
    """File names, error messages and Wi-Fi names come from outside: hostile text (NFR-03). A control character,
    such as a terminal escape sequence or a line break hidden in a file name, is shown escaped ("\\x1b", "\\n")
    instead of being run by the terminal or faking a line of output."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _write_utf8() -> None:
    """Romanian needs "ș" and "ț", which Windows' cp1252 can't encode when the output goes to a file or a pipe: print
    would crash. UTF-8 can encode every character."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
