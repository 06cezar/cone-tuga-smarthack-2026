"""The command line, built first as the brief asks.

- `python -m conetuga analyse <folder> --out <dir>` writes the standard findings.csv and scores.csv for a whole folder
  (FR-15) and says, file by file, what happened. No network, no administrator rights.
- `python -m conetuga scan [target] --confirm` runs a live scan of our hotspot (FR-04), only when the guardrail allows
  it (FR-02), then shows the same analysis. Only nmap gets administrator rights.
- Both log every finding they detect in the findings log (conetuga/ledger); `python -m conetuga ledger deploy | anchor
  | verify` puts its hashes on a blockchain and checks the log against them."""
import argparse
import io
import os
import sqlite3
import sys
from pathlib import Path

from conetuga import ledger
from conetuga.analysis import analyse_file
from conetuga.guard.export import FINDINGS_FILE, SCORES_FILE, ExportError, export_results, scan_files
from conetuga.guard.network import NetworkNotFound
from conetuga.guard.scan import DEFAULT_MINUTES, DEFAULT_OUT, MIN_MINUTES, ScanError, ScanRefused, live_scan
from conetuga.history import save_scan

EXIT_OK = 0
EXIT_ERROR = 2  # the command couldn't run; argparse uses the same code for a wrong command
EXIT_REFUSED = 3  # the guardrail refused the scan: nmap never started
EXIT_PARTIAL = 4  # the scan finished, but nmap gave up on some devices: their findings are missing
EXIT_TAMPERED = 5  # ledger verify: the log no longer matches the hashes on the chain
LEDGER_ACTIONS = ("deploy", "anchor", "verify")
MISSING_IDS_SHOWN = 10  # deleted row numbers listed by ledger verify; the count says how many there are in all
RETRY_FACTOR = 2  # a device that ran out of time gets this many times as long on the next try
FOLDERS_SHOWN = 3  # subfolders named when the scans sit deeper than the folder given; one is the usual case
ENV_FILE = Path(__file__).resolve().parents[1] / ".env"  # gitignored: where a person keeps settings and secrets
ENV_FILE_VARIABLE = "CONETUGA_ENV_FILE"  # another file than ENV_FILE (the tests point it at a file that isn't there)
ENV_PREFIX = "CONETUGA_"  # the only names read from the file


def main(argv: list[str] | None = None) -> int:
    _write_utf8()
    _load_env_file()
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
    log = commands.add_parser(
        "ledger",
        help="jurnalul de constatări pe blockchain: deploy, anchor, verify / the findings log on a blockchain",
    )
    log.add_argument("action", choices=LEDGER_ACTIONS,
                     help="deploy: un contract nou; anchor: trimite loturile pline; verify: compară jurnalul cu "
                          "blockchain-ul / deploy: a new contract; anchor: send the full batches; verify: compare the "
                          "log with the chain")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.target, args.confirm, args.out, args.minutes)
    if args.command == "ledger":
        return _ledger(args.action)
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
    _log_findings(results, "analyse")
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
    # FR-10, every scan in the history: the stored result has masked MACs only, and it stays on this computer. A
    # history that can't be written (a full disk, no permission) is only a warning: the scan's result and the
    # warnings about devices nmap gave up on still follow.
    try:
        saved = save_scan(result, scan.xml.read_bytes())
    except OSError as exc:
        saved = False
        _print_message(f"Scanarea nu a putut fi salvată în istoric ({exc.strerror or exc}); rezultatul de mai sus "
                       "rămâne valabil.\n"
                       f"The scan couldn't be saved to the history ({exc.strerror or exc}); the result above still "
                       "stands.")
    if saved:
        print("Salvat în istoric (deschide UI-ul să vezi înainte/după) / saved to the history (open the UI for before/after)")
    _log_findings([result], "scan")
    if not scan.timed_out:
        return EXIT_OK
    for device in scan.timed_out:
        _print_message(
            f"ATENȚIE: {device} nu a terminat în {scan.minutes} minute, deci rezultatele lui lipsesc: „nicio problemă” "
            f"nu e adevărat pentru el. Rulează din nou cu --minutes {scan.minutes * RETRY_FACTOR}.\n"
            f"WARNING: {device} didn't finish within {scan.minutes} minutes, so its results are missing: \"no "
            f"findings\" isn't true for it. Run again with --minutes {scan.minutes * RETRY_FACTOR}.")
    return EXIT_PARTIAL


def _log_findings(results: list, command: str) -> None:
    """Every finding just detected goes into the findings log; when a chain is set up, the full batches go on it.
    The log never changes the command's results or its exit code: a failure here is only a warning."""
    try:
        ids = ledger.record_findings(results, command)
    except (OSError, sqlite3.Error) as exc:
        _print_message(f"Jurnalul de constatări nu a putut fi scris ({exc}).\n"
                       f"The findings log couldn't be written ({exc}).")
        return
    if not ids:
        return
    print(f"Jurnal: {_ro_count(len(ids), 'constatare salvată', 'constatări salvate')} (nr. {ids[0]}–{ids[-1]}) / "
          f"log: {_en_count(len(ids), 'finding')} saved (#{ids[0]}–{ids[-1]})")
    settings = ledger.settings_from_env()
    if settings is not None:
        _anchor(settings)


def _anchor(settings) -> bool:
    """Sends the full batches the chain doesn't hold yet; True unless the chain refused or couldn't be reached."""
    try:
        sent = ledger.anchor_pending(settings)
    except ledger.LedgerError as exc:
        _print_message(str(exc))
        return False
    if sent:
        first, last = sent[0][0], sent[-1][0]
        span = f"{first}" if first == last else f"{first}–{last}"
        print(f"Blockchain: am ancorat lotul/loturile {span}, ultima tranzacție {sent[-1][1]} / "
              f"anchored batch(es) {span}, last transaction {sent[-1][1]}")
    else:
        print("Blockchain: niciun lot plin nou de ancorat / no new full batch to anchor")
    return True


def _ledger(action: str) -> int:
    """ledger deploy: a new contract for this log; anchor: send the full batches; verify: compare the log with the
    chain (exit 5 when it no longer matches)."""
    settings = ledger.settings_from_env()
    if settings is None:
        _print_message(f"Setează {ledger.ENV_RPC_URL} (de ex. http://127.0.0.1:8545 pentru Anvil), "
                       f"{ledger.ENV_PRIVATE_KEY} și, după deploy, {ledger.ENV_CONTRACT}.\n"
                       f"Set {ledger.ENV_RPC_URL} (e.g. http://127.0.0.1:8545 for Anvil), "
                       f"{ledger.ENV_PRIVATE_KEY} and, after deploy, {ledger.ENV_CONTRACT}.")
        return EXIT_ERROR
    if action == "anchor":
        return EXIT_OK if _anchor(settings) else EXIT_ERROR
    try:
        if action == "deploy":
            address = ledger.deploy(settings)
            print(f"Contract: {address}")
            print(f"Setează / set: export {ledger.ENV_CONTRACT}={address}")
            return EXIT_OK
        report = ledger.check(settings)
    except ledger.LedgerError as exc:
        _print_message(str(exc))
        return EXIT_ERROR
    _print_check(report)
    return EXIT_TAMPERED if report.tampered else EXIT_OK


def _print_check(report) -> None:
    size = ledger.BATCH_SIZE
    print(f"Jurnal: {_ro_count(report.entries, 'rând', 'rânduri')}; pe blockchain: "
          f"{_ro_count(report.on_chain, 'lot', 'loturi')} / log: {_en_count(report.entries, 'row')}; on chain: "
          f"{_en_count(report.on_chain, 'batch', 'batches')}")
    if report.intact:
        print(f"✅ Loturile 0–{report.intact - 1} (rândurile 1–{report.intact * size}) sunt neschimbate / "
              f"batches 0–{report.intact - 1} (rows 1–{report.intact * size}) are unchanged")
    if report.first_changed is not None:
        batch = report.first_changed
        print(f"⛔ Lotul {batch} (rândurile {batch * size + 1}–{(batch + 1) * size}) a fost modificat; loturile de "
              f"după depind de el / batch {batch} (rows {batch * size + 1}–{(batch + 1) * size}) was changed; the "
              "batches after it depend on it")
    if report.chain_ahead:
        print(f"⛔ Blockchain-ul are {_ro_count(report.chain_ahead, 'lot', 'loturi')} pentru care jurnalul nu mai are "
              f"rândurile: rânduri șterse sau jurnal golit / the chain holds "
              f"{_en_count(report.chain_ahead, 'batch', 'batches')} the log no longer has the rows for: rows deleted "
              "or the log cleared")
    if report.missing_ids:
        shown = ", ".join(str(number) for number in report.missing_ids[:MISSING_IDS_SHOWN])
        more = "…" if len(report.missing_ids) > MISSING_IDS_SHOWN else ""
        print(f"⛔ Lipsesc rândurile {shown}{more} / rows {shown}{more} are missing")
    if report.unanchored:
        print(f"⏳ {_ro_count(report.unanchored, 'lot plin', 'loturi pline')} încă nu sunt pe blockchain: ledger "
              f"anchor / {_en_count(report.unanchored, 'full batch', 'full batches')} not on the chain yet: "
              "ledger anchor")
    if report.unprotected:
        print(f"⏳ Ultimele {report.unprotected} rânduri vor fi protejate când lotul lor ajunge la {size} / the last "
              f"{report.unprotected} rows are protected once their batch reaches {size}")


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


def _en_count(count: int, one: str, many: str = "") -> str:
    """A number with its noun, in English: "1 row", "8 rows"; `many` for a plural that isn't one + "s" ("batches")."""
    return f"{count} {one}" if count == 1 else f"{count} {many or one + 's'}"


def _print_message(message: str) -> None:
    """Our two-line messages (Romanian, then English) to stderr, each line made printable."""
    for line in message.split("\n"):
        print(_printable(line), file=sys.stderr)


def _printable(text: str) -> str:
    """File names, error messages and Wi-Fi names come from outside: hostile text (NFR-03). A control character,
    such as a terminal escape sequence or a line break hidden in a file name, is shown escaped ("\\x1b", "\\n")
    instead of being run by the terminal or faking a line of output."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _load_env_file() -> None:
    """Reads the CONETUGA_* settings in .env into the environment, so a person writes them once (the chain's RPC URL,
    key and contract) instead of exporting them in every terminal, on Linux and Windows alike. A variable already set
    wins; any other name in the file is ignored; no value is ever printed; no package is needed. Lines look like
    `NAME=value`, optionally after `export `, with the value optionally in quotes and an optional ` # comment`."""
    path = Path(os.environ.get(ENV_FILE_VARIABLE) or ENV_FILE)
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()  # -sig: Notepad starts the file with a BOM
    except OSError:
        return  # no .env: the environment alone decides
    for line in lines:
        name, separator, value = line.strip().removeprefix("export ").partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name.startswith(ENV_PREFIX) or name == ENV_FILE_VARIABLE:
            continue  # a blank line, a comment, or a name that isn't ours
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(name, value)


def _write_utf8() -> None:
    """Romanian needs "ș" and "ț", which Windows' cp1252 can't encode when the output goes to a file or a pipe: print
    would crash. UTF-8 can encode every character."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
