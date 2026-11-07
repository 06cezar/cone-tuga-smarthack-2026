"""The local, opt-in statistics behind "Cele mai comune probleme" (FE-A2; contract "insights" in specs/contracts.md).

On disk, and only this: a count per catalog code and the opt-in flag, in one SQLite file inside the history folder,
so "Șterge istoricul meu" (`delete_history()`, which removes that folder) deletes it too. No scan identifier, IP,
MAC, hostname, vendor, port, title or file name is ever written (NFR-02): the caller keeps the scans it already
counted in its own session memory (`seen`).

Reading never creates the folder or the file (the file is opened read-only). A store that can't be read or written
is never overwritten and nothing here raises: the calls answer on the safe side (off, nothing saved, no counts), so
the page can say "statistics unavailable" instead of crashing."""
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path

from conetuga.analysis import FileResult
from conetuga.analysis.catalog import load_catalog
from conetuga.history.store import history_dir

STORE_NAME = "insights.sqlite3"  # inside history_dir(), so delete_history() removes it with the rest
STATUS_OFF = "off"
STATUS_ON = "on"
STATUS_UNAVAILABLE = "unavailable"
ENABLED_KEY = "enabled"
ENABLED_YES = "1"
ENABLED_NO = "0"
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS counts (code TEXT PRIMARY KEY, count INTEGER NOT NULL)",
)
# Everything that can go wrong with a store file: SQLite's errors (not a database, locked, read-only, disk full) and
# the operating system's (no permission, a file where the folder should be).
STORE_ERRORS = (sqlite3.Error, OSError)


def store_path() -> Path:
    return history_dir() / STORE_NAME


def status() -> str:
    """STATUS_OFF (no store yet, or statistics turned off), STATUS_ON, or STATUS_UNAVAILABLE (a store file exists but
    can't be read). Never creates anything and never raises. It says how the store is now, not whether the next write
    will succeed: `set_enabled` and `record` report that themselves."""
    path = store_path()
    if not path.exists():
        return STATUS_OFF
    try:
        with closing(_open_for_reading(path)) as connection:
            row = connection.execute("SELECT value FROM settings WHERE key = ?", (ENABLED_KEY,)).fetchone()
    except STORE_ERRORS:
        return STATUS_UNAVAILABLE
    return STATUS_ON if row and row[0] == ENABLED_YES else STATUS_OFF


def is_enabled() -> bool:
    """True only when the person turned statistics on and the store can be read (off is the safe side)."""
    return status() == STATUS_ON


def set_enabled(on: bool) -> bool:
    """Save the person's choice. True when it was saved; False when the store can't be written (nothing changes)."""
    try:
        with closing(_open_for_writing()) as connection, connection:
            connection.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
                               "value = excluded.value", (ENABLED_KEY, ENABLED_YES if on else ENABLED_NO))
    except STORE_ERRORS:
        return False
    return True


def record(result: FileResult, scan_id: str, seen: set[str]) -> bool:
    """Add this scan's findings to the counts, once per `scan_id` within the caller's session set `seen`. True when it
    counted (and `scan_id` is then added to `seen`); False, with nothing stored, when statistics are off, the result
    has an error, `scan_id` is already in `seen`, or the store can't be written. After a failed write `scan_id` stays
    out of `seen`, so the same scan can be counted when the store works again."""
    if scan_id in seen or result.error or result.score is None or not is_enabled():
        return False
    catalog_codes = {rule.code for rule in load_catalog().rules}
    counts = Counter(finding.code for finding in result.findings if finding.code in catalog_codes)
    try:
        with closing(_open_for_writing()) as connection, connection:
            connection.executemany("INSERT INTO counts (code, count) VALUES (?, ?) ON CONFLICT(code) DO UPDATE SET "
                                   "count = count + excluded.count", sorted(counts.items()))
    except STORE_ERRORS:
        return False
    seen.add(scan_id)
    return True


def top_codes(n: int) -> list[tuple[str, int]]:
    """The `n` catalog codes found most often, as (code, number of findings), most first, ties by code; [] when there
    is no store or it can't be read. Raises ValueError for n < 1."""
    if n < 1:
        raise ValueError(f"top_codes needs n >= 1, got {n}")
    path = store_path()
    if not path.exists():
        return []
    try:
        with closing(_open_for_reading(path)) as connection:
            rows = connection.execute("SELECT code, count FROM counts WHERE count > 0 ORDER BY count DESC, code ASC "
                                      "LIMIT ?", (n,)).fetchall()
    except STORE_ERRORS:
        return []
    return [(code, count) for code, count in rows]


def _open_for_reading(path: Path) -> sqlite3.Connection:
    """The store, read-only: SQLite's `mode=ro` never creates or changes the file."""
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def _open_for_writing() -> sqlite3.Connection:
    """The store, created with its two tables if it doesn't exist yet. A file that isn't a database makes SQLite raise
    at the first statement, so it is never overwritten."""
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        for statement in SCHEMA:
            connection.execute(statement)
    except sqlite3.Error:
        connection.close()
        raise
    return connection
