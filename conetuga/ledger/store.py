"""The findings log: one SQLite row per finding the tool detects, and the hashes that make the log tamper-evident.

Every BATCH_SIZE rows form a batch. A batch's hash covers its rows and the hash of the batch before it, so the hash of
the latest batch vouches for the whole log up to it. Those hashes go on a blockchain (chain.py), where they can't be
changed; checking the log means recomputing the hashes from the rows and comparing them with the chain.

The log lives in the history folder (history_dir(), gitignored), so "Șterge istoricul meu" deletes it with the rest
(NFR-02). A row holds what findings.csv holds, plus when and by which command it was found: no MAC and no hostname
(NFR-02). Rows are only ever added; nothing here updates or deletes one."""
import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from conetuga.analysis import FileResult
from conetuga.history.store import history_dir

LEDGER_NAME = "findings_ledger.sqlite3"  # inside history_dir(), so delete_history() removes it too
BATCH_SIZE = 10  # one on-chain hash per 10 log rows, to save gas (the team's choice)
GENESIS_HASH = bytes(32)  # "the batch before the first one": 32 zero bytes
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, logged_at TEXT NOT NULL, "
    "command TEXT NOT NULL, file TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER, proto TEXT NOT NULL, "
    "code TEXT NOT NULL, severity TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS anchors (batch INTEGER PRIMARY KEY, batch_hash TEXT NOT NULL, tx_hash TEXT NOT NULL, "
    "anchored_at TEXT NOT NULL)",
)


@dataclass(frozen=True)
class Entry:
    """One logged finding. `id` counts from 1 with no gaps: a missing number means a deleted row."""

    id: int
    logged_at: str  # local time, ISO 8601 to the second
    command: str  # "analyse" or "scan"
    file: str
    ip: str
    port: int | None  # None for UNKNOWN_DEVICE, as in findings.csv
    proto: str
    code: str
    severity: str


def ledger_path() -> Path:
    return history_dir() / LEDGER_NAME


def record_findings(results: list[FileResult], command: str, now: datetime | None = None) -> list[int]:
    """Add one row per finding of every readable result, in the order given. Returns the new rows' ids."""
    logged_at = (now or datetime.now()).isoformat(timespec="seconds")
    rows = [(logged_at, command, f.file, f.ip, f.port, f.proto, f.code, f.severity)
            for result in results if not result.error for f in result.findings]
    if not rows:
        return []
    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ids = []
    with closing(sqlite3.connect(path)) as connection, connection:
        _create(connection)
        for row in rows:
            cursor = connection.execute("INSERT INTO entries (logged_at, command, file, ip, port, proto, code, "
                                        "severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
            ids.append(cursor.lastrowid)
    return ids


def entries() -> list[Entry]:
    """Every row, by id; [] when there is no log yet."""
    path = ledger_path()
    if not path.exists():
        return []
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        rows = connection.execute("SELECT id, logged_at, command, file, ip, port, proto, code, severity FROM entries "
                                  "ORDER BY id").fetchall()
    return [Entry(*row) for row in rows]


def entry_digest(entry: Entry) -> bytes:
    """SHA-256 of the row written as canonical JSON (sorted keys, no spaces, UTF-8): the same row always gives the
    same bytes, on any computer."""
    canonical = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def batch_hashes(log: list[Entry]) -> list[str]:
    """The hash of every full batch, as "0x" + 64 hex digits (Solidity's bytes32): SHA-256 of the previous batch's
    hash followed by the digests of the batch's rows in id order. A partial last batch has no hash yet."""
    hashes, previous = [], GENESIS_HASH
    for start in range(0, len(log) - len(log) % BATCH_SIZE, BATCH_SIZE):
        digest = hashlib.sha256(previous + b"".join(entry_digest(e) for e in log[start:start + BATCH_SIZE])).digest()
        hashes.append("0x" + digest.hex())
        previous = digest
    return hashes


def missing_ids(log: list[Entry]) -> list[int]:
    """Ids absent from 1..last: rows someone deleted (SQLite's AUTOINCREMENT never reuses an id)."""
    present = {entry.id for entry in log}
    return [number for number in range(1, max(present, default=0) + 1) if number not in present]


def save_anchor(batch: int, batch_hash: str, tx_hash: str, now: datetime | None = None) -> None:
    """Note where a batch went on the chain. Only a convenience: checking the log always asks the chain itself."""
    with closing(sqlite3.connect(ledger_path())) as connection, connection:
        _create(connection)
        connection.execute("INSERT OR REPLACE INTO anchors (batch, batch_hash, tx_hash, anchored_at) VALUES "
                           "(?, ?, ?, ?)", (batch, batch_hash, tx_hash,
                                            (now or datetime.now()).isoformat(timespec="seconds")))


def _create(connection: sqlite3.Connection) -> None:
    for statement in SCHEMA:
        connection.execute(statement)
