"""The scan history, kept only on this computer (NFR-02): one JSON record per analysed scan in `.history/`
(gitignored), with MACs already masked by analyse_file. "Delete my history" removes the folder in one action.

A record is keyed by the SHA-256 of the scan file's bytes, so the same file analysed twice is stored once."""
import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from conetuga.analysis import FileResult, Finding, Host, Port

# Where the history lives: `.history/` at the repo root, or the folder in this environment variable (the tests use a
# temporary one, so they never touch a real history).
HISTORY_ENV = "CONETUGA_HISTORY_DIR"
DEFAULT_HISTORY_DIR = Path(__file__).resolve().parents[2] / ".history"
RECORD_SUFFIX = ".json"
DIGEST_CHARS_IN_NAME = 16  # enough to tell scans apart; the full digest is inside the record


@dataclass(frozen=True)
class Record:
    saved_at: str  # local time, ISO 8601 to the second
    file: str
    digest: str  # SHA-256 of the scan file's bytes
    result: FileResult


def history_dir() -> Path:
    return Path(os.environ.get(HISTORY_ENV) or DEFAULT_HISTORY_DIR)


def save_scan(result: FileResult, content: bytes, now: datetime | None = None) -> bool:
    """Store one analysed scan. Returns False, and stores nothing, when the result has an error or this exact file
    content is already in the history."""
    if result.error or result.score is None:
        return False
    digest = hashlib.sha256(content).hexdigest()
    path = history_dir() / f"{digest[:DIGEST_CHARS_IN_NAME]}{RECORD_SUFFIX}"
    if path.exists():
        return False
    saved_at = (now or datetime.now()).isoformat(timespec="seconds")
    record = {"saved_at": saved_at, "file": result.file, "digest": digest, "result": asdict(result)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    return True


def load_history() -> list[Record]:
    """Every stored scan, oldest first. A record that can't be read is skipped, never a crash."""
    folder = history_dir()
    if not folder.is_dir():
        return []
    records = []
    for path in folder.glob(f"*{RECORD_SUFFIX}"):
        try:
            records.append(_record(json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(records, key=lambda r: (r.saved_at, r.file))


def find_record(digest: str) -> Record | None:
    return next((r for r in load_history() if r.digest == digest), None)


def digest_of(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def delete_history() -> None:
    """Remove the whole history folder, with nothing left behind."""
    shutil.rmtree(history_dir(), ignore_errors=True)


def _record(data: dict) -> Record:
    result = data["result"]
    hosts = [Host(**{**h, "ports": [Port(**p) for p in h["ports"]]}) for h in result["hosts"]]
    findings = [Finding(**f) for f in result["findings"]]
    file_result = FileResult(file=result["file"], hosts=hosts, findings=findings, score=result["score"],
                             error=result["error"])
    return Record(saved_at=data["saved_at"], file=data["file"], digest=data["digest"], result=file_result)
