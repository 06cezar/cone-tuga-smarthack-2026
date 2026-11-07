"""The findings log (C): every finding the tool detects is a row in a local SQLite log, and every 10 rows one hash
goes on a blockchain, where nobody can change it. Checking the log recomputes the hashes from its rows and compares
them with the chain: a row changed, deleted, inserted or reordered in any anchored batch shows up.

store.py keeps the log and computes the hashes; chain.py talks to the FindingsLedger contract. This module joins
them: `anchor_pending` sends the full batches the chain doesn't hold yet, and `check` compares the log with the chain.
Only the command line calls it (conetuga/__main__.py)."""
from dataclasses import dataclass

from conetuga.ledger.chain import (ENV_CONTRACT, ENV_PRIVATE_KEY, ENV_RPC_URL, ChainSettings, LedgerError, chain_count,
                                   chain_hash, deploy, send_anchor, settings_from_env)
from conetuga.ledger.store import (BATCH_SIZE, Entry, batch_hashes, entries, ledger_path, missing_ids,
                                   record_findings, save_anchor)

__all__ = ["BATCH_SIZE", "ENV_CONTRACT", "ENV_PRIVATE_KEY", "ENV_RPC_URL", "ChainSettings", "Check", "Entry",
           "LedgerError", "anchor_pending", "check", "deploy", "entries", "ledger_path", "record_findings",
           "settings_from_env"]


@dataclass(frozen=True)
class Check:
    """The log compared with the chain."""

    entries: int  # rows in the log
    on_chain: int  # batch hashes the contract holds
    intact: int  # anchored batches whose rows still give the stored hash
    first_changed: int | None  # the first anchored batch that no longer matches (every later one follows it)
    chain_ahead: int  # batches the chain holds that the log no longer has the rows for (rows removed, or log cleared)
    missing_ids: list[int]  # row numbers absent from the log
    unanchored: int  # full batches not on the chain yet
    unprotected: int  # rows after the last full batch: protected once their batch is full

    @property
    def tampered(self) -> bool:
        return self.first_changed is not None or self.chain_ahead > 0 or bool(self.missing_ids)


def anchor_pending(settings: ChainSettings) -> list[tuple[int, str]]:
    """Sends every full batch the chain doesn't hold yet, oldest first, and returns (batch, transaction hash) for
    each. Refuses to send anything when the log no longer matches what the chain already holds: anchoring on top of a
    changed log would bless the change."""
    hashes = batch_hashes(entries())
    on_chain = chain_count(settings)
    if on_chain > len(hashes):
        raise LedgerError(
            f"Blockchain-ul are {on_chain} loturi, jurnalul doar {len(hashes)}: lipsesc rânduri sau jurnalul a fost "
            "șters. Rulează ledger verify; pentru un jurnal nou, fă un contract nou (ledger deploy).\n"
            f"The chain holds {on_chain} batches, the log only {len(hashes)}: rows are missing or the log was "
            "cleared. Run ledger verify; for a new log, deploy a new contract (ledger deploy).")
    # The hashes are chained, so the last anchored batch matching the chain proves every earlier one does too.
    if on_chain and chain_hash(settings, on_chain - 1) != hashes[on_chain - 1]:
        raise LedgerError(
            "Jurnalul nu mai corespunde cu ce e deja pe blockchain; nu am trimis nimic. Rulează ledger verify.\n"
            "The log no longer matches what the chain already holds; nothing was sent. Run ledger verify.")
    sent = []
    for batch in range(on_chain, len(hashes)):
        tx_hash = send_anchor(settings, batch, hashes[batch])
        save_anchor(batch, hashes[batch], tx_hash)
        sent.append((batch, tx_hash))
    return sent


def check(settings: ChainSettings) -> Check:
    """Recomputes every batch hash from the log's rows and compares each anchored one with the chain."""
    log = entries()
    hashes = batch_hashes(log)
    on_chain = chain_count(settings)
    compared = min(on_chain, len(hashes))
    first_changed = next((batch for batch in range(compared) if chain_hash(settings, batch) != hashes[batch]), None)
    return Check(
        entries=len(log),
        on_chain=on_chain,
        intact=compared if first_changed is None else first_changed,
        first_changed=first_changed,
        chain_ahead=max(0, on_chain - len(hashes)),
        missing_ids=missing_ids(log),
        unanchored=max(0, len(hashes) - on_chain),
        unprotected=len(log) % BATCH_SIZE,
    )
