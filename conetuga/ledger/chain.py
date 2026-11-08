"""The blockchain side of the findings log: it stores and reads batch hashes in the FindingsLedger contract
(contracts/src/FindingsLedger.sol) through Foundry's command-line tools, `cast` and `forge`, so no Python package is
needed; the chain is a local Anvil or a testnet such as Sepolia.

The settings come only from environment variables, never from the log's database: whoever can edit the database must
not be able to point the check at a contract of their own. The private key stays in the environment (NFR-01): it is
needed to deploy and to anchor, not to verify, and it is removed from every message the tools print."""
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ENV_RPC_URL = "CONETUGA_CHAIN_RPC_URL"  # e.g. http://127.0.0.1:8545 for a local Anvil, or a Sepolia RPC URL
ENV_CONTRACT = "CONETUGA_CHAIN_CONTRACT"  # the address `python -m conetuga ledger deploy` printed
ENV_PRIVATE_KEY = "CONETUGA_CHAIN_PRIVATE_KEY"  # the deployer's key: an Anvil account, or a testnet-only key
CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts"
CONTRACT_ID = "src/FindingsLedger.sol:FindingsLedger"
CALL_TIMEOUT_SECONDS = 30  # a read is one RPC request
SEND_TIMEOUT_SECONDS = 120  # cast waits for the receipt; a Sepolia block comes about every 12 s
DEPLOY_TIMEOUT_SECONDS = 300  # the first build may also fetch the pinned compiler
RPC_URL = re.compile(r"^https?://\S+$")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
PRIVATE_KEY = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
DEPLOYED_TO = re.compile(r'"deployedTo"\s*:\s*"(0x[0-9a-fA-F]{40})"')  # in forge create --json's output
SUCCESS = ("0x1", "1", 1, True)  # how a receipt's "status" says the transaction went through


@dataclass(frozen=True)
class ChainSettings:
    rpc_url: str
    contract: str  # "" before the contract is deployed
    private_key: str  # "" when only checking the log


class LedgerError(Exception):
    """The chain can't be used now. The message is one Romanian line, then one English line, with no key in it."""


def settings_from_env(values: Mapping[str, str] | None = None) -> ChainSettings | None:
    """The chain settings from `values` (default: this process's environment), or None when no RPC URL is set: the
    log is then kept on this computer only."""
    values = os.environ if values is None else values
    rpc_url = values.get(ENV_RPC_URL, "").strip()
    if not rpc_url:
        return None
    return ChainSettings(rpc_url=rpc_url, contract=values.get(ENV_CONTRACT, "").strip(),
                         private_key=values.get(ENV_PRIVATE_KEY, "").strip())


def deploy(settings: ChainSettings) -> str:
    """Build and deploy a new FindingsLedger with the settings' key, and return its address."""
    _check(settings, need_contract=False, need_key=True)
    output = _run([_tool("forge"), "create", CONTRACT_ID, "--root", str(CONTRACT_ROOT), "--rpc-url", settings.rpc_url,
                   "--private-key", settings.private_key, "--broadcast", "--json"],
                  settings, DEPLOY_TIMEOUT_SECONDS)
    # forge prints its JSON over several lines, sometimes after build messages: look for the field itself.
    found = DEPLOYED_TO.findall(output)
    if found:
        return found[-1]
    raise LedgerError("forge nu a spus adresa contractului.\nforge didn't print the contract's address.")


def chain_count(settings: ChainSettings) -> int:
    """How many batch hashes the contract holds."""
    _check(settings, need_contract=True, need_key=False)
    output = _run([_tool("cast"), "call", settings.contract, "count()(uint256)", "--rpc-url", settings.rpc_url],
                  settings, CALL_TIMEOUT_SECONDS)
    try:
        return int(output.split()[0])
    except (ValueError, IndexError) as exc:
        raise LedgerError(f"Răspuns neașteptat de la contract: {output[:80]!r}.\n"
                          f"Unexpected answer from the contract: {output[:80]!r}.") from exc


def chain_hash(settings: ChainSettings, batch: int) -> str:
    """The hash the contract holds for `batch`, as "0x" + 64 lowercase hex digits."""
    _check(settings, need_contract=True, need_key=False)
    output = _run([_tool("cast"), "call", settings.contract, "batchHash(uint256)(bytes32)", str(batch),
                   "--rpc-url", settings.rpc_url], settings, CALL_TIMEOUT_SECONDS)
    value = (output.split() or [""])[0].lower()
    if not BYTES32.match(value):
        raise LedgerError(f"Răspuns neașteptat de la contract: {output[:80]!r}.\n"
                          f"Unexpected answer from the contract: {output[:80]!r}.")
    return value


def send_anchor(settings: ChainSettings, batch: int, batch_hash: str) -> str:
    """Store `batch_hash` as batch number `batch` and return the transaction's hash once it is in a block."""
    _check(settings, need_contract=True, need_key=True)
    if not BYTES32.match(batch_hash):
        raise ValueError(f"not a bytes32 hash: {batch_hash!r}")
    output = _run([_tool("cast"), "send", settings.contract, "anchor(uint256,bytes32)", str(batch), batch_hash,
                   "--rpc-url", settings.rpc_url, "--private-key", settings.private_key, "--json"],
                  settings, SEND_TIMEOUT_SECONDS)
    try:
        receipt = json.loads(output)
    except ValueError as exc:
        raise LedgerError("cast nu a dat chitanța tranzacției.\ncast didn't give the transaction's receipt.") from exc
    if receipt.get("status") not in SUCCESS:
        raise LedgerError(f"Tranzacția pentru lotul {batch} a fost respinsă.\n"
                          f"The transaction for batch {batch} was rejected.")
    return str(receipt.get("transactionHash", ""))


def _check(settings: ChainSettings, need_contract: bool, need_key: bool) -> None:
    """Every value reaches the tools as an argument of its own, never through a shell; checking its shape also keeps
    a value such as "--help" from being read as an option."""
    if not RPC_URL.match(settings.rpc_url):
        raise LedgerError(f"{ENV_RPC_URL} trebuie să fie o adresă http:// sau https://.\n"
                          f"{ENV_RPC_URL} must be an http:// or https:// URL.")
    if need_contract and not ADDRESS.match(settings.contract):
        raise LedgerError(f"Setează {ENV_CONTRACT} la adresa contractului (0x și 40 de cifre hexa).\n"
                          f"Set {ENV_CONTRACT} to the contract's address (0x and 40 hex digits).")
    if need_key and not PRIVATE_KEY.match(settings.private_key):
        raise LedgerError(f"Setează {ENV_PRIVATE_KEY} la cheia privată (64 de cifre hexa).\n"
                          f"Set {ENV_PRIVATE_KEY} to the private key (64 hex digits).")


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise LedgerError(f"Lipsește {name} (Foundry): instalează-l cu foundryup.\n"
                          f"{name} (Foundry) is missing: install it with foundryup.")
    return path


def _run(command: list[str], settings: ChainSettings, timeout: int) -> str:
    """What the tool prints. A failure becomes LedgerError with the tool's own last words, the key removed: never the
    command line, which holds the key."""
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LedgerError(f"Blockchain-ul nu a răspuns în {timeout} s.\n"
                          f"The chain didn't answer within {timeout} s.") from exc
    except OSError as exc:
        raise LedgerError(f"Comanda {Path(command[0]).name} nu a pornit ({exc.strerror}).\n"
                          f"The command {Path(command[0]).name} didn't start ({exc.strerror}).") from exc
    output = completed.stdout.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        detail = _redact(completed.stderr.decode("utf-8", errors="replace").strip() or output, settings)
        last = detail.splitlines()[-1][:200] if detail else str(completed.returncode)
        raise LedgerError(f"{Path(command[0]).name} a eșuat: {last}\n{Path(command[0]).name} failed: {last}")
    return _redact(output, settings)


def _redact(text: str, settings: ChainSettings) -> str:
    """Removes the private key, in any case and with or without "0x", and the RPC URL, which for a hosted node such as
    Infura or Alchemy holds an API key."""
    bare = settings.private_key.removeprefix("0x")
    for form in sorted({bare, bare.lower(), bare.upper()} - {""}, key=len, reverse=True):
        text = re.sub(re.escape(form), "***", text, flags=re.IGNORECASE)
    if settings.rpc_url:
        text = text.replace(settings.rpc_url, "<RPC>")
    return text
