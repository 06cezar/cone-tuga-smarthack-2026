"""The findings log (conetuga/ledger): one SQLite row per detected finding, one chained hash per 10 rows on a
blockchain, and a check that finds any change to an anchored row.

No test touches a real chain: the contract is a FakeChain in memory, and `cast`/`forge` are replaced by a fake runner
that records the command lines. The Validation Set gives 24 findings: two full batches and 4 rows after them."""
import re
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

import conetuga.__main__ as cli
import conetuga.ledger as ledger
import conetuga.ledger.chain as chain
from conetuga.analysis import analyse_file
from conetuga.history import delete_history
from conetuga.ledger import ChainSettings, LedgerError, anchor_pending, check, entries, ledger_path, record_findings
from conetuga.ledger.store import batch_hashes, entry_digest, missing_ids

SCANS = Path(__file__).resolve().parent / "fixtures" / "validation" / "scans"
EXPECTED = Path(__file__).resolve().parent / "fixtures" / "validation" / "expected_findings.csv"
CONTRACT = "0x" + "c0" * 20
KEY = "0x" + "ab" * 32  # a made-up key: the format only
SETTINGS = ChainSettings(rpc_url="http://127.0.0.1:8545", contract=CONTRACT, private_key=KEY)
CHAIN_ENV = (chain.ENV_RPC_URL, chain.ENV_CONTRACT, chain.ENV_PRIVATE_KEY)
REAL_RUN = chain._run  # kept before the autouse fixture below replaces it


@pytest.fixture(autouse=True)
def no_real_chain(monkeypatch):
    """No test runs cast or forge (tests/conftest.py also removes any exported chain settings)."""
    def forbidden(command, settings, timeout):
        raise AssertionError(f"a test tried to run {command[0]}")

    monkeypatch.setattr(chain, "_run", forbidden)


class FakeChain:
    """The FindingsLedger contract in memory: write-once, in order, as the Solidity code enforces."""

    def __init__(self, monkeypatch):
        self.hashes: list[str] = []
        monkeypatch.setattr(ledger, "chain_count", lambda settings: len(self.hashes))
        monkeypatch.setattr(ledger, "chain_hash", lambda settings, batch: self.hashes[batch])
        monkeypatch.setattr(ledger, "send_anchor", self.anchor)

    def anchor(self, settings, batch, batch_hash):
        assert batch == len(self.hashes), "the contract takes the next batch only"
        self.hashes.append(batch_hash)
        return "0x" + f"{batch:064x}"


def validation_results():
    return [analyse_file(path) for path in sorted(SCANS.iterdir())]


def logged_validation_set():
    return record_findings(validation_results(), "analyse")


def execute(sql: str, *parameters) -> None:
    with closing(sqlite3.connect(ledger_path())) as connection, connection:
        connection.execute(sql, parameters)


# --- the log ------------------------------------------------------------------------------------------------------

def test_every_finding_becomes_a_numbered_row():
    ids = logged_validation_set()
    log = entries()
    assert ids == list(range(1, 25)) and [entry.id for entry in log] == ids
    first = log[0]
    assert (first.command, first.file, first.ip, first.port, first.code, first.severity) == (
        "analyse", "V1_home_basic.xml", "192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT", "medium")
    assert any(entry.code == "UNKNOWN_DEVICE" and entry.port is None for entry in log)


def test_an_unreadable_file_adds_no_row():
    assert record_findings([analyse_file(SCANS / "V7_broken.xml")], "analyse") == []
    assert not ledger_path().exists()


def test_the_log_lives_in_the_history_and_goes_with_delete_my_history():
    logged_validation_set()
    assert ledger_path().exists()
    delete_history()
    assert not ledger_path().exists() and entries() == []


def test_a_row_holds_no_mac_and_no_hostname():
    """NFR-02: what findings.csv holds, plus when and by which command; the file has no raw MAC or hostname."""
    logged_validation_set()
    with closing(sqlite3.connect(ledger_path())) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(entries)")]
    assert columns == ["id", "logged_at", "command", "file", "ip", "port", "proto", "code", "severity"]
    stored = ledger_path().read_bytes().upper()
    raw_macs = {m.upper().encode() for path in SCANS.iterdir()
                for m in re.findall(r'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', path.read_text(encoding="utf-8"))}
    assert raw_macs and not any(mac in stored for mac in raw_macs)
    assert b"ROUTER.LAN" not in stored  # V2's router hostname


# --- the hashes ---------------------------------------------------------------------------------------------------

def test_one_hash_per_full_batch_of_ten():
    logged_validation_set()
    hashes = batch_hashes(entries())
    assert len(hashes) == 2 and all(re.fullmatch(r"0x[0-9a-f]{64}", value) for value in hashes)


def test_the_same_rows_always_give_the_same_hashes():
    logged_validation_set()
    assert batch_hashes(entries()) == batch_hashes(entries())
    assert entry_digest(entries()[0]) == entry_digest(entries()[0])


def test_each_batch_hash_covers_the_batch_before_it():
    """Change a row of batch 0 and both batch hashes change: the latest hash vouches for the whole log."""
    logged_validation_set()
    before = batch_hashes(entries())
    execute("UPDATE entries SET severity = 'info' WHERE id = 3")
    after = batch_hashes(entries())
    assert after[0] != before[0] and after[1] != before[1]


def test_deleted_rows_are_named():
    logged_validation_set()
    execute("DELETE FROM entries WHERE id IN (4, 17)")
    assert missing_ids(entries()) == [4, 17]


# --- anchoring and checking against a chain -----------------------------------------------------------------------

def test_anchor_sends_each_full_batch_once(monkeypatch):
    fake = FakeChain(monkeypatch)
    logged_validation_set()
    assert [batch for batch, _ in anchor_pending(SETTINGS)] == [0, 1]
    assert anchor_pending(SETTINGS) == [] and fake.hashes == batch_hashes(entries())


def test_an_untouched_log_checks_out(monkeypatch):
    FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    report = check(SETTINGS)
    assert not report.tampered
    assert (report.entries, report.on_chain, report.intact, report.unanchored, report.unprotected) == (24, 2, 2, 0, 4)


@pytest.mark.parametrize("change, first_changed", [
    ("UPDATE entries SET code = 'SSH_OPEN' WHERE id = 12", 1),  # a finding rewritten
    ("UPDATE entries SET logged_at = '2020-01-01T00:00:00' WHERE id = 1", 0),  # its time rewritten
    ("DELETE FROM entries WHERE id = 5", 0),  # a finding removed
])
def test_any_change_to_an_anchored_row_is_found(monkeypatch, change, first_changed):
    FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    execute(change)
    report = check(SETTINGS)
    assert report.tampered and report.first_changed == first_changed


def test_two_rows_swapped_are_found(monkeypatch):
    """The same findings in another order: rows 2 and 3 (V2's router, ports 80 and 1900) trade places."""
    FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    second, third = entries()[1], entries()[2]
    assert (second.port, third.port) == (80, 1900)
    for row, other in ((second, third), (third, second)):
        execute("UPDATE entries SET logged_at = ?, command = ?, file = ?, ip = ?, port = ?, proto = ?, code = ?, "
                "severity = ? WHERE id = ?", other.logged_at, other.command, other.file, other.ip, other.port,
                other.proto, other.code, other.severity, row.id)
    assert sorted((e.port, e.code) for e in entries()[1:3]) == [(80, "HTTP_ADMIN_CLEARTEXT"), (1900, "UPNP_EXPOSED")]
    report = check(SETTINGS)
    assert report.tampered and report.first_changed == 0


def test_a_cleared_log_is_found(monkeypatch):
    FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    ledger_path().unlink()
    report = check(SETTINGS)
    assert report.tampered and report.chain_ahead == 2 and report.entries == 0


def test_rows_after_the_last_full_batch_are_reported_as_not_protected_yet(monkeypatch):
    FakeChain(monkeypatch)
    logged_validation_set()
    report = check(SETTINGS)
    assert not report.tampered and (report.unanchored, report.unprotected) == (2, 4)


def test_nothing_is_anchored_on_top_of_a_changed_log(monkeypatch):
    """Anchoring after a change would bless it: the newest anchored hash must still match before anything is sent."""
    fake = FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    execute("UPDATE entries SET code = 'SSH_OPEN' WHERE id = 1")
    logged_validation_set()  # 24 more rows: two more full batches waiting
    with pytest.raises(LedgerError, match="no longer matches"):
        anchor_pending(SETTINGS)
    assert len(fake.hashes) == 2


def test_a_chain_longer_than_the_log_stops_anchoring(monkeypatch):
    FakeChain(monkeypatch)
    logged_validation_set()
    anchor_pending(SETTINGS)
    delete_history()
    record_findings([analyse_file(SCANS / "V1_home_basic.xml")], "analyse")
    with pytest.raises(LedgerError, match="deploy a new contract"):
        anchor_pending(SETTINGS)


# --- the chain client: settings and the cast/forge command lines --------------------------------------------------

def test_without_an_rpc_url_the_log_stays_local(monkeypatch):
    assert ledger.settings_from_env() is None
    monkeypatch.setenv(chain.ENV_RPC_URL, "http://127.0.0.1:8545")
    monkeypatch.setenv(chain.ENV_CONTRACT, CONTRACT)
    assert ledger.settings_from_env() == ChainSettings("http://127.0.0.1:8545", CONTRACT, "")


def test_settings_can_come_from_given_values_instead_of_the_environment():
    """The app reads .env without changing its own environment (conetuga/guard/env_file.py)."""
    values = {chain.ENV_RPC_URL: " http://127.0.0.1:8545 ", chain.ENV_CONTRACT: CONTRACT, chain.ENV_PRIVATE_KEY: KEY}
    assert ledger.settings_from_env(values) == ChainSettings("http://127.0.0.1:8545", CONTRACT, KEY)
    assert ledger.settings_from_env({}) is None


@pytest.mark.parametrize("settings, message", [
    (ChainSettings("file:///etc/passwd", CONTRACT, KEY), "http:// or https://"),
    (ChainSettings("http://127.0.0.1:8545", "--help", KEY), "contract's address"),
    (ChainSettings("http://127.0.0.1:8545", CONTRACT, "0x1234"), "private key"),
])
def test_bad_settings_are_refused_before_any_tool_runs(settings, message):
    with pytest.raises(LedgerError, match=message):
        chain.send_anchor(settings, 0, "0x" + "0" * 64)


def fake_tools(monkeypatch, output: str = "", returncode: int = 0, stderr: str = "") -> list[list[str]]:
    """Replaces subprocess.run inside chain.py: records each command line and answers with `output`."""
    seen = []

    def run(command, capture_output, timeout):
        seen.append(command)
        return chain.subprocess.CompletedProcess(command, returncode, output.encode(), stderr.encode())

    monkeypatch.setattr(chain, "_run", REAL_RUN)  # the real one, with its checks and redaction, over a fake process
    monkeypatch.setattr(chain.subprocess, "run", run)
    monkeypatch.setattr(chain.shutil, "which", lambda name: f"/opt/foundry/bin/{name}")
    return seen


def test_anchoring_sends_the_batch_number_and_hash_to_the_contract(monkeypatch):
    seen = fake_tools(monkeypatch, output='{"status":"0x1","transactionHash":"0x' + "9" * 64 + '"}')
    batch_hash = "0x" + "a1" * 32
    assert chain.send_anchor(SETTINGS, 3, batch_hash) == "0x" + "9" * 64
    assert seen == [["/opt/foundry/bin/cast", "send", CONTRACT, "anchor(uint256,bytes32)", "3", batch_hash,
                     "--rpc-url", "http://127.0.0.1:8545", "--private-key", KEY, "--json"]]


def test_reading_the_count_and_a_hash(monkeypatch):
    fake_tools(monkeypatch, output="2\n")
    assert chain.chain_count(SETTINGS) == 2
    fake_tools(monkeypatch, output="0x" + "A1" * 32 + "\n")
    assert chain.chain_hash(SETTINGS, 1) == "0x" + "a1" * 32


def test_deploy_builds_and_returns_the_new_address(monkeypatch):
    """forge 1.8's real output: its JSON spread over several lines."""
    address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
    output = ('{\n  "deployer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",\n  "deployedTo": "' + address + '",\n'
              '  "transactionHash": "0x' + "4b" * 32 + '"\n}\n')
    seen = fake_tools(monkeypatch, output=output)
    assert chain.deploy(SETTINGS) == address
    assert seen[0][1:4] == ["create", "src/FindingsLedger.sol:FindingsLedger", "--root"] and "--broadcast" in seen[0]


def test_deploy_without_an_address_in_forges_output_is_an_error(monkeypatch):
    fake_tools(monkeypatch, output="Compiler run successful!\n")
    with pytest.raises(LedgerError, match="address"):
        chain.deploy(SETTINGS)


def test_a_rejected_transaction_is_an_error(monkeypatch):
    fake_tools(monkeypatch, output='{"status":"0x0","transactionHash":"0x1"}')
    with pytest.raises(LedgerError, match="rejected"):
        chain.send_anchor(SETTINGS, 0, "0x" + "0" * 64)


def test_the_key_and_the_rpc_url_never_reach_an_error_message(monkeypatch):
    """A tool's error may echo them; an Infura or Alchemy URL holds an API key."""
    settings = ChainSettings("https://sepolia.infura.io/v3/" + "f" * 32, CONTRACT, KEY)
    fake_tools(monkeypatch, returncode=1, stderr=f"error: bad key {KEY.upper()} for {settings.rpc_url}")
    with pytest.raises(LedgerError) as error:
        chain.send_anchor(settings, 0, "0x" + "0" * 64)
    message = str(error.value)
    assert "ab" * 32 not in message.lower() and "f" * 32 not in message and "***" in message and "<RPC>" in message


def test_the_key_never_reaches_an_unexpected_answer_message(monkeypatch):
    """What a tool prints on success can also end up in a message ("unexpected answer: ...")."""
    fake_tools(monkeypatch, output=f"warning {KEY} count unknown")
    with pytest.raises(LedgerError) as error:
        chain.chain_count(SETTINGS)
    assert "ab" * 32 not in str(error.value).lower() and "***" in str(error.value)


def test_missing_foundry_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(chain.shutil, "which", lambda name: None)
    with pytest.raises(LedgerError, match="foundryup"):
        chain.chain_count(SETTINGS)


# --- the command line ---------------------------------------------------------------------------------------------

def test_analyse_logs_every_finding_and_its_csv_is_unchanged(tmp_path, capsys):
    assert cli.main(["analyse", str(SCANS), "--out", str(tmp_path)]) == cli.EXIT_OK
    assert "24 de constatări salvate (nr. 1–24)" in capsys.readouterr().out
    rows = (tmp_path / "findings.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert sorted(rows) == sorted(EXPECTED.read_text(encoding="utf-8").splitlines()[1:])
    assert len(entries()) == 24


def test_a_log_that_cant_be_written_never_changes_analyse(monkeypatch, tmp_path, capsys):
    def broken(results, command):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ledger, "record_findings", broken)
    assert cli.main(["analyse", str(SCANS), "--out", str(tmp_path)]) == cli.EXIT_OK
    assert (tmp_path / "scores.csv").is_file() and "couldn't be written" in capsys.readouterr().err


def test_analyse_anchors_the_full_batches_when_a_chain_is_set(monkeypatch, tmp_path, capsys):
    fake = FakeChain(monkeypatch)
    for name, value in zip(CHAIN_ENV, ("http://127.0.0.1:8545", CONTRACT, KEY)):
        monkeypatch.setenv(name, value)
    assert cli.main(["analyse", str(SCANS), "--out", str(tmp_path)]) == cli.EXIT_OK
    assert "anchored batch(es) 0–1" in capsys.readouterr().out and len(fake.hashes) == 2


def test_a_chain_that_fails_never_changes_analyse(monkeypatch, tmp_path, capsys):
    def down(settings):
        raise LedgerError("Blockchain-ul nu a răspuns în 30 s.\nThe chain didn't answer within 30 s.")

    monkeypatch.setattr(ledger, "chain_count", down)
    monkeypatch.setenv(chain.ENV_RPC_URL, "http://127.0.0.1:8545")
    monkeypatch.setenv(chain.ENV_CONTRACT, CONTRACT)
    assert cli.main(["analyse", str(SCANS), "--out", str(tmp_path)]) == cli.EXIT_OK
    assert "didn't answer" in capsys.readouterr().err and len(entries()) == 24


def test_ledger_verify_exits_0_when_intact_and_5_when_changed(monkeypatch, tmp_path, capsys):
    FakeChain(monkeypatch)
    monkeypatch.setenv(chain.ENV_RPC_URL, "http://127.0.0.1:8545")
    monkeypatch.setenv(chain.ENV_CONTRACT, CONTRACT)
    logged_validation_set()
    anchor_pending(SETTINGS)
    assert cli.main(["ledger", "verify"]) == cli.EXIT_OK
    assert "rows 1–20) are unchanged" in capsys.readouterr().out
    execute("UPDATE entries SET severity = 'low' WHERE id = 15")
    assert cli.main(["ledger", "verify"]) == cli.EXIT_TAMPERED
    assert "batch 1 (rows 11–20) was changed" in capsys.readouterr().out


def test_ledger_without_settings_says_what_to_set(capsys):
    assert cli.main(["ledger", "verify"]) == cli.EXIT_ERROR
    assert chain.ENV_RPC_URL in capsys.readouterr().err


def test_ledger_deploy_prints_the_line_to_export(monkeypatch, capsys):
    address = "0x" + "5f" * 20
    monkeypatch.setattr(ledger, "deploy", lambda settings: address)
    monkeypatch.setenv(chain.ENV_RPC_URL, "http://127.0.0.1:8545")
    monkeypatch.setenv(chain.ENV_PRIVATE_KEY, KEY)
    assert cli.main(["ledger", "deploy"]) == cli.EXIT_OK
    assert f"export {chain.ENV_CONTRACT}={address}" in capsys.readouterr().out
