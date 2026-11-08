"""Shared test setup: every test gets its own empty history folder, so no test (the live-scan CLI tests save their
scan) ever writes into the real `.history/` of the computer running the suite; and no test ever reaches a real
blockchain, even when the person running the suite exported the findings log's chain settings (conetuga/ledger);
and no test ever calls a local model, even when CONETUGA_LLM_MODEL is set in that terminal (conetuga/explain/llm.py)."""
import pytest

CHAIN_SETTINGS = ("CONETUGA_CHAIN_RPC_URL", "CONETUGA_CHAIN_CONTRACT", "CONETUGA_CHAIN_PRIVATE_KEY")


@pytest.fixture(autouse=True)
def history_in_a_temporary_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history-of-this-test"))


@pytest.fixture(autouse=True)
def no_blockchain_settings(monkeypatch, tmp_path):
    for name in CHAIN_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    # The CLI reads CONETUGA_* settings from the repo's .env: point it at a file that isn't there, so a person's own
    # .env (with a real chain's settings) never reaches a test.
    monkeypatch.setenv("CONETUGA_ENV_FILE", str(tmp_path / "no-env-file"))


@pytest.fixture(autouse=True)
def no_local_model(monkeypatch):
    monkeypatch.delenv("CONETUGA_LLM_MODEL", raising=False)
