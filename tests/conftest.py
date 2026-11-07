"""Shared test setup: every test gets its own empty history folder, so no test (the live-scan CLI tests save their
scan) ever writes into the real `.history/` of the computer running the suite."""
import pytest


@pytest.fixture(autouse=True)
def history_in_a_temporary_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history-of-this-test"))
