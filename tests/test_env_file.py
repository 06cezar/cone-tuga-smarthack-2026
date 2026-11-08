"""The .env reader shared by the CLI and the app (conetuga/guard/env_file.py). The CLI's own loading is tested in
tests/test_cli.py; these tests cover what the app uses: the values as the CLI would see them, read without changing
the app's environment. Every file is a temporary one: no test reads a person's real .env."""
import os

from conetuga.guard.env_file import env_file_values, settings_with_env_file

RPC_URL = "CONETUGA_CHAIN_RPC_URL"


def env_file(tmp_path, monkeypatch, text: str) -> None:
    path = tmp_path / "test.env"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("CONETUGA_ENV_FILE", str(path))


def test_the_app_sees_the_env_file_without_changing_its_environment(tmp_path, monkeypatch):
    env_file(tmp_path, monkeypatch, "CONETUGA_CHAIN_RPC_URL=http://127.0.0.1:8545\nPATH=/tmp/evil\n")
    values = settings_with_env_file()
    assert values[RPC_URL] == "http://127.0.0.1:8545" and values["PATH"] == os.environ["PATH"]
    assert RPC_URL not in os.environ


def test_an_exported_variable_wins_over_the_env_file_for_the_app_too(tmp_path, monkeypatch):
    env_file(tmp_path, monkeypatch, "CONETUGA_CHAIN_RPC_URL=http://from-the-file:8545\n")
    monkeypatch.setenv(RPC_URL, "http://exported:8545")
    assert settings_with_env_file()[RPC_URL] == "http://exported:8545"


def test_the_first_line_for_a_name_wins(tmp_path, monkeypatch):
    """The same rule as before the reader was shared: the CLI kept the first value it set."""
    env_file(tmp_path, monkeypatch, "CONETUGA_CHAIN_RPC_URL=http://first:8545\nCONETUGA_CHAIN_RPC_URL=http://second:8545\n")
    assert env_file_values() == {RPC_URL: "http://first:8545"}


def test_no_env_file_gives_no_values(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_ENV_FILE", str(tmp_path / "missing.env"))
    assert env_file_values() == {}
