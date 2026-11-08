"""The app's Streamlit settings (.streamlit/config.toml): reachable only from this computer, and no usage statistics
sent anywhere (NFR-02). Without the file, Streamlit listens on every network interface, so anyone on the hotspot or
the venue's Wi-Fi could open the results, delete the history or start a scan."""
import tomllib
from pathlib import Path

import pytest

CONFIG = Path(__file__).resolve().parents[1] / ".streamlit" / "config.toml"


def settings() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def test_the_app_listens_only_on_this_computer():
    assert settings()["server"]["address"] == "127.0.0.1"


def test_the_app_sends_no_usage_statistics():
    assert settings()["browser"]["gatherUsageStats"] is False


def test_streamlit_reads_the_same_values(monkeypatch):
    """Streamlit itself, started from the repository's root as the README says, picks the file up."""
    config = pytest.importorskip("streamlit.config")
    monkeypatch.chdir(CONFIG.parents[1])
    config.get_config_options(force_reparse=True)
    try:
        assert config.get_option("server.address") == "127.0.0.1"
        assert config.get_option("browser.gatherUsageStats") is False
    finally:
        monkeypatch.undo()
        config.get_config_options(force_reparse=True)
