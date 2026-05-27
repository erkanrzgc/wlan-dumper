"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def pcap_dir() -> Path:
    """Directory containing captured 802.11 fixtures used by sniffer tests."""
    return Path(__file__).parent / "fixtures" / "pcaps"


@pytest.fixture
def tmp_config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect XDG config/data dirs to a tmp tree so auth/audit tests don't touch $HOME."""
    config = tmp_path / "config"
    data = tmp_path / "data"
    config.mkdir()
    data.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    return tmp_path
