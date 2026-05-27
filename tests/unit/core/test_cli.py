"""Tests for the Click entry point and the adapters subcommand."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from cyberm4fia_wifi import cli as cli_module
from cyberm4fia_wifi.cli import main
from cyberm4fia_wifi.core.adapter import ADAPTERS, DetectedAdapter
from cyberm4fia_wifi.core.auth import AuthzConfig


@pytest.fixture
def cli_env(tmp_config_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Acknowledge the gate up-front so root-callback prompts don't block tests."""
    from cyberm4fia_wifi.core.auth import AuthorizationGate

    gate = AuthorizationGate.from_xdg()
    AuthzConfig(acknowledged_at="2026-05-27T00:00:00Z").dump(gate.config_path)
    return tmp_config_home


class TestCliBasics:
    def test_help_lists_subcommands(self, cli_env: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "adapters" in result.output
        assert "scan" in result.output

    def test_adapters_command_with_no_adapters(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cli_module, "detect_adapters", lambda: [])
        runner = CliRunner()
        result = runner.invoke(main, ["adapters"])
        assert result.exit_code == 0
        assert "no wireless adapters" in result.output

    def test_adapters_command_prints_detected(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = [
            DetectedAdapter(
                iface="wlan0",
                profile=ADAPTERS[(0x0CF3, 0x9271)],
                vendor_id=0x0CF3,
                product_id=0x9271,
            ),
            DetectedAdapter(
                iface="wlan1",
                profile=ADAPTERS[(0x0BDA, 0x8812)],
                vendor_id=0x0BDA,
                product_id=0x8812,
            ),
        ]
        monkeypatch.setattr(cli_module, "detect_adapters", lambda: fake)

        runner = CliRunner()
        result = runner.invoke(main, ["adapters"])
        assert result.exit_code == 0
        assert "wlan0" in result.output
        assert "AR9271" in result.output
        assert "wlan1" in result.output
        assert "RTL8812AU" in result.output


class TestAuthGateWiring:
    def test_missing_acknowledgment_blocks_subcommands(
        self,
        tmp_config_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # No authz.yaml exists; the runner will see an EOF on stdin and the
        # gate's ensure_acknowledged should turn that into a ClickException.
        runner = CliRunner()
        result = runner.invoke(main, ["adapters"], input="")
        assert result.exit_code != 0
