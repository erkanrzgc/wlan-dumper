"""Tests for the one-time legal acknowledgment + audit log."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from wlan_dumper.core.auth import (
    AuthorizationGate,
    AuthzConfig,
    AuthzError,
    PluginRisk,
)


@pytest.fixture
def gate(tmp_config_home: Path) -> AuthorizationGate:
    return AuthorizationGate.from_xdg()


class TestAuthzConfigPersistence:
    def test_round_trip_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "authz.yaml"
        AuthzConfig(acknowledged_at="2026-05-27T05:30:00Z").dump(path)

        loaded = AuthzConfig.load(path)
        assert loaded is not None
        assert loaded.acknowledged_at == "2026-05-27T05:30:00Z"

    def test_load_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert AuthzConfig.load(tmp_path / "absent.yaml") is None


class TestFirstLaunchAcknowledgment:
    def test_prompt_writes_config_on_yes(self, gate: AuthorizationGate) -> None:
        gate.ensure_acknowledged(
            stdin=io.StringIO("y\n"),
            stdout=io.StringIO(),
        )

        cfg = AuthzConfig.load(gate.config_path)
        assert cfg is not None
        assert cfg.acknowledged_at  # ISO timestamp recorded

    def test_prompt_refusal_raises(self, gate: AuthorizationGate) -> None:
        with pytest.raises(AuthzError):
            gate.ensure_acknowledged(
                stdin=io.StringIO("n\n"),
                stdout=io.StringIO(),
            )
        assert AuthzConfig.load(gate.config_path) is None

    def test_already_acknowledged_does_not_re_prompt(
        self, gate: AuthorizationGate
    ) -> None:
        AuthzConfig(acknowledged_at="2026-05-27T00:00:00Z").dump(gate.config_path)

        # Empty stdin: would block / EOF if a prompt were issued.
        gate.ensure_acknowledged(stdin=io.StringIO(""), stdout=io.StringIO())


class TestAuditLog:
    def test_passive_action_is_not_logged(self, gate: AuthorizationGate) -> None:
        gate.check(plugin="scan", risk=PluginRisk.PASSIVE)
        assert not gate.audit_path.exists() or gate.audit_path.read_text() == ""

    def test_active_action_is_logged(self, gate: AuthorizationGate) -> None:
        gate.check(
            plugin="pmkid",
            risk=PluginRisk.ACTIVE,
            target="AA:BB:CC:DD:EE:01",
        )

        line = gate.audit_path.read_text().strip().splitlines()[-1]
        assert "risk=active" in line
        assert "plugin=pmkid" in line
        assert "target=AA:BB:CC:DD:EE:01" in line

    def test_high_action_logs_reason_verbatim(self, gate: AuthorizationGate) -> None:
        gate.check(
            plugin="evil_twin",
            risk=PluginRisk.HIGH,
            target="AA:BB:CC:DD:EE:01",
            reason="engagement 4711",
        )

        line = gate.audit_path.read_text().strip().splitlines()[-1]
        assert 'reason="engagement 4711"' in line
        assert "risk=high" in line

    def test_active_action_without_target_still_logs(
        self, gate: AuthorizationGate
    ) -> None:
        gate.check(plugin="deauth", risk=PluginRisk.ACTIVE)
        line = gate.audit_path.read_text().strip().splitlines()[-1]
        assert "target=-" in line

    def test_check_never_raises(self, gate: AuthorizationGate) -> None:
        # The whole point of the simplification: check() is informational only.
        gate.check(plugin="deauth", risk=PluginRisk.HIGH)
        gate.check(plugin="deauth", risk=PluginRisk.HIGH, target=None, reason=None)
