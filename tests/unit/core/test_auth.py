"""Tests for the authorization gate, mode persistence, and audit log."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from cyberm4fia_wifi.core.auth import (
    AuthorizationGate,
    AuthzConfig,
    AuthzError,
    Mode,
    PluginRisk,
)


@pytest.fixture
def gate(tmp_config_home: Path) -> AuthorizationGate:
    return AuthorizationGate.from_xdg()


class TestAuthzConfigPersistence:
    def test_round_trip_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "authz.yaml"
        cfg = AuthzConfig(
            mode=Mode.PENTEST,
            acknowledged_at="2026-05-27T05:30:00Z",
            whitelist_bssids=["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )
        cfg.dump(path)

        loaded = AuthzConfig.load(path)
        assert loaded.mode is Mode.PENTEST
        assert loaded.whitelist_bssids == ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]

    def test_load_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert AuthzConfig.load(tmp_path / "absent.yaml") is None

    def test_invalid_mode_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "authz.yaml"
        path.write_text("mode: nonsense\nacknowledged_at: now\n")
        with pytest.raises(AuthzError):
            AuthzConfig.load(path)


class TestFirstLaunchPrompt:
    def test_prompt_writes_config_on_yes(self, gate: AuthorizationGate) -> None:
        gate.ensure_acknowledged(
            stdin=io.StringIO("general\ny\n"),
            stdout=io.StringIO(),
        )

        cfg = AuthzConfig.load(gate.config_path)
        assert cfg is not None
        assert cfg.mode is Mode.GENERAL
        assert cfg.acknowledged_at  # ISO timestamp recorded

    def test_prompt_refusal_raises(self, gate: AuthorizationGate) -> None:
        with pytest.raises(AuthzError):
            gate.ensure_acknowledged(
                stdin=io.StringIO("general\nn\n"),
                stdout=io.StringIO(),
            )
        assert AuthzConfig.load(gate.config_path) is None

    def test_already_acknowledged_does_not_re_prompt(self, gate: AuthorizationGate) -> None:
        cfg = AuthzConfig(mode=Mode.LAB, acknowledged_at="2026-05-27T00:00:00Z")
        cfg.dump(gate.config_path)

        # Empty stdin: would raise EOF if a prompt were issued.
        gate.ensure_acknowledged(stdin=io.StringIO(""), stdout=io.StringIO())


class TestGateChecks:
    def test_passive_plugin_always_allowed(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.GENERAL, acknowledged_at="x"))
        gate.check(plugin="scan", risk=PluginRisk.PASSIVE, target=None, reason=None)

    def test_active_plugin_in_general_mode_needs_target(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.GENERAL, acknowledged_at="x"))
        with pytest.raises(AuthzError):
            gate.check(plugin="pmkid", risk=PluginRisk.ACTIVE, target=None, reason=None)

    def test_active_plugin_in_pentest_requires_whitelisted_bssid(
        self, gate: AuthorizationGate
    ) -> None:
        gate.set_config(
            AuthzConfig(
                mode=Mode.PENTEST,
                acknowledged_at="x",
                whitelist_bssids=["AA:BB:CC:DD:EE:01"],
            )
        )
        gate.check(plugin="pmkid", risk=PluginRisk.ACTIVE, target="AA:BB:CC:DD:EE:01", reason=None)
        with pytest.raises(AuthzError):
            gate.check(
                plugin="pmkid",
                risk=PluginRisk.ACTIVE,
                target="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
                reason=None,
            )

    def test_high_risk_requires_reason_flag(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        with pytest.raises(AuthzError):
            gate.check(plugin="evil_twin", risk=PluginRisk.HIGH, target=None, reason=None)

        gate.check(
            plugin="evil_twin",
            risk=PluginRisk.HIGH,
            target=None,
            reason="lab smoke test",
        )

    def test_lab_mode_allows_active_without_target(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        gate.check(plugin="pmkid", risk=PluginRisk.ACTIVE, target=None, reason=None)


class TestAuditLog:
    def test_active_action_is_logged(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        gate.check(
            plugin="pmkid",
            risk=PluginRisk.ACTIVE,
            target="AA:BB:CC:DD:EE:01",
            reason=None,
        )

        line = gate.audit_path.read_text().strip().splitlines()[-1]
        assert "mode=lab" in line
        assert "plugin=pmkid" in line
        assert "target=AA:BB:CC:DD:EE:01" in line

    def test_high_action_logs_reason_verbatim(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        gate.check(
            plugin="evil_twin",
            risk=PluginRisk.HIGH,
            target="AA:BB:CC:DD:EE:01",
            reason="engagement 4711",
        )

        line = gate.audit_path.read_text().strip().splitlines()[-1]
        assert 'reason="engagement 4711"' in line

    def test_passive_action_is_not_logged(self, gate: AuthorizationGate) -> None:
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        gate.check(plugin="scan", risk=PluginRisk.PASSIVE, target=None, reason=None)

        # Audit file may not even exist for passive-only runs
        assert not gate.audit_path.exists() or gate.audit_path.read_text() == ""
