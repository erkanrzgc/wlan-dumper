"""Tests for CrackPlugin orchestration (backend runners are stubbed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wlan_dumper.core.auth import AuthorizationGate, AuthzConfig
from wlan_dumper.core.events import CrackComplete, CrackProgress, CrackStarted, EventBus
from wlan_dumper.plugins.crack import CrackPlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(acknowledged_at="x"))
    return g


@pytest.fixture(autouse=True)
def _force_hashcat(monkeypatch: pytest.MonkeyPatch) -> None:
    # detect_backend would otherwise depend on what's installed on the box.
    monkeypatch.setattr("wlan_dumper.plugins.crack.detect_backend", lambda pref=None: "hashcat")


def _collect(bus: EventBus):
    events: dict[type, list] = {CrackStarted: [], CrackProgress: [], CrackComplete: []}
    for et in events:
        bus.subscribe(et, events[et].append)
    return events


class TestCrackPluginExecute:
    def test_hit_emits_started_and_complete_and_writes_file(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        plugin = CrackPlugin()
        # Stub the backend runner: pretend hashcat found the passphrase.
        monkeypatch.setattr(plugin, "_run_hashcat", lambda job, on_progress: "hunter2")

        bus = EventBus()
        events = _collect(bus)

        rc = plugin.execute(
            bus=bus,
            gate=gate,
            hash_path="/tmp/x.22000",
            bssid="AA:BB:CC:DD:EE:FF",
            essid="MyNet",
            mode="wordlist",
            wordlist="/w/rockyou.txt",
        )

        assert rc == 0
        assert len(events[CrackStarted]) == 1
        assert events[CrackStarted][0].backend == "hashcat"
        assert len(events[CrackComplete]) == 1
        complete = events[CrackComplete][0]
        assert complete.password == "hunter2"
        assert complete.bssid == "aa:bb:cc:dd:ee:ff"

        out = paths.cracked_path("MyNet", "aa:bb:cc:dd:ee:ff")
        assert out.exists()
        assert "password=hunter2" in out.read_text()

    def test_miss_emits_complete_with_none_and_no_file(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        plugin = CrackPlugin()
        monkeypatch.setattr(plugin, "_run_hashcat", lambda job, on_progress: None)

        bus = EventBus()
        events = _collect(bus)

        rc = plugin.execute(
            bus=bus,
            gate=gate,
            hash_path="/tmp/x.22000",
            bssid="aa:bb:cc:dd:ee:ff",
            essid="MyNet",
            mode="wordlist",
            wordlist="/w/rockyou.txt",
        )

        assert rc == 1
        assert events[CrackComplete][0].password is None
        assert not paths.cracked_path("MyNet", "aa:bb:cc:dd:ee:ff").exists()

    def test_mask_mode_reports_keyspace_in_started(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        plugin = CrackPlugin()
        monkeypatch.setattr(plugin, "_run_hashcat", lambda job, on_progress: None)

        bus = EventBus()
        events = _collect(bus)

        plugin.execute(
            bus=bus,
            gate=gate,
            hash_path="/tmp/x.22000",
            bssid="aa:bb:cc:dd:ee:ff",
            essid="MyNet",
            mode="mask",
            mask="?d?d?d?d",
        )

        assert events[CrackStarted][0].keyspace == 10_000
        assert events[CrackStarted][0].eta_seconds is not None
