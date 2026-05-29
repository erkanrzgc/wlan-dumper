"""Tests for the DeauthPlugin (frame construction + event emission)."""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")

from wlan_dumper.core.auth import AuthorizationGate, AuthzConfig
from wlan_dumper.core.events import DeauthSent, EventBus
from wlan_dumper.plugins.deauth import DeauthPlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(acknowledged_at="x"))
    return g


def _capture_sent(monkeypatch: pytest.MonkeyPatch) -> list:
    sent: list = []

    def fake_sendp(frames, **_kw):
        if isinstance(frames, list):
            sent.extend(frames)
        else:
            sent.append(frames)

    monkeypatch.setattr("scapy.all.sendp", fake_sendp)
    return sent


class TestDeauthExecute:
    def test_sends_configured_count(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent = _capture_sent(monkeypatch)
        bus = EventBus()
        events: list = []
        bus.subscribe(DeauthSent, events.append)

        plugin = DeauthPlugin()
        rc = plugin.execute(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:01",
            target_station="11:22:33:44:55:66",
            count=5, reason="test",
        )

        assert rc == 0
        assert len(sent) == 5
        assert [e.sequence for e in events] == [1, 2, 3, 4, 5]
        assert all(e.total == 5 for e in events)

    def test_broadcast_target_sets_station_none_and_uses_ff(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent = _capture_sent(monkeypatch)
        bus = EventBus()
        events: list = []
        bus.subscribe(DeauthSent, events.append)

        plugin = DeauthPlugin()
        plugin.execute(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:01",
            target_station=None,
            count=2, reason="test",
        )

        assert events[0].target_station is None
        from scapy.all import Dot11
        for frame in sent:
            assert frame[Dot11].addr1.lower() == "ff:ff:ff:ff:ff:ff"

    def test_reason_is_optional(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Gate no longer enforces a reason — execute must run without one."""
        _capture_sent(monkeypatch)
        plugin = DeauthPlugin()
        rc = plugin.execute(
            bus=EventBus(), gate=gate, iface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:01",
            target_station="11:22:33:44:55:66",
            count=1,
        )
        assert rc == 0
