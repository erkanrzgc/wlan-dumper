"""Tests for the HandshakePlugin state machine + artifact write."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import Ether  # noqa: E402

from cyberm4fia_wifi.core.auth import AuthorizationGate, AuthzConfig
from cyberm4fia_wifi.core.events import EAPOLCapture, EventBus, HandshakeComplete
from cyberm4fia_wifi.plugins.handshake import HandshakePlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(acknowledged_at="x"))
    return g


def _eapol(bssid: str, sta: str, mi: int) -> EAPOLCapture:
    return EAPOLCapture(
        timestamp=100.0 + mi,
        bssid=bssid,
        station=sta,
        message_index=mi,
        raw=bytes(Ether() / b"x"),
    )


class TestHandshakeStateMachine:
    def test_emits_handshake_complete_when_all_four_messages_seen(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        def fake_convert(p):
            out = p.with_suffix(".22000")
            out.write_text("WPA*02*...")
            return out

        monkeypatch.setattr(
            "cyberm4fia_wifi.plugins.handshake.convert_to_22000", fake_convert
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )

        for mi in (1, 2, 3, 4):
            bus.publish(_eapol("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", mi))

        assert len(completes) == 1
        evt = completes[0]
        assert evt.valid_by_hcxtool is True
        assert evt.pcap_path.endswith(".pcap")
        assert evt.hashcat_path is not None and evt.hashcat_path.endswith(".22000")
        assert Path(evt.pcap_path).exists()

    def test_partial_capture_no_complete_event(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        monkeypatch.setattr(
            "cyberm4fia_wifi.plugins.handshake.convert_to_22000", lambda p: None
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )
        # Only M1 — handshake not complete (need {1,2} minimum).
        bus.publish(_eapol("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", 1))

        assert completes == []

    def test_ignores_eapol_for_other_bssid(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        def fake_convert(p):
            out = p.with_suffix(".22000")
            out.write_text("WPA*02*...")
            return out

        monkeypatch.setattr(
            "cyberm4fia_wifi.plugins.handshake.convert_to_22000", fake_convert
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )
        for mi in (1, 2, 3, 4):
            bus.publish(_eapol("zz:zz:zz:zz:zz:zz", "11:22:33:44:55:66", mi))

        assert completes == []
