"""Tests for the HandshakePlugin state machine + artifact write."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
import scapy.all as s

from wlan_dumper.core.auth import AuthorizationGate, AuthzConfig
from wlan_dumper.core.events import (
    CaptureNotice,
    EAPOLCapture,
    EventBus,
    HandshakeComplete,
)
from wlan_dumper.plugins.handshake import HandshakePlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(acknowledged_at="x"))
    return g


def _raw_eapol(bssid: str, sta: str) -> bytes:
    """Realistic radiotap-prefixed 802.11 QoS-data EAPOL-Key bytes, as captured.

    The sniffer delivers raw radiotap frames; the plugin must persist them in a
    form hcxpcapngtool can read, so tests feed it the real wire shape rather
    than an Ethernet stub.
    """
    pkt = (
        s.RadioTap()
        / s.Dot11(type=2, subtype=8, addr1=sta, addr2=bssid, addr3=bssid)
        / s.Dot11QoS()
        / s.LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / s.SNAP(OUI=0, code=0x888E)
        / s.EAPOL(version=2, type=3)
    )
    return bytes(pkt)


def _eapol(bssid: str, sta: str, mi: int) -> EAPOLCapture:
    return EAPOLCapture(
        timestamp=100.0 + mi,
        bssid=bssid,
        station=sta,
        message_index=mi,
        raw=_raw_eapol(bssid, sta),
    )


class TestHandshakeStateMachine:
    def test_emits_handshake_complete_when_all_four_messages_seen(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        def fake_convert(p):
            out = p.with_suffix(".22000")
            out.write_text("WPA*02*...")
            return out

        monkeypatch.setattr("wlan_dumper.plugins.handshake.convert_to_22000", fake_convert)

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
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
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        monkeypatch.setattr("wlan_dumper.plugins.handshake.convert_to_22000", lambda p: None)

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
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
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        def fake_convert(p):
            out = p.with_suffix(".22000")
            out.write_text("WPA*02*...")
            return out

        monkeypatch.setattr("wlan_dumper.plugins.handshake.convert_to_22000", fake_convert)

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
        )
        for mi in (1, 2, 3, 4):
            bus.publish(_eapol("99:99:99:99:99:99", "11:22:33:44:55:66", mi))

        assert completes == []


class TestHandshakePcapArtifact:
    """The saved pcap must be readable by hcxpcapngtool: radiotap DLT + ESSID.

    Regression for handshake captures being written as Ethernet under
    DLT_EN10MB with no beacon, which made every capture silently uncrackable.
    """

    def test_capture_is_radiotap_and_carries_essid_beacon(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        # Leave append_packets REAL — we assert on the bytes it writes.
        monkeypatch.setattr(
            "wlan_dumper.plugins.handshake.convert_to_22000", lambda p: None
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        bssid, sta = "aa:bb:cc:dd:ee:01", "11:22:33:44:55:66"
        plugin = HandshakePlugin()
        plugin._arm(bus=bus, target_bssid=bssid, target_station=None, essid="MyHome")
        bus.publish(_eapol(bssid, sta, 1))
        bus.publish(_eapol(bssid, sta, 2))

        # M1+M2 → exactly one completion; PARTIAL because hcx is stubbed to None.
        assert len(completes) == 1
        assert completes[0].valid_by_hcxtool is False

        pkts = s.rdpcap(completes[0].pcap_path)
        # Whole file decodes as radiotap (not the old corrupt Ether/EN10MB form).
        assert all(type(p).__name__ == "RadioTap" for p in pkts)
        # libpcap DLT in the global header is DLT_IEEE802_11_RADIO (127).
        dlt = int.from_bytes(Path(completes[0].pcap_path).read_bytes()[20:24], "little")
        assert dlt == 127
        # Exactly one synthetic beacon carrying the ESSID was prepended.
        beacons = [p for p in pkts if p.haslayer(s.Dot11Beacon)]
        assert len(beacons) == 1
        assert bytes(beacons[0].getlayer(s.Dot11Elt).info) == b"MyHome"
        # Both EAPOL frames survived the round-trip.
        assert sum(1 for p in pkts if p.haslayer(s.EAPOL)) == 2

    def test_hidden_essid_skips_beacon_but_still_captures(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        monkeypatch.setattr(
            "wlan_dumper.plugins.handshake.convert_to_22000", lambda p: None
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        bssid, sta = "aa:bb:cc:dd:ee:01", "11:22:33:44:55:66"
        plugin = HandshakePlugin()
        plugin._arm(bus=bus, target_bssid=bssid, target_station=None, essid=None)
        bus.publish(_eapol(bssid, sta, 1))
        bus.publish(_eapol(bssid, sta, 2))

        assert len(completes) == 1
        pkts = s.rdpcap(completes[0].pcap_path)
        assert [p for p in pkts if p.haslayer(s.Dot11Beacon)] == []
        assert sum(1 for p in pkts if p.haslayer(s.EAPOL)) == 2


class TestCaptureTimeoutDiagnostic:
    """On an empty capture, execute() must explain why — especially injection."""

    def _run_until_timeout(
        self, gate, monkeypatch: pytest.MonkeyPatch, *, auto_deauth: bool
    ) -> list[CaptureNotice]:
        # Don't transmit real frames; pretend the deauth burst was sent.
        monkeypatch.setattr(
            "wlan_dumper.plugins.handshake.DeauthPlugin.execute",
            lambda self, **kw: 0,
        )
        bus = EventBus()
        notices: list[CaptureNotice] = []
        bus.subscribe(CaptureNotice, notices.append)
        plugin = HandshakePlugin()
        plugin.execute(
            bus=bus,
            gate=gate,
            iface="wlan0",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station=None,
            essid="MyHome",
            auto_deauth=auto_deauth,
            deauth_count=8,
            timeout=0.05,
        )
        return notices

    def test_deauth_sent_but_no_eapol_warns_injection(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notices = self._run_until_timeout(gate, monkeypatch, auto_deauth=True)
        assert len(notices) == 1
        assert notices[0].level == "warning"
        assert notices[0].deauth_sent == 8
        assert notices[0].eapol_seen == 0
        assert "injection" in notices[0].message.lower()

    def test_passive_no_eapol_is_info_not_injection(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notices = self._run_until_timeout(gate, monkeypatch, auto_deauth=False)
        assert len(notices) == 1
        assert notices[0].level == "info"
        assert notices[0].deauth_sent == 0
        assert "injection" not in notices[0].message.lower()

    def test_partial_eapol_is_info_timing(
        self, gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wlan_dumper.utils import paths

        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        monkeypatch.setattr(
            "wlan_dumper.plugins.handshake.convert_to_22000", lambda p: None
        )
        monkeypatch.setattr(
            "wlan_dumper.plugins.handshake.DeauthPlugin.execute",
            lambda self, **kw: 0,
        )

        bssid, sta = "aa:bb:cc:dd:ee:01", "11:22:33:44:55:66"
        bus = EventBus()
        notices: list[CaptureNotice] = []
        bus.subscribe(CaptureNotice, notices.append)

        plugin = HandshakePlugin()
        plugin._arm(bus=bus, target_bssid=bssid, target_station=None, essid="MyHome")
        # Only M1 — a reaction, but no usable pair, so no completion.
        bus.publish(_eapol(bssid, sta, 1))
        plugin._emit_timeout_notice(bus, auto_deauth=True, deauth_sent=8)

        assert notices[-1].level == "info"
        assert notices[-1].eapol_seen == 1
        assert "client is reacting" in notices[-1].message
