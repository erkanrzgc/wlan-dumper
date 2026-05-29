"""Tests for the in-memory session state store."""

from __future__ import annotations

from pathlib import Path

from wlan_dumper.core.events import BeaconSeen, ChannelChanged, ClientSeen, EventBus
from wlan_dumper.core.session import Session


def _beacon(
    bssid: str = "AA:BB:CC:DD:EE:01",
    essid: str | None = "MyHome",
    channel: int = 6,
    signal: int = -42,
    ts: float = 100.0,
) -> BeaconSeen:
    return BeaconSeen(
        timestamp=ts,
        bssid=bssid,
        essid=essid,
        channel=channel,
        encryption="WPA2-PSK",
        signal_dbm=signal,
    )


def _client(
    bssid: str = "AA:BB:CC:DD:EE:01",
    station: str = "11:22:33:44:55:66",
    signal: int = -55,
    ts: float = 100.5,
) -> ClientSeen:
    return ClientSeen(timestamp=ts, bssid=bssid, station=station, signal_dbm=signal)


class TestAPUpserts:
    def test_first_beacon_creates_ap(self) -> None:
        sess = Session()
        sess.handle_event(_beacon())

        aps = sess.aps_snapshot()
        assert len(aps) == 1
        ap = aps[0]
        assert ap.bssid == "AA:BB:CC:DD:EE:01"
        assert ap.essid == "MyHome"
        assert ap.channel == 6
        assert ap.beacon_count == 1

    def test_repeat_beacon_increments_count_and_updates_signal(self) -> None:
        sess = Session()
        sess.handle_event(_beacon(signal=-42, ts=100.0))
        sess.handle_event(_beacon(signal=-38, ts=101.0))

        ap = sess.aps_snapshot()[0]
        assert ap.beacon_count == 2
        assert ap.signal_dbm == -38
        assert ap.last_seen == 101.0

    def test_hidden_network_essid_none_preserved(self) -> None:
        sess = Session()
        sess.handle_event(_beacon(essid=None))

        assert sess.aps_snapshot()[0].essid is None

    def test_hidden_then_disclosed_essid_is_promoted(self) -> None:
        # Hidden beacon arrives first; later a probe response discloses ESSID.
        # We model that by a subsequent beacon carrying a non-None ESSID
        # for the same BSSID.
        sess = Session()
        sess.handle_event(_beacon(essid=None, ts=100.0))
        sess.handle_event(_beacon(essid="HiddenRevealed", ts=101.0))

        assert sess.aps_snapshot()[0].essid == "HiddenRevealed"


class TestClientUpserts:
    def test_client_recorded_under_ap(self) -> None:
        sess = Session()
        sess.handle_event(_beacon())
        sess.handle_event(_client())

        clients = sess.clients_of("AA:BB:CC:DD:EE:01")
        assert len(clients) == 1
        assert clients[0].station == "11:22:33:44:55:66"
        assert clients[0].frames == 1

    def test_repeat_client_increments_frames(self) -> None:
        sess = Session()
        sess.handle_event(_beacon())
        sess.handle_event(_client(ts=100.0))
        sess.handle_event(_client(ts=101.0))

        client = sess.clients_of("AA:BB:CC:DD:EE:01")[0]
        assert client.frames == 2
        assert client.last_seen == 101.0

    def test_client_for_unseen_ap_is_buffered(self) -> None:
        # Client frames sometimes arrive before a beacon. Still record them.
        sess = Session()
        sess.handle_event(_client())

        clients = sess.clients_of("AA:BB:CC:DD:EE:01")
        assert len(clients) == 1


class TestChannelTracking:
    def test_channel_changed_event_updates_active_channel(self) -> None:
        sess = Session()
        sess.handle_event(ChannelChanged(timestamp=0.0, channel=11))

        assert sess.active_channel == 11


class TestEventBusIntegration:
    def test_session_subscribes_via_helper(self) -> None:
        bus = EventBus()
        sess = Session()
        sess.attach(bus)

        bus.publish(_beacon())
        bus.publish(_client())

        assert len(sess.aps_snapshot()) == 1
        assert len(sess.clients_of("AA:BB:CC:DD:EE:01")) == 1


class TestPersistence:
    def test_json_round_trip(self, tmp_path: Path) -> None:
        sess = Session()
        sess.handle_event(_beacon())
        sess.handle_event(_client())
        sess.handle_event(ChannelChanged(timestamp=0.0, channel=6))

        out = tmp_path / "sess.json"
        sess.dump_json(out)

        loaded = Session.load_json(out)
        assert len(loaded.aps_snapshot()) == 1
        assert loaded.aps_snapshot()[0].bssid == "AA:BB:CC:DD:EE:01"
        assert len(loaded.clients_of("AA:BB:CC:DD:EE:01")) == 1
        assert loaded.active_channel == 6


class TestHandshakeAndMfpFields:
    def test_handshake_complete_event_bumps_counter(self) -> None:
        from wlan_dumper.core.events import HandshakeComplete

        sess = Session()
        sess.handle_event(_beacon())
        sess.handle_event(
            HandshakeComplete(
                timestamp=200.0,
                bssid="AA:BB:CC:DD:EE:01",
                station="11:22:33:44:55:66",
                pcap_path="/tmp/x.pcap",
                hashcat_path=None,
                valid_by_hcxtool=True,
            )
        )

        ap = sess.aps_snapshot()[0]
        assert ap.handshake_count == 1

    def test_mfp_status_promoted_from_beacon(self) -> None:
        from wlan_dumper.core.events import BeaconSeen

        sess = Session()
        sess.handle_event(
            BeaconSeen(
                timestamp=1.0,
                bssid="AA:BB:CC:DD:EE:01",
                essid="Home",
                channel=6,
                encryption="WPA2-PSK",
                signal_dbm=-50,
                mfp_status="required",
            )
        )
        assert sess.aps_snapshot()[0].mfp_status == "required"

    def test_mfp_status_unknown_does_not_overwrite_known(self) -> None:
        from wlan_dumper.core.events import BeaconSeen

        sess = Session()
        sess.handle_event(
            BeaconSeen(
                timestamp=1.0, bssid="x", essid="x", channel=1,
                encryption="WPA2-PSK", signal_dbm=-50, mfp_status="required",
            )
        )
        sess.handle_event(
            BeaconSeen(
                timestamp=2.0, bssid="x", essid="x", channel=1,
                encryption="WPA2-PSK", signal_dbm=-50, mfp_status="unknown",
            )
        )
        assert sess.aps_snapshot()[0].mfp_status == "required"
