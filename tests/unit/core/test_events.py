"""Tests for the core event bus."""

from __future__ import annotations

import threading

import pytest

from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ChannelChanged,
    ClientSeen,
    EventBus,
    ProbeSeen,
)


def _make_beacon(bssid: str = "AA:BB:CC:DD:EE:01") -> BeaconSeen:
    return BeaconSeen(
        bssid=bssid,
        essid="MyHome",
        channel=6,
        encryption="WPA2-PSK",
        signal_dbm=-42,
        timestamp=0.0,
    )


class TestEventBusBasics:
    def test_subscribe_and_publish_invokes_handler(self) -> None:
        bus = EventBus()
        received: list[BeaconSeen] = []
        bus.subscribe(BeaconSeen, received.append)

        evt = _make_beacon()
        bus.publish(evt)

        assert received == [evt]

    def test_unsubscribe_stops_delivery(self) -> None:
        bus = EventBus()
        received: list[BeaconSeen] = []
        bus.subscribe(BeaconSeen, received.append)
        bus.unsubscribe(BeaconSeen, received.append)

        bus.publish(_make_beacon())

        assert received == []

    def test_type_specific_subscription(self) -> None:
        bus = EventBus()
        beacons: list[BeaconSeen] = []
        clients: list[ClientSeen] = []
        bus.subscribe(BeaconSeen, beacons.append)
        bus.subscribe(ClientSeen, clients.append)

        bus.publish(_make_beacon())

        assert len(beacons) == 1
        assert clients == []

    def test_multiple_subscribers_all_called(self) -> None:
        bus = EventBus()
        a: list[BeaconSeen] = []
        b: list[BeaconSeen] = []
        bus.subscribe(BeaconSeen, a.append)
        bus.subscribe(BeaconSeen, b.append)

        evt = _make_beacon()
        bus.publish(evt)

        assert a == [evt]
        assert b == [evt]


class TestEventBusErrorIsolation:
    def test_handler_exception_does_not_affect_other_handlers(self) -> None:
        bus = EventBus()
        survivor: list[BeaconSeen] = []

        def boom(_evt: BeaconSeen) -> None:
            raise RuntimeError("subscriber failure")

        bus.subscribe(BeaconSeen, boom)
        bus.subscribe(BeaconSeen, survivor.append)

        bus.publish(_make_beacon())

        assert len(survivor) == 1

    def test_handler_exceptions_are_collected(self) -> None:
        bus = EventBus()

        def boom(_evt: BeaconSeen) -> None:
            raise RuntimeError("x")

        bus.subscribe(BeaconSeen, boom)
        errors = bus.publish(_make_beacon())

        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)


class TestEventBusThreadSafety:
    def test_concurrent_publish_does_not_lose_events(self) -> None:
        bus = EventBus()
        received: list[BeaconSeen] = []
        lock = threading.Lock()

        def handler(evt: BeaconSeen) -> None:
            with lock:
                received.append(evt)

        bus.subscribe(BeaconSeen, handler)

        def worker(n: int) -> None:
            for _ in range(n):
                bus.publish(_make_beacon())

        threads = [threading.Thread(target=worker, args=(50,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 200


class TestEventDataclasses:
    def test_beacon_seen_is_frozen(self) -> None:
        evt = _make_beacon()
        with pytest.raises(AttributeError):
            evt.bssid = "ZZ"  # type: ignore[misc]

    def test_channel_changed_carries_channel_only(self) -> None:
        evt = ChannelChanged(channel=11, timestamp=1.0)
        assert evt.channel == 11

    def test_probe_seen_records_essid_optional(self) -> None:
        evt = ProbeSeen(
            station="11:22:33:44:55:66",
            essid=None,
            signal_dbm=-60,
            timestamp=0.0,
        )
        assert evt.essid is None


class TestPhase2EventDataclasses:
    def test_deauth_sent_carries_burst_position(self) -> None:
        from cyberm4fia_wifi.core.events import DeauthSent

        evt = DeauthSent(
            timestamp=1.0,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            sequence=3,
            total=8,
        )
        assert evt.sequence == 3
        assert evt.total == 8

    def test_deauth_sent_allows_broadcast(self) -> None:
        from cyberm4fia_wifi.core.events import DeauthSent

        evt = DeauthSent(
            timestamp=1.0,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station=None,
            sequence=1,
            total=5,
        )
        assert evt.target_station is None

    def test_eapol_capture_carries_raw_bytes_and_optional_index(self) -> None:
        from cyberm4fia_wifi.core.events import EAPOLCapture

        evt = EAPOLCapture(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            message_index=2,
            raw=b"\x00\x01\x02",
        )
        assert evt.message_index == 2
        assert evt.raw == b"\x00\x01\x02"

    def test_eapol_capture_message_index_may_be_none(self) -> None:
        from cyberm4fia_wifi.core.events import EAPOLCapture

        evt = EAPOLCapture(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            message_index=None,
            raw=b"",
        )
        assert evt.message_index is None

    def test_handshake_complete_carries_artifact_paths(self) -> None:
        from cyberm4fia_wifi.core.events import HandshakeComplete

        evt = HandshakeComplete(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            pcap_path="/tmp/x.pcap",
            hashcat_path="/tmp/x.22000",
            valid_by_hcxtool=True,
        )
        assert evt.hashcat_path == "/tmp/x.22000"
        assert evt.valid_by_hcxtool is True
