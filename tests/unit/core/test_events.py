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
