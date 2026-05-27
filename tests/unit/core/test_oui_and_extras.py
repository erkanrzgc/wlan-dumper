"""Tests for the OUI lookup helper and the new Beacon/Session metadata."""

from __future__ import annotations

from cyberm4fia_wifi.core.events import BeaconSeen, ClientSeen
from cyberm4fia_wifi.core.session import Session
from cyberm4fia_wifi.utils.oui import is_locally_administered, oui_for


class TestOuiLookup:
    def test_known_vendor_resolves(self) -> None:
        assert oui_for("80:af:ca:27:b0:78") == "Cudy"
        assert oui_for("80afca27b078") == "Cudy"
        assert oui_for("F8:1A:67:7E:CC:36") == "TP-Link"

    def test_unknown_oui_returns_none(self) -> None:
        assert oui_for("ff:ff:ff:00:00:00") is None

    def test_empty_input_safe(self) -> None:
        assert oui_for("") is None
        assert oui_for("ab") is None

    def test_locally_administered_bit(self) -> None:
        # Bit 0x02 of the first octet → randomized MAC.
        assert is_locally_administered("02:00:00:00:00:01") is True
        assert is_locally_administered("aa:bb:cc:dd:ee:ff") is True
        assert is_locally_administered("80:af:ca:00:00:00") is False


def _beacon(bssid: str, *, wps: bool = False, interval_ms: int = 102) -> BeaconSeen:
    return BeaconSeen(
        timestamp=100.0,
        bssid=bssid,
        essid="Home",
        channel=6,
        encryption="WPA2-PSK",
        signal_dbm=-50,
        wps=wps,
        beacon_interval_ms=interval_ms,
    )


class TestBeaconExtraFields:
    def test_wps_and_interval_default_to_safe_values(self) -> None:
        evt = BeaconSeen(
            timestamp=0.0,
            bssid="x",
            essid=None,
            channel=1,
            encryption="OPEN",
            signal_dbm=-90,
        )
        assert evt.wps is False
        assert evt.beacon_interval_ms == 0


class TestSessionPropagatesNewFields:
    def test_wps_persists_after_a_beacon_without_it(self) -> None:
        sess = Session()
        sess.handle_event(_beacon("aa:bb:cc:dd:ee:01", wps=True))
        sess.handle_event(_beacon("aa:bb:cc:dd:ee:01", wps=False))

        ap = sess.aps_snapshot()[0]
        assert ap.wps is True  # sticky

    def test_beacon_interval_persists_and_updates(self) -> None:
        sess = Session()
        sess.handle_event(_beacon("aa:bb:cc:dd:ee:01", interval_ms=102))
        sess.handle_event(_beacon("aa:bb:cc:dd:ee:01", interval_ms=200))

        ap = sess.aps_snapshot()[0]
        assert ap.beacon_interval_ms == 200

    def test_client_seen_bumps_ap_data_count(self) -> None:
        sess = Session()
        sess.handle_event(_beacon("aa:bb:cc:dd:ee:01"))
        for _ in range(5):
            sess.handle_event(
                ClientSeen(
                    timestamp=101.0,
                    bssid="aa:bb:cc:dd:ee:01",
                    station="11:22:33:44:55:66",
                    signal_dbm=-55,
                )
            )

        ap = sess.aps_snapshot()[0]
        assert ap.data_count == 5

    def test_client_without_known_ap_does_not_crash(self) -> None:
        sess = Session()
        sess.handle_event(
            ClientSeen(
                timestamp=101.0,
                bssid="unknown",
                station="11:22:33:44:55:66",
                signal_dbm=-55,
            )
        )
        # No AP was registered → no data_count bump, but the client itself
        # is still recorded for later promotion when a beacon arrives.
        assert sess.aps_snapshot() == []
        assert len(sess.clients_of("unknown")) == 1
