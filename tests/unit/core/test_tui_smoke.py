"""Smoke tests for the Textual TUI."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from cyberm4fia_wifi.core.events import BeaconSeen, ClientSeen, EventBus  # noqa: E402
from cyberm4fia_wifi.core.session import Session  # noqa: E402
from cyberm4fia_wifi.tui.app import ScanApp  # noqa: E402


def _populate(session: Session) -> None:
    session.handle_event(
        BeaconSeen(
            timestamp=100.0,
            bssid="aa:bb:cc:dd:ee:01",
            essid="MyHome",
            channel=6,
            encryption="WPA2-PSK",
            signal_dbm=-42,
        )
    )
    session.handle_event(
        BeaconSeen(
            timestamp=100.0,
            bssid="aa:bb:cc:dd:ee:02",
            essid="Neighbour",
            channel=11,
            encryption="WPA2-PSK",
            signal_dbm=-67,
        )
    )
    session.handle_event(
        ClientSeen(
            timestamp=100.5,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            signal_dbm=-55,
        )
    )


@pytest.mark.asyncio
async def test_app_mounts_and_renders_rows() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    async with app.run_test() as pilot:
        # Trigger a refresh tick directly; set_interval would otherwise wait
        # _REFRESH_INTERVAL (250 ms), which makes the test slower than needed.
        app._tick()
        await pilot.pause()
        ap_table = app.query_one("#ap_dt")
        assert ap_table.row_count == 2


@pytest.mark.asyncio
async def test_client_panel_lists_stations_for_selected_ap() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    async with app.run_test() as pilot:
        app._selected_bssid = "aa:bb:cc:dd:ee:01"
        app._tick()
        await pilot.pause()

        client_table = app.query_one("#client_dt")
        assert client_table.row_count == 1
        row = client_table.get_row_at(0)
        station_cell = getattr(row[0], "plain", str(row[0]))
        assert "11:22:33:44:55:66" in station_cell


def test_log_line_for_client() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    app._log_event(
        ClientSeen(
            timestamp=100.5,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            signal_dbm=-55,
        )
    )

    line = app._log_queue.get_nowait()
    # "STA" tag + station MAC + the resolved ESSID label of the AP
    assert "STA" in line
    assert "11:22:33:44:55:66" in line
    assert "MyHome" in line


def test_beacon_logged_once_per_new_ap() -> None:
    """Beacon spam (10/sec per AP) is dampened — only the first beacon for a
    new BSSID writes a log line; the next ones are dropped until the AP's
    beacon_count reaches the next multiple of _BEACON_LOG_EVERY."""
    sess = Session()
    bus = EventBus()
    app = ScanApp(session=sess, bus=bus, iface="wlan0mon", driver="ath9k_htc")

    beacon = BeaconSeen(
        timestamp=100.0,
        bssid="aa:bb:cc:dd:ee:01",
        essid="MyHome",
        channel=6,
        encryption="WPA2-PSK",
        signal_dbm=-42,
    )
    sess.handle_event(beacon)
    app._log_event(beacon)
    assert app._log_queue.qsize() == 1

    # Two more beacons → no extra log lines (still rate-limited).
    for _ in range(2):
        sess.handle_event(beacon)
        app._log_event(beacon)
    assert app._log_queue.qsize() == 1


@pytest.mark.asyncio
async def test_sort_action_does_not_crash() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("f2")
        await pilot.press("f2")
        await pilot.pause()
        assert app.query_one("#ap_dt").row_count == 2


@pytest.mark.asyncio
async def test_pause_action_toggles_state() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._paused is False
        await pilot.press("f5")
        await pilot.pause()
        assert app._paused is True


@pytest.mark.asyncio
async def test_d_and_h_bindings_present() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")

    async with app.run_test() as pilot:
        await pilot.pause()
        keys = {b.key for b in app.BINDINGS}
        assert "d" in keys
        assert "h" in keys


@pytest.mark.asyncio
async def test_ap_details_shows_mfp_and_handshake_count() -> None:
    sess = Session()
    from cyberm4fia_wifi.core.events import BeaconSeen, HandshakeComplete

    sess.handle_event(
        BeaconSeen(
            timestamp=100.0,
            bssid="aa:bb:cc:dd:ee:01",
            essid="MyHome",
            channel=6,
            encryption="WPA2-PSK",
            signal_dbm=-42,
            mfp_status="required",
        )
    )
    sess.handle_event(
        HandshakeComplete(
            timestamp=101.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            pcap_path="/tmp/x.pcap",
            hashcat_path=None,
            valid_by_hcxtool=True,
        )
    )

    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc")
    async with app.run_test() as pilot:
        app._selected_bssid = "aa:bb:cc:dd:ee:01"
        app._tick()
        await pilot.pause()
        text = str(app.query_one("#details").render())
        assert "MFP" in text
        assert "required" in text
        assert "Hands." in text  # short label for the handshakes row
        assert "1" in text
