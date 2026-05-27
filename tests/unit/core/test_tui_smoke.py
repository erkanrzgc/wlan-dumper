"""Smoke tests for the Textual TUI.

Snapshot coverage (pytest-textual-snapshot) lands in a later phase; for now
we verify the app constructs, mounts, and renders rows from the session
without crashing. We rely on Textual's headless ``Pilot`` to drive the app.
"""

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
    bus = EventBus()
    app = ScanApp(session=sess, bus=bus, iface="wlan0mon", driver="ath9k_htc", mode="general")

    async with app.run_test() as pilot:
        # Trigger a refresh tick directly; set_interval would otherwise wait
        # _REFRESH_INTERVAL (250 ms), which makes the test slower than needed.
        app._tick()
        await pilot.pause()
        ap_table = app.query_one("#ap_dt")
        assert ap_table.row_count == 2


@pytest.mark.asyncio
async def test_sort_action_does_not_crash() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc", mode="lab")

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("f2")
        await pilot.press("f2")
        await pilot.pause()
        # Still has both rows after re-sort
        assert app.query_one("#ap_dt").row_count == 2


@pytest.mark.asyncio
async def test_pause_action_toggles_state() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc", mode="lab")

    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._paused is False
        await pilot.press("f5")
        await pilot.pause()
        assert app._paused is True
