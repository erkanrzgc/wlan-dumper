"""Smoke tests for the HandshakeModal."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402

from cyberm4fia_wifi.tui.modals import HandshakeModal  # noqa: E402


class _Harness(App):
    def __init__(self, ap_bssid: str, clients: list[str], mfp: str) -> None:
        super().__init__()
        self._ap_bssid = ap_bssid
        self._clients = clients
        self._mfp = mfp

    def on_mount(self) -> None:
        self.push_screen(
            HandshakeModal(
                ap_bssid=self._ap_bssid,
                ap_essid="MyHome",
                ap_channel=6,
                clients=self._clients,
                mfp_status=self._mfp,
            )
        )


@pytest.mark.asyncio
async def test_modal_opens_with_start_enabled() -> None:
    """No mode system → no reason prompt → Start is enabled immediately."""
    app = _Harness("aa:bb:cc:dd:ee:01", ["11:22:33:44:55:66"], "none")
    async with app.run_test() as pilot:
        await pilot.pause()
        start = app.screen.query_one("#start_btn")
        assert start.disabled is False


@pytest.mark.asyncio
async def test_modal_has_no_reason_field() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", ["11:22:33:44:55:66"], "none")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert not app.screen.query("#reason_input")


@pytest.mark.asyncio
async def test_modal_warns_when_mfp_required() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", [], "required")
    async with app.run_test() as pilot:
        await pilot.pause()
        warning = app.screen.query_one("#mfp_warn")
        assert "required" in warning.classes
        assert app.screen.query_one("#mfp_override") is not None
