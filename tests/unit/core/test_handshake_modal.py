"""Smoke tests for the HandshakeModal."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402

from cyberm4fia_wifi.tui.modals import HandshakeModal  # noqa: E402


class _Harness(App):
    def __init__(
        self, ap_bssid: str, clients: list[str], mfp: str, mode: str = "general"
    ) -> None:
        super().__init__()
        self._ap_bssid = ap_bssid
        self._clients = clients
        self._mfp = mfp
        self._mode = mode

    def on_mount(self) -> None:
        self.push_screen(
            HandshakeModal(
                ap_bssid=self._ap_bssid,
                ap_essid="MyHome",
                ap_channel=6,
                clients=self._clients,
                mfp_status=self._mfp,
                mode=self._mode,
            )
        )


@pytest.mark.asyncio
async def test_general_mode_blocks_start_when_reason_empty() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", ["11:22:33:44:55:66"], "none", mode="general")
    async with app.run_test() as pilot:
        await pilot.pause()
        start = app.screen.query_one("#start_btn")
        assert start.disabled is True
        assert app.screen.query("#reason_input")  # field is present


@pytest.mark.asyncio
async def test_lab_mode_skips_reason_and_enables_start() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", ["11:22:33:44:55:66"], "none", mode="lab")
    async with app.run_test() as pilot:
        await pilot.pause()
        start = app.screen.query_one("#start_btn")
        assert start.disabled is False
        assert not app.screen.query("#reason_input")  # no prompt in lab mode


@pytest.mark.asyncio
async def test_modal_warns_when_mfp_required() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", [], "required", mode="lab")
    async with app.run_test() as pilot:
        await pilot.pause()
        warning = app.screen.query_one("#mfp_warn")
        assert "required" in warning.classes
        assert app.screen.query_one("#mfp_override") is not None
