"""Smoke tests for the HandshakeModal."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.app import App

from wlan_dumper.tui.modals import HandshakeModal


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


def test_positive_int_falls_back_on_garbage() -> None:
    from wlan_dumper.tui.modals import _positive_int

    assert _positive_int("8", default=99) == 8
    assert _positive_int("", default=99) == 99
    assert _positive_int(None, default=99) == 99
    assert _positive_int("-3", default=99) == 99  # negative → fallback
    assert _positive_int("0", default=99) == 99  # zero → fallback
    assert _positive_int("abc", default=99) == 99  # type='integer' filters this anyway
    assert _positive_int(" 12 ", default=99) == 12
