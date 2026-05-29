"""Tests for the channel hopper."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable

import pytest

from wlan_dumper.core.events import ChannelChanged, EventBus
from wlan_dumper.core.hopper import (
    DEFAULT_2GHZ_CHANNELS,
    DEFAULT_5GHZ_CHANNELS,
    ChannelHopper,
    HopperError,
    parse_iw_list_channels,
)

_IW_LIST_FIXTURE = """\
Wiphy phy0
\tmax # scan SSIDs: 4
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412 MHz [1] (20.0 dBm)
\t\t\t* 2417 MHz [2] (20.0 dBm)
\t\t\t* 2462 MHz [11] (20.0 dBm)
\t\t\t* 2467 MHz [12] (disabled)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180 MHz [36] (20.0 dBm)
\t\t\t* 5200 MHz [40] (20.0 dBm)
\t\t\t* 5260 MHz [52] (no IR, radar detection)
"""


class TestRegdomParsing:
    def test_extracts_enabled_channels_only(self) -> None:
        channels = parse_iw_list_channels(_IW_LIST_FIXTURE)
        assert 1 in channels
        assert 11 in channels
        assert 36 in channels
        assert 40 in channels
        assert 12 not in channels  # disabled
        # "no IR" / "radar" channels are allowed for passive scan, so we keep 52
        assert 52 in channels


class _FakeSetter:
    """Records channel-set calls and lets us simulate failures."""

    def __init__(self, fail_channels: Iterable[int] = ()) -> None:
        self.calls: list[int] = []
        self._fail = set(fail_channels)
        self._lock = threading.Lock()

    def __call__(self, channel: int) -> None:
        with self._lock:
            self.calls.append(channel)
        if channel in self._fail:
            raise HopperError(f"simulated failure on ch{channel}")


class TestRoundRobin:
    def test_round_robin_order(self) -> None:
        bus = EventBus()
        events: list[ChannelChanged] = []
        bus.subscribe(ChannelChanged, events.append)

        setter = _FakeSetter()
        hopper = ChannelHopper(
            iface="wlan0mon",
            channels=[1, 6, 11],
            dwell_seconds=0.01,
            bus=bus,
            channel_setter=setter,
        )

        hopper.start()
        time.sleep(0.1)  # ~10 hops
        hopper.stop()

        # We should have visited each channel multiple times in order.
        # Drop trailing duplicates that may appear during shutdown.
        ordered = setter.calls[:9]
        assert ordered == [1, 6, 11, 1, 6, 11, 1, 6, 11]
        assert len(events) >= 9

    def test_band_filter_restricts_channel_set(self) -> None:
        hopper = ChannelHopper.for_bands(
            iface="wlan0mon",
            bands=("2.4",),
            bus=EventBus(),
            channel_setter=lambda _ch: None,
        )
        # No 5GHz channels permitted when only 2.4 is requested
        assert all(ch in DEFAULT_2GHZ_CHANNELS for ch in hopper.channels)
        assert not set(hopper.channels) & set(DEFAULT_5GHZ_CHANNELS)

    def test_dual_band_includes_both(self) -> None:
        hopper = ChannelHopper.for_bands(
            iface="wlan0mon",
            bands=("2.4", "5"),
            bus=EventBus(),
            channel_setter=lambda _ch: None,
        )
        assert set(hopper.channels) >= set(DEFAULT_2GHZ_CHANNELS[:3])
        assert any(ch in DEFAULT_5GHZ_CHANNELS for ch in hopper.channels)


class TestQuarantine:
    def test_repeatedly_failing_channel_is_quarantined(self) -> None:
        setter = _FakeSetter(fail_channels={11})
        hopper = ChannelHopper(
            iface="wlan0mon",
            channels=[1, 6, 11],
            dwell_seconds=0.01,
            bus=EventBus(),
            channel_setter=setter,
            quarantine_after=2,
        )

        hopper.start()
        time.sleep(0.2)
        hopper.stop()

        # After two failures the hopper should stop trying channel 11 within
        # the back-off window. Count attempts on 11 vs 1/6.
        fails = sum(1 for c in setter.calls if c == 11)
        ones = sum(1 for c in setter.calls if c == 1)
        # Far fewer attempts on the quarantined channel than on healthy ones.
        assert fails <= ones // 2 + 2


class TestLockUnlock:
    def test_lock_pins_to_single_channel(self) -> None:
        setter = _FakeSetter()
        hopper = ChannelHopper(
            iface="wlan0mon",
            channels=[1, 6, 11],
            dwell_seconds=0.01,
            bus=EventBus(),
            channel_setter=setter,
        )

        hopper.start()
        time.sleep(0.05)
        hopper.lock(6)
        before = len(setter.calls)
        time.sleep(0.1)
        after = len(setter.calls)
        hopper.stop()

        # While locked, no new channel sets should happen.
        assert after == before or all(c == 6 for c in setter.calls[before:after])

    def test_unlock_resumes_hopping(self) -> None:
        setter = _FakeSetter()
        hopper = ChannelHopper(
            iface="wlan0mon",
            channels=[1, 6, 11],
            dwell_seconds=0.01,
            bus=EventBus(),
            channel_setter=setter,
        )

        hopper.start()
        hopper.lock(6)
        time.sleep(0.05)
        locked_count = len(setter.calls)
        hopper.unlock()
        time.sleep(0.1)
        hopper.stop()

        # After unlock the hopper visits other channels again.
        post = setter.calls[locked_count:]
        assert any(c != 6 for c in post)


class TestValidation:
    def test_empty_channel_list_rejected(self) -> None:
        with pytest.raises(HopperError):
            ChannelHopper(
                iface="wlan0mon",
                channels=[],
                dwell_seconds=0.1,
                bus=EventBus(),
                channel_setter=lambda _ch: None,
            )
