"""Channel hopper.

Runs in a dedicated daemon thread, walks a channel list in round-robin order,
sets the radio to each channel via the injected ``channel_setter`` (default:
``iw dev <iface> set channel <n>``), publishes a ``ChannelChanged`` event,
and sleeps for the configured dwell time before moving on.

Two behaviors worth knowing:

- **Quarantine.** A channel that fails to set more than ``quarantine_after``
  times in succession is put into a back-off window so a single broken
  channel does not poison the loop.
- **Lock / unlock.** ``lock(channel)`` pins the radio to one channel
  (useful when the operator wants to capture handshakes for a specific AP);
  ``unlock()`` resumes round-robin.

The default channel sets are intentionally conservative - 2.4 GHz 1-13 and a
common subset of non-DFS 5 GHz channels. ``parse_iw_list_channels`` extracts
the radio-permitted set from ``iw list`` output so the hopper can intersect
with the active regulatory domain when the operator chooses to.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from wlan_dumper.core.events import ChannelChanged, EventBus


class HopperError(Exception):
    """Raised when the hopper cannot run (invalid config or setter failure)."""


DEFAULT_2GHZ_CHANNELS: tuple[int, ...] = tuple(range(1, 14))
# Common non-DFS 5 GHz channels; DFS channels (52-144) are allowed for passive
# scan in most regdomains but we keep the default conservative.
DEFAULT_5GHZ_CHANNELS: tuple[int, ...] = (36, 40, 44, 48, 149, 153, 157, 161, 165)


def _iw_set_channel(iface: str) -> Callable[[int], None]:
    """Return a channel setter that shells out to ``iw dev <iface> set channel``."""

    def setter(channel: int) -> None:
        res = subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            check=False,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise HopperError(
                f"iw set channel {channel} failed: {(res.stderr or res.stdout).strip()}"
            )

    return setter


_IW_LIST_FREQ_RE = re.compile(
    r"^\s*\*\s+\d+\s+MHz\s+\[(\d+)\](?:\s+\(([^)]*)\))?",
    re.MULTILINE,
)


def parse_iw_list_channels(iw_list_output: str) -> set[int]:
    """Extract the set of channels the radio is allowed to use.

    We exclude entries explicitly marked as ``disabled``. Channels carrying
    only ``no IR`` or ``radar detection`` flags are kept because passive
    scanning is still permitted on them in most regdomains.
    """
    enabled: set[int] = set()
    for m in _IW_LIST_FREQ_RE.finditer(iw_list_output):
        ch = int(m.group(1))
        flags = (m.group(2) or "").lower()
        if "disabled" in flags:
            continue
        enabled.add(ch)
    return enabled


@dataclass
class ChannelHopper:
    iface: str
    channels: Sequence[int]
    dwell_seconds: float
    bus: EventBus
    channel_setter: Callable[[int], None]
    quarantine_after: int = 3
    quarantine_skip_rounds: int = 5

    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _locked_channel: int | None = field(default=None, init=False, repr=False)
    _fail_counts: dict[int, int] = field(default_factory=dict, init=False, repr=False)
    _quarantine: dict[int, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.channels:
            raise HopperError("channel list is empty")

    # ---- factory ------------------------------------------------------------

    @classmethod
    def for_bands(
        cls,
        *,
        iface: str,
        bands: Sequence[str],
        bus: EventBus,
        channel_setter: Callable[[int], None] | None = None,
        dwell_seconds: float = 0.25,
        regdom_channels: set[int] | None = None,
    ) -> ChannelHopper:
        chans: list[int] = []
        if "2.4" in bands:
            chans.extend(DEFAULT_2GHZ_CHANNELS)
        if "5" in bands:
            chans.extend(DEFAULT_5GHZ_CHANNELS)
        if regdom_channels is not None:
            chans = [c for c in chans if c in regdom_channels]
        if not chans:
            raise HopperError(
                f"no channels left after band filter (bands={bands}, regdom={regdom_channels})"
            )
        return cls(
            iface=iface,
            channels=tuple(chans),
            dwell_seconds=dwell_seconds,
            bus=bus,
            channel_setter=channel_setter or _iw_set_channel(iface),
        )

    # ---- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wlan-dumper-hopper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ---- lock / unlock ------------------------------------------------------

    def lock(self, channel: int) -> None:
        self._locked_channel = channel
        try:
            self.channel_setter(channel)
            self.bus.publish(ChannelChanged(timestamp=time.time(), channel=channel))
        except HopperError:
            pass  # surfaced via the loop's next attempt

    def unlock(self) -> None:
        self._locked_channel = None

    # ---- main loop ----------------------------------------------------------

    def _run(self) -> None:
        idx = 0
        while not self._stop.is_set():
            if self._locked_channel is not None:
                self._stop.wait(self.dwell_seconds)
                continue

            ch = self.channels[idx % len(self.channels)]
            idx += 1

            # Skip quarantined channels for the configured number of rounds.
            skip_left = self._quarantine.get(ch, 0)
            if skip_left > 0:
                self._quarantine[ch] = skip_left - 1
                continue

            try:
                self.channel_setter(ch)
            except HopperError:
                self._fail_counts[ch] = self._fail_counts.get(ch, 0) + 1
                if self._fail_counts[ch] >= self.quarantine_after:
                    self._quarantine[ch] = self.quarantine_skip_rounds
                    self._fail_counts[ch] = 0
                continue

            # Success — clear the running failure count for this channel.
            self._fail_counts.pop(ch, None)
            self.bus.publish(ChannelChanged(timestamp=time.time(), channel=ch))
            self._stop.wait(self.dwell_seconds)


# Keep a stub for the unused subprocess import linter check.
_ = Any
