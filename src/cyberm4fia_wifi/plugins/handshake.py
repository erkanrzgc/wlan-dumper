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

import click

from cyberm4fia_wifi.core.auth import AuthorizationGate, PluginRisk
from cyberm4fia_wifi.core.events import (
    EAPOLCapture,
    EventBus,
    HandshakeComplete,
)
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin
from cyberm4fia_wifi.utils.hcxtools import convert_to_22000
from cyberm4fia_wifi.utils.paths import handshake_path
from cyberm4fia_wifi.utils.pcap_writer import append_packets


class HandshakePlugin(Plugin):
    name = "handshake"
    risk = PluginRisk.ACTIVE
    requires_injection = False  # auto-deauth elevates this at call time

    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._target_bssid: str | None = None
        self._target_station: str | None = None
        self._pcap_path: Path | None = None
        self._state: set[int] = set()
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
            "--note", default=None,
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
            from cyberm4fia_wifi.cli import build_runtime_for  # noqa: PLC0415

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
            bus=bus, gate=gate, iface=iface,
            target_bssid=target_bssid,
            target_station=target_station,
            essid=essid, reason=reason,
        )

        try:
            if auto_deauth:
                DeauthPlugin().execute(
                    bus=bus, gate=gate, iface=iface,
                    target_bssid=target_bssid,
                    target_station=target_station,
                    count=deauth_count, reason=reason,
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
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        essid: str | None,
        reason: str | None = None,
    ) -> None:
        self._bus = bus
        self._target_bssid = target_bssid.lower()
        self._target_station = target_station.lower() if target_station else None
        self._pcap_path = handshake_path(essid, target_bssid)
        self._state = set()
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
        # useful.
        import scapy.all as s  # noqa: PLC0415

        try:
            wrapped = s.Ether(evt.raw)
        except Exception:  # noqa: BLE001 — fall back to raw bytes if scapy chokes
            wrapped = s.Raw(load=evt.raw)
        append_packets(self._pcap_path, [wrapped])

        if evt.message_index is not None:
            self._state.add(evt.message_index)

        # Validate once we have at least M1+M2 (sufficient for crack).
        if {1, 2}.issubset(self._state):
            hashcat = convert_to_22000(self._pcap_path)
            valid = hashcat is not None or {1, 2, 3, 4}.issubset(self._state)
            if valid:
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

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI uses execute()
        raise NotImplementedError("call HandshakePlugin.execute(...) directly")
