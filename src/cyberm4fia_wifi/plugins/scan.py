"""Scan plugin — the only plugin in Phase 1.

Wires the core engine and the TUI together for a live 802.11 scan. Selects an
adapter, enters monitor mode, starts the hopper and sniffer, mounts the
Textual app, and on exit tears everything down in reverse.

The plugin is intentionally thin: every interesting unit (adapter management,
hopping, sniffing, state) lives in ``core/`` and is tested there. This module
is the orchestration glue and the surface the CLI binds to.
"""

from __future__ import annotations

import sys
from typing import Any

import click

from cyberm4fia_wifi.core.adapter import AdapterManager, DetectedAdapter, detect_adapters
from cyberm4fia_wifi.core.auth import PluginRisk
from cyberm4fia_wifi.core.events import EventBus
from cyberm4fia_wifi.core.hopper import ChannelHopper
from cyberm4fia_wifi.core.session import Session
from cyberm4fia_wifi.core.sniffer import Sniffer
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.tui.app import ScanApp


def pick_adapter(adapters: list[DetectedAdapter], preferred_iface: str | None) -> DetectedAdapter:
    """Return the adapter that matches ``preferred_iface`` or the first one found."""
    if not adapters:
        raise click.ClickException(
            "no wireless adapters detected — is the radio plugged in and "
            "is the driver loaded? (try: dmesg | tail)"
        )
    if preferred_iface:
        for a in adapters:
            if a.iface == preferred_iface:
                return a
        raise click.ClickException(
            f"requested --iface {preferred_iface!r} not found; "
            f"available: {[a.iface for a in adapters]}"
        )
    if len(adapters) == 1:
        return adapters[0]
    # Multiple adapters present: prefer one with injection over generic.
    with_injection = [a for a in adapters if a.profile.injection]
    return (with_injection or adapters)[0]


class ScanPlugin(Plugin):
    name = "scan"
    risk = PluginRisk.PASSIVE
    requires_injection = False

    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Live 802.11 scan + TUI (passive)")
        @click.pass_context
        def scan_cmd(ctx: click.Context) -> None:
            from cyberm4fia_wifi.cli import build_runtime_for

            runtime = build_runtime_for(ctx)
            plugin_ctx = PluginContext(
                session=runtime.session,
                bus=runtime.bus,
                adapter=runtime.adapter,
                gate=runtime.gate,
                cli_args=dict(ctx.obj or {}),
            )
            sys.exit(self.run(plugin_ctx))

    def run(self, ctx: PluginContext) -> int:
        # Authorization (passive: always allowed; not logged).
        ctx.gate.check(plugin=self.name, risk=self.risk, target=None, reason=None)

        adapter_mgr = AdapterManager(iface=ctx.adapter.iface, profile=ctx.adapter.profile)
        try:
            mon_iface = adapter_mgr.enter_monitor_mode()
        except Exception as exc:  # noqa: BLE001 — surface as a clean CLI error
            raise click.ClickException(f"could not enter monitor mode: {exc}") from exc

        # Wire bus -> session.
        ctx.session.attach(ctx.bus)

        # Channel hopper across whatever bands the adapter supports.
        hopper = ChannelHopper.for_bands(
            iface=mon_iface,
            bands=ctx.adapter.profile.bands,
            bus=ctx.bus,
        )

        sniffer = Sniffer(iface=mon_iface, bus=ctx.bus)

        hopper.start()
        sniffer.start()

        app = ScanApp(
            session=ctx.session,
            bus=ctx.bus,
            hopper=hopper,
            iface=mon_iface,
            driver=ctx.adapter.profile.driver,
            mode=ctx.cli_args.get("mode") or _mode_label(ctx.gate),
        )
        try:
            app.run()
        finally:
            sniffer.stop()
            hopper.stop()
            adapter_mgr.restore()
        return 0


def _mode_label(gate: Any) -> str:
    try:
        return gate.config.mode.value
    except Exception:  # noqa: BLE001 — pre-acknowledgment runs
        return "?"


# Public, eagerly-instantiated registry. Phase 2 swaps this for entry-points.
REGISTRY: list[Plugin] = [ScanPlugin()]
