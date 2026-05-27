"""Scan plugin — the only plugin in Phase 1.

Wires the core engine and the TUI together for a live 802.11 scan. Selects an
adapter, enters monitor mode, starts the hopper and sniffer, mounts the
Textual app, and on exit tears everything down in reverse.

The plugin is intentionally thin: every interesting unit (adapter management,
hopping, sniffing, state) lives in ``core/`` and is tested there. This module
is the orchestration glue and the surface the CLI binds to.
"""

from __future__ import annotations

import contextlib
import sys
from typing import Any, ClassVar

import click
from rich.text import Text

from cyberm4fia_wifi.core.adapter import AdapterManager, DetectedAdapter
from cyberm4fia_wifi.core.auth import PluginRisk
from cyberm4fia_wifi.core.hopper import ChannelHopper
from cyberm4fia_wifi.core.sniffer import Sniffer
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.tui.app import ScanApp


def pick_adapter(adapters: list[DetectedAdapter], preferred_iface: str | None) -> DetectedAdapter:
    """Non-interactive selection — used by tests and by the auto-pick path."""
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
    with_injection = [a for a in adapters if a.profile.injection]
    return (with_injection or adapters)[0]


def interactive_pick_adapter(
    adapters: list[DetectedAdapter],
    preferred_iface: str | None,
    *,
    stdin: Any = None,
    stdout: Any = None,
) -> DetectedAdapter:
    """Ask the operator which adapter to use when more than one is present.

    Explicit ``--iface`` always wins. In an interactive terminal, scan startup
    always shows a picker before monitor mode is touched; non-TTY callers keep
    the old behavior (single adapter auto-picks, multiple adapters use a
    numbered prompt).
    """
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
    if _is_tty(stdin or sys.stdin) and _is_tty(stdout or sys.stdout):
        return _pick_adapter_tui(adapters)

    if len(adapters) == 1:
        return adapters[0]

    out = stdout or sys.stdout
    inp = stdin or sys.stdin
    print("\nMultiple wireless adapters detected — pick one:\n", file=out)
    for i, a in enumerate(adapters, start=1):
        bands = "+".join(a.profile.bands)
        inj = "inject" if a.profile.injection else "no inject"
        unverified = " (unverified)" if a.profile.injection_unverified else ""
        print(
            f"  [{i}] {a.iface:8s}  {a.profile.name:12s}  "
            f"driver={a.profile.driver:10s}  bands={bands:5s}  {inj}{unverified}",
            file=out,
        )
    print(file=out)
    out.write(f"Choice [1-{len(adapters)}, default 1]: ")
    out.flush()
    raw = inp.readline().strip()
    if not raw:
        return adapters[0]
    try:
        idx = int(raw)
    except ValueError as exc:
        raise click.ClickException(f"not a number: {raw!r}") from exc
    if not 1 <= idx <= len(adapters):
        raise click.ClickException(f"choice {idx} out of range [1-{len(adapters)}]")
    return adapters[idx - 1]


def _is_tty(stream: Any) -> bool:
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _pick_adapter_tui(adapters: list[DetectedAdapter]) -> DetectedAdapter:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal
    from textual.widgets import Button, DataTable, Footer, Header, Static

    class AdapterPickerApp(App[int | None]):
        TITLE = "cyberm4fia-wifi"
        SUB_TITLE = "pick wireless interface"
        BINDINGS: ClassVar[list[Binding]] = [
            Binding("enter", "start", "Start scan"),
            Binding("q,escape", "cancel", "Cancel"),
        ]
        # No theme — let the terminal palette show through.
        CSS = """
        Screen { layout: vertical; }
        #hint { height: 3; padding: 0 1; }
        #adapter_dt { height: 1fr; }
        #buttons { height: 3; align: right middle; padding: 0 1; }
        #buttons Button { margin-left: 1; }
        """

        def __init__(self) -> None:
            super().__init__()
            self._chosen_idx: int = 0

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            yield Static(
                "Pick the wireless interface to scan with. ↑↓ to move, "
                "Enter or [Start scan] to begin, q to cancel.",
                id="hint",
            )
            table = DataTable[str](zebra_stripes=True, cursor_type="row", id="adapter_dt")
            table.add_columns("Interface", "Chipset", "Driver", "Bands", "Injection")
            yield table
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button("Start scan", id="start_btn", variant="primary")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#adapter_dt", DataTable)
            for idx, adapter in enumerate(adapters):
                profile = adapter.profile
                injection = "yes" if profile.injection else "no"
                if profile.injection_unverified:
                    injection = f"{injection}?"
                table.add_row(
                    Text(adapter.iface, style="cyan"),
                    Text(profile.name),
                    Text(profile.driver, style="dim"),
                    Text("+".join(profile.bands), style="green"),
                    Text(injection, style="yellow" if profile.injection_unverified else ""),
                    key=str(idx),
                )
            table.focus()

        def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
            with contextlib.suppress(TypeError, ValueError):
                self._chosen_idx = int(str(event.row_key.value))

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            # Double-click / Enter on a row → treat as Start.
            with contextlib.suppress(TypeError, ValueError):
                self._chosen_idx = int(str(event.row_key.value))
            self.action_start()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "cancel_btn":
                self.action_cancel()
            elif event.button.id == "start_btn":
                self.action_start()

        def action_start(self) -> None:
            if 0 <= self._chosen_idx < len(adapters):
                self.exit(self._chosen_idx)

        def action_cancel(self) -> None:
            self.exit(None)

    selected = AdapterPickerApp().run()
    if selected is None:
        raise click.ClickException("adapter selection cancelled")
    return adapters[selected]


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
        except Exception as exc:
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
        )
        try:
            app.run()
        finally:
            sniffer.stop()
            hopper.stop()
            adapter_mgr.restore()
        return 0


# Public, eagerly-instantiated registry. Phase 2 swaps this for entry-points.
REGISTRY: list[Plugin] = [ScanPlugin()]
