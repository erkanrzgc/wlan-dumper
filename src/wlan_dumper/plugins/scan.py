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

from wlan_dumper.core.adapter import AdapterManager, DetectedAdapter
from wlan_dumper.core.auth import PluginRisk
from wlan_dumper.core.hopper import ChannelHopper
from wlan_dumper.core.sniffer import Sniffer
from wlan_dumper.plugins.base import Plugin, PluginContext
from wlan_dumper.tui.app import ScanApp


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


# Picker behaviour when no adapter is present yet.
_PICKER_POLL_INTERVAL = 2.0  # seconds between background re-scans for adapters
_PICKER_IDLE_TIMEOUT = 30  # seconds with zero adapters before the picker self-closes


def interactive_pick_adapter(
    adapters: list[DetectedAdapter],
    preferred_iface: str | None,
    *,
    stdin: Any = None,
    stdout: Any = None,
    redetect: Any = None,
) -> DetectedAdapter:
    """Ask the operator which adapter to use.

    Explicit ``--iface`` wins when that interface is already present. In an
    interactive terminal the picker always opens — even with zero adapters —
    and live-refreshes (``redetect`` every few seconds) so an adapter plugged
    in after launch shows up without restarting. If nothing ever appears the
    picker self-closes after ``_PICKER_IDLE_TIMEOUT`` seconds.

    Non-TTY callers (scripts) keep the strict behaviour: zero adapters or an
    unmatched ``--iface`` is a hard error, a single adapter auto-picks, and
    multiple adapters use a numbered prompt.
    """
    tty = _is_tty(stdin or sys.stdin) and _is_tty(stdout or sys.stdout)

    # Explicit --iface that is already present always wins, TTY or not.
    if preferred_iface:
        for a in adapters:
            if a.iface == preferred_iface:
                return a
        if not tty:
            raise click.ClickException(
                f"requested --iface {preferred_iface!r} not found; "
                f"available: {[a.iface for a in adapters]}"
            )
        # TTY: fall through to the picker, which keeps watching for it.

    if tty:
        return _pick_adapter_tui(
            adapters, redetect=redetect, preferred_iface=preferred_iface
        )

    # ---- non-interactive fall-through (scripts / pipes) ----
    if not adapters:
        raise click.ClickException(
            "no wireless adapters detected — is the radio plugged in and "
            "is the driver loaded? (try: dmesg | tail)"
        )
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


def _pick_adapter_tui(
    adapters: list[DetectedAdapter],
    *,
    redetect: Any = None,
    preferred_iface: str | None = None,
) -> DetectedAdapter:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container
    from textual.widgets import DataTable, Static

    from wlan_dumper.core.adapter import detect_adapters, iface_link_info

    redetect_fn = redetect or detect_adapters

    class AdapterPickerApp(App["DetectedAdapter | None"]):
        TITLE = "wlan-dumper"
        BINDINGS: ClassVar[list[Binding]] = [
            Binding("enter", "select", "Select"),
            Binding("q,escape", "cancel", "Cancel"),
        ]
        # Centred dialog, keyboard-driven, no buttons.
        CSS = """
        Screen { align: center middle; }
        #picker {
            width: 88;
            height: auto;
            border: solid white;
            padding: 1 2;
        }
        #title { padding-bottom: 1; }
        #adapter_dt { height: auto; max-height: 14; }
        #status { padding-top: 1; }
        #hint { padding-top: 1; }
        """

        def __init__(self) -> None:
            super().__init__()
            self._adapters: list[DetectedAdapter] = list(adapters)
            self._chosen_idx: int = 0
            self._idle_left: int = _PICKER_IDLE_TIMEOUT

        def compose(self) -> ComposeResult:
            with Container(id="picker"):
                yield Static(Text("Select interface", style="bold"), id="title")
                table = DataTable[str](zebra_stripes=True, cursor_type="row", id="adapter_dt")
                table.add_columns(
                    "Interface", "State", "MAC", "Chipset", "Driver", "Bands", "Inject"
                )
                yield table
                yield Static("", id="status")
                yield Static(
                    Text.assemble(
                        ("Only wireless interfaces shown — eth*, docker0, br-*, "
                         "veth* etc. can't enter monitor mode.\n", "dim"),
                        ("↑↓", ""),
                        (" move  ·  ", "dim"),
                        ("Enter", ""),
                        (" select  ·  ", "dim"),
                        ("Esc", ""),
                        (" cancel", "dim"),
                    ),
                    id="hint",
                )

        def on_mount(self) -> None:
            self._rebuild_table()
            self._update_status()
            self.set_interval(_PICKER_POLL_INTERVAL, self._poll)
            self.set_interval(1.0, self._countdown)

        def _rebuild_table(self) -> None:
            table = self.query_one("#adapter_dt", DataTable)
            table.clear()
            for idx, adapter in enumerate(self._adapters):
                profile = adapter.profile
                injection = "yes" if profile.injection else "no"
                if profile.injection_unverified:
                    injection = f"{injection}?"
                mac, state = iface_link_info(adapter.iface)
                state_style = "green" if state == "up" else "dim"
                table.add_row(
                    Text(adapter.iface, style="cyan"),
                    Text(state, style=state_style),
                    Text(mac, style="dim"),
                    Text(profile.name),
                    Text(profile.driver, style="dim"),
                    Text("+".join(profile.bands), style="green"),
                    Text(injection, style="yellow" if profile.injection_unverified else ""),
                    key=str(idx),
                )
            if self._adapters:
                self._chosen_idx = min(self._chosen_idx, len(self._adapters) - 1)
                with contextlib.suppress(Exception):
                    table.move_cursor(row=self._chosen_idx)
                table.focus()

        def _poll(self) -> None:
            try:
                found = list(redetect_fn())
            except Exception:
                # A failed rescan must never crash the picker; try again next tick.
                return
            # Auto-select the requested --iface the moment it appears.
            if preferred_iface:
                for adapter in found:
                    if adapter.iface == preferred_iface:
                        self.exit(adapter)
                        return
            if [a.iface for a in found] != [a.iface for a in self._adapters]:
                self._adapters = found
                self._rebuild_table()
                self._update_status()

        def _countdown(self) -> None:
            if self._adapters:
                self._idle_left = _PICKER_IDLE_TIMEOUT  # reset while we have something
                return
            self._idle_left -= 1
            if self._idle_left <= 0:
                self.exit(None)
                return
            self._update_status()

        def _update_status(self) -> None:
            status = self.query_one("#status", Static)
            if self._adapters:
                status.update(Text(""))
            else:
                status.update(
                    Text.assemble(
                        ("No wireless interface detected — plug one in. ", "yellow"),
                        (f"closing in {self._idle_left}s", "dim"),
                    )
                )

        def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
            self._remember_row(event.row_key)

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            self._remember_row(event.row_key)
            self.action_select()

        def _remember_row(self, row_key: object) -> None:
            # When the table goes from empty to populated (or clears), Textual
            # fires highlight events with row_key=None — guard against it.
            key_value = getattr(row_key, "value", None)
            if key_value is None:
                return
            with contextlib.suppress(TypeError, ValueError):
                self._chosen_idx = int(str(key_value))

        def action_select(self) -> None:
            if 0 <= self._chosen_idx < len(self._adapters):
                self.exit(self._adapters[self._chosen_idx])

        def action_cancel(self) -> None:
            self.exit(None)

    selected = AdapterPickerApp().run()
    if selected is None:
        raise click.ClickException(
            "no interface selected (cancelled or no adapter appeared in time)"
        )
    return selected


class ScanPlugin(Plugin):
    name = "scan"
    risk = PluginRisk.PASSIVE
    requires_injection = False

    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Live 802.11 scan + TUI (passive)")
        @click.pass_context
        def scan_cmd(ctx: click.Context) -> None:
            from wlan_dumper.cli import build_runtime_for

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
