"""Textual TUI for the scan plugin.

Three vertically stacked panels:

1. ``APTable``     — every AP, sorted by PWR descending; row selection drives
                     the client panel.
2. ``ClientPanel`` — clients for the currently selected AP.
3. ``LogPanel``    — last N events, newest first.

The app polls the ``Session`` on a 250 ms interval rather than subscribing to
the bus directly; polling keeps the TUI thread firmly in charge of its own
state and avoids cross-thread widget mutation. Event-bus subscription is used
only for the rolling log line, which is queued and drained on the polling
tick.
"""

from __future__ import annotations

import queue
import time
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import DataTable, Footer, Header, Log, Static

from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ChannelChanged,
    ClientSeen,
    Event,
    EventBus,
    ProbeSeen,
)
from cyberm4fia_wifi.core.hopper import ChannelHopper
from cyberm4fia_wifi.core.session import Session

_REFRESH_INTERVAL = 0.25
_LOG_MAX_LINES = 200
_SORT_COLUMNS = ("pwr", "ch", "essid", "beacon_count")


class ScanApp(App[None]):
    """Textual application for the scan plugin."""

    CSS = """
    Screen { layout: vertical; }
    #status { height: 1; background: $panel; color: $text; padding: 0 1; }
    #ap_table { height: 50%; }
    #client_panel { height: 25%; }
    #log_panel { height: 1fr; }
    """

    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "cycle_sort", "Sort"),
        Binding("f3", "filter_prompt", "Filter"),
        Binding("f4", "lock_channel", "Lock CH"),
        Binding("f5", "toggle_pause", "Pause"),
        Binding("f10,q", "quit", "Quit"),
    ]

    def __init__(
        self,
        *,
        session: Session,
        bus: EventBus,
        hopper: ChannelHopper | None = None,
        iface: str = "?",
        driver: str = "?",
        mode: str = "?",
    ) -> None:
        super().__init__()
        self._session = session
        self._bus = bus
        self._hopper = hopper
        self._iface = iface
        self._driver_name = driver
        self._mode = mode
        self._sort_idx = 0
        self._filter: str = ""
        self._paused = False
        self._log_queue: queue.Queue[str] = queue.Queue()
        self._selected_bssid: str | None = None

    # ---- compose ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(self._format_status(), id="status")
        yield Container(self._build_ap_table(), id="ap_table")
        yield Container(self._build_client_panel(), id="client_panel")
        yield Container(Log(highlight=False, id="log"), id="log_panel")
        yield Footer()

    def _build_ap_table(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="ap_dt")
        table.add_columns("BSSID", "PWR", "CH", "ENC", "ESSID", "#Beacon", "#Data")
        return table

    def _build_client_panel(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="client_dt")
        table.add_columns("STATION", "PWR", "FRAMES", "FIRST", "LAST")
        return table

    # ---- lifecycle ----------------------------------------------------------

    def on_mount(self) -> None:
        self._bus.subscribe(BeaconSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ProbeSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ClientSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ChannelChanged, self._log_event)  # type: ignore[arg-type]
        self.set_interval(_REFRESH_INTERVAL, self._tick)

    def _tick(self) -> None:
        if self._paused:
            return
        self._refresh_ap_table()
        self._refresh_client_panel()
        self._drain_log()
        self._refresh_status()

    # ---- table refresh ------------------------------------------------------

    def _refresh_ap_table(self) -> None:
        table = self.query_one("#ap_dt", DataTable)
        previous = self._selected_bssid

        rows = self._session.aps_snapshot()
        if self._filter:
            f = self._filter.lower()
            rows = [
                ap
                for ap in rows
                if f in (ap.bssid.lower()) or (ap.essid and f in ap.essid.lower())
            ]
        sort_key = _SORT_COLUMNS[self._sort_idx % len(_SORT_COLUMNS)]
        rows.sort(key=lambda ap: _sort_value(ap, sort_key), reverse=(sort_key == "pwr"))

        table.clear()
        for ap in rows:
            table.add_row(
                ap.bssid,
                str(ap.signal_dbm),
                str(ap.channel),
                ap.encryption,
                ap.essid or "<hidden>",
                str(ap.beacon_count),
                str(ap.data_count),
                key=ap.bssid,
            )
        if previous and any(ap.bssid == previous for ap in rows):
            try:
                table.move_cursor(row=next(i for i, ap in enumerate(rows) if ap.bssid == previous))
            except (ValueError, StopIteration):
                pass

    def _refresh_client_panel(self) -> None:
        table = self.query_one("#client_dt", DataTable)
        table.clear()
        if not self._selected_bssid:
            return
        for client in self._session.clients_of(self._selected_bssid):
            table.add_row(
                client.station,
                str(client.signal_dbm),
                str(client.frames),
                _fmt_ts(client.first_seen),
                _fmt_ts(client.last_seen),
            )

    def _refresh_status(self) -> None:
        widget = self.query_one("#status", Static)
        widget.update(self._format_status())

    def _format_status(self) -> str:
        ch = self._session.active_channel
        ch_label = f"locked={ch}" if (self._hopper and self._hopper._locked_channel) else (
            f"{ch}" if ch is not None else "—"
        )
        return (
            f"iface: {self._iface}  driver: {self._driver_name}  "
            f"CH: {ch_label}  mode: {self._mode}  "
            f"{'(paused)' if self._paused else ''}"
        )

    # ---- log buffering ------------------------------------------------------

    def _log_event(self, evt: Event) -> None:
        """Subscriber: format an event and enqueue it. Runs on sniffer thread."""
        if isinstance(evt, BeaconSeen):
            line = (
                f"beacon {evt.bssid} ch{evt.channel} "
                f"{evt.signal_dbm}dBm {evt.essid or '<hidden>'}"
            )
        elif isinstance(evt, ProbeSeen):
            line = f"probe  {evt.station} -> {evt.essid or '<any>'} {evt.signal_dbm}dBm"
        elif isinstance(evt, ClientSeen):
            line = f"client {evt.station} on {evt.bssid} {evt.signal_dbm}dBm"
        elif isinstance(evt, ChannelChanged):
            line = f"chan   {evt.channel}"
        else:
            line = type(evt).__name__
        try:
            self._log_queue.put_nowait(line)
        except queue.Full:
            pass

    def _drain_log(self) -> None:
        log = self.query_one("#log", Log)
        drained = 0
        while drained < _LOG_MAX_LINES:
            try:
                line = self._log_queue.get_nowait()
            except queue.Empty:
                break
            log.write_line(line)
            drained += 1

    # ---- selection ----------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "ap_dt":
            key = event.row_key.value
            self._selected_bssid = str(key) if key is not None else None

    # ---- actions ------------------------------------------------------------

    def action_cycle_sort(self) -> None:
        self._sort_idx = (self._sort_idx + 1) % len(_SORT_COLUMNS)
        self._refresh_ap_table()

    def action_filter_prompt(self) -> None:
        # Phase 1 keeps this minimal — toggle a stored filter via a notify.
        # A modal input lands in Phase 2 once we have a few more screens.
        if self._filter:
            self._filter = ""
            self.notify("filter cleared")
        else:
            self.notify("filter: type a substring then press F3 again")

    def action_lock_channel(self) -> None:
        if not self._hopper:
            self.notify("no hopper attached", severity="warning")
            return
        if self._hopper._locked_channel is not None:
            self._hopper.unlock()
            self.notify("hopper resumed")
        elif self._selected_bssid:
            ap = next(
                (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
                None,
            )
            if ap is not None:
                self._hopper.lock(ap.channel)
                self.notify(f"locked to channel {ap.channel}")
        else:
            self.notify("select an AP first", severity="warning")

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.notify("paused" if self._paused else "resumed")


def _sort_value(ap: Any, column: str) -> Any:
    if column == "pwr":
        return ap.signal_dbm
    if column == "ch":
        return ap.channel
    if column == "essid":
        return (ap.essid or "").lower()
    if column == "beacon_count":
        return ap.beacon_count
    return 0


def _fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))
