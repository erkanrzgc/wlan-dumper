"""Textual TUI for the scan plugin.

Layout (top to bottom):

    ┌─────────────────────────────────────────────────────────────────┐
    │ Header (cyberm4fia-wifi)                                        │
    ├─────────────────────────────────────────────────────────────────┤
    │ Status bar: iface · driver · CH · mode · counts                 │
    ├─── Access Points ───────────────────────────────────────────────┤
    │ BSSID  PWR  CH  ENC      ESSID         #B  #D   (colour-coded)  │
    │ ...                                                             │
    ├─── Clients of <selected ESSID> ──┬─── Live Events ──────────────┤
    │ STATION  PWR  FRAMES  FIRST  LAST│ beacon ...                   │
    │                                  │ probe ...                    │
    └──────────────────────────────────┴──────────────────────────────┘
    [F1] Help  [F2] Sort  [F3] Filter  [F4] Lock CH  [F5] Pause  [q]   ← Footer

The app polls the ``Session`` on a 250 ms interval (TUI thread owns widget
mutation). The bus subscription only enqueues formatted log lines into a
thread-safe queue that the polling tick drains.

Colour coding (Rich Text):
    Encryption — OPEN red bold, WEP red, WPA-PSK orange, WPA2-PSK yellow,
                 WPA3-SAE green, WPA/WPA2-MIXED yellow italic.
    Signal     — > -50 green, -50..-70 yellow, -70..-85 orange, < -85 red.
"""

from __future__ import annotations

import queue
import time
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
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
_LOG_MAX_LINES = 500
_SORT_COLUMNS = ("pwr", "ch", "essid", "beacon_count")

_ENC_STYLES = {
    "OPEN": "bold red",
    "WEP": "red",
    "WPA-PSK": "orange1",
    "WPA2-PSK": "yellow",
    "WPA3-SAE": "bold green",
    "WPA/WPA2-MIXED": "yellow italic",
}


def _signal_style(dbm: int) -> str:
    if dbm > -50:
        return "bold green"
    if dbm > -70:
        return "yellow"
    if dbm > -85:
        return "orange1"
    return "red"


def _signal_bars(dbm: int) -> str:
    """Five-step bar gauge, ASCII so it works in every terminal."""
    if dbm > -50:
        return "▰▰▰▰▰"
    if dbm > -60:
        return "▰▰▰▰▱"
    if dbm > -70:
        return "▰▰▰▱▱"
    if dbm > -80:
        return "▰▰▱▱▱"
    if dbm > -90:
        return "▰▱▱▱▱"
    return "▱▱▱▱▱"


class ScanApp(App[None]):
    TITLE = "cyberm4fia-wifi"
    SUB_TITLE = "live 802.11 scan"

    CSS = """
    Screen {
        background: $surface;
    }

    #status_bar {
        height: 3;
        padding: 0 2;
        background: $primary 30%;
        color: $text;
        border-bottom: heavy $primary;
    }

    #ap_panel {
        height: 1fr;
        border: round $primary;
        margin: 0 1;
        padding: 0;
    }

    #bottom_split {
        height: 16;
        margin: 0 1 0 1;
    }

    #client_panel {
        width: 1fr;
        border: round $accent;
        padding: 0;
        margin-right: 1;
    }

    #log_panel {
        width: 1fr;
        border: round $secondary;
        padding: 0;
    }

    DataTable {
        height: 1fr;
    }

    DataTable > .datatable--cursor {
        background: $accent 60%;
        color: $text;
    }

    Log {
        background: $surface-lighten-1;
        height: 1fr;
        scrollbar-size-vertical: 1;
        scrollbar-background: $surface;
        scrollbar-color: $primary 40%;
    }
    """

    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "cycle_sort", "Sort"),
        Binding("f3", "filter_prompt", "Filter"),
        Binding("f4", "lock_channel", "Lock CH"),
        Binding("f5", "toggle_pause", "Pause"),
        Binding("q,f10", "quit", "Quit"),
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
        self._started_at = time.time()

    # ---- compose ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._format_status(), id="status_bar")
        ap_panel = Container(self._build_ap_table(), id="ap_panel")
        ap_panel.border_title = "📡 Access Points"
        ap_panel.border_subtitle = "F2 sort · F3 filter · F4 lock · F5 pause"
        yield ap_panel
        client_panel = Container(self._build_client_panel(), id="client_panel")
        client_panel.border_title = "Clients"
        log_panel = Container(Log(highlight=False, id="log"), id="log_panel")
        log_panel.border_title = "Live Events"
        yield Horizontal(client_panel, log_panel, id="bottom_split")
        yield Footer()

    def _build_ap_table(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="ap_dt")
        table.add_columns("BSSID", "PWR", "Signal", "CH", "Encryption", "ESSID", "#Beacon")
        return table

    def _build_client_panel(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="client_dt")
        table.add_columns("STATION", "PWR", "Signal", "FRAMES", "FIRST", "LAST")
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
                if f in ap.bssid.lower() or (ap.essid and f in ap.essid.lower())
            ]
        sort_key = _SORT_COLUMNS[self._sort_idx % len(_SORT_COLUMNS)]
        rows.sort(key=lambda ap: _sort_value(ap, sort_key), reverse=(sort_key == "pwr"))

        table.clear()
        for ap in rows:
            essid_txt = (
                Text(ap.essid) if ap.essid else Text("<hidden>", style="italic dim")
            )
            enc_style = _ENC_STYLES.get(ap.encryption, "white")
            table.add_row(
                Text(ap.bssid, style="cyan"),
                Text(f"{ap.signal_dbm:>4}", style=_signal_style(ap.signal_dbm)),
                Text(_signal_bars(ap.signal_dbm), style=_signal_style(ap.signal_dbm)),
                Text(str(ap.channel), style="bright_white"),
                Text(ap.encryption, style=enc_style),
                essid_txt,
                Text(str(ap.beacon_count), style="dim"),
                key=ap.bssid,
            )
        if previous and any(ap.bssid == previous for ap in rows):
            try:
                table.move_cursor(
                    row=next(i for i, ap in enumerate(rows) if ap.bssid == previous)
                )
            except (ValueError, StopIteration):
                pass

    def _refresh_client_panel(self) -> None:
        table = self.query_one("#client_dt", DataTable)
        table.clear()
        panel = self.query_one("#client_panel", Container)
        if not self._selected_bssid:
            panel.border_title = "Clients"
            return

        ap = next(
            (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
            None,
        )
        label = ap.essid if (ap and ap.essid) else self._selected_bssid
        clients = self._session.clients_of(self._selected_bssid)
        panel.border_title = f"Clients — {label} ({len(clients)})"

        for client in clients:
            table.add_row(
                Text(client.station, style="cyan"),
                Text(f"{client.signal_dbm:>4}", style=_signal_style(client.signal_dbm)),
                Text(_signal_bars(client.signal_dbm), style=_signal_style(client.signal_dbm)),
                Text(str(client.frames), style="bright_white"),
                Text(_fmt_ts(client.first_seen), style="dim"),
                Text(_fmt_ts(client.last_seen), style="dim"),
            )

    def _refresh_status(self) -> None:
        widget = self.query_one("#status_bar", Static)
        widget.update(self._format_status())

    def _format_status(self) -> Text:
        ch = self._session.active_channel
        locked = self._hopper and self._hopper._locked_channel is not None
        ch_label = (
            f"locked={self._hopper._locked_channel}"  # type: ignore[union-attr]
            if locked
            else (str(ch) if ch is not None else "—")
        )
        aps = self._session.aps_snapshot()
        ap_count = len(aps)
        c24 = sum(1 for a in aps if a.channel <= 14)
        c5 = sum(1 for a in aps if a.channel > 14)
        clients_total = sum(len(self._session.clients_of(a.bssid)) for a in aps)
        uptime = int(time.time() - self._started_at)

        line1 = Text.assemble(
            ("iface ", "dim"), (self._iface, "bold cyan"),
            ("  ·  driver ", "dim"), (self._driver_name, "bold white"),
            ("  ·  CH ", "dim"), (ch_label, "bold yellow"),
            ("  ·  mode ", "dim"), (self._mode, "bold magenta"),
            ("  ·  uptime ", "dim"), (f"{uptime}s", "white"),
            ("    PAUSED", "bold red on yellow") if self._paused else ("", ""),
        )
        line2 = Text.assemble(
            ("APs ", "dim"), (f"{ap_count}", "bold green"),
            ("  ·  2.4GHz ", "dim"), (str(c24), "green"),
            ("  ·  5GHz ", "dim"), (str(c5), "green"),
            ("  ·  clients ", "dim"), (str(clients_total), "bold cyan"),
            ("  ·  filter ", "dim"),
            (f'"{self._filter}"' if self._filter else "<none>",
             "yellow" if self._filter else "dim"),
        )
        return Text.assemble(line1, "\n", line2)

    # ---- log buffering ------------------------------------------------------

    def _log_event(self, evt: Event) -> None:
        if isinstance(evt, BeaconSeen):
            line = (
                f"[beacon] {evt.bssid} ch{evt.channel:>3} {evt.signal_dbm:>4}dBm "
                f"{evt.encryption:14s} {evt.essid or '<hidden>'}"
            )
        elif isinstance(evt, ProbeSeen):
            line = f"[probe ] {evt.station} → {evt.essid or '<any>'} {evt.signal_dbm:>4}dBm"
        elif isinstance(evt, ClientSeen):
            line = f"[client] {evt.station} on {evt.bssid} {evt.signal_dbm:>4}dBm"
        elif isinstance(evt, ChannelChanged):
            line = f"[chan  ] hop → {evt.channel}"
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
        self.notify(f"sort: {_SORT_COLUMNS[self._sort_idx]}")
        self._refresh_ap_table()

    def action_filter_prompt(self) -> None:
        if self._filter:
            self._filter = ""
            self.notify("filter cleared")
        else:
            # Phase 2 lands a real modal; for now cycle through the most
            # common quick filters by pressing F3 repeatedly.
            self._filter = "wpa"
            self.notify("filter: 'wpa' (press F3 again to clear)")

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

    def action_help(self) -> None:
        self.notify(
            "F2 sort · F3 filter · F4 lock channel · F5 pause · q quit",
            timeout=8,
        )


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
