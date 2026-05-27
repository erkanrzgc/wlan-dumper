"""Textual TUI for the scan plugin.

Layout (top to bottom):

    Header (cyberm4fia-wifi · live 802.11 scan)
    Status bar (2 lines + a help hint)
    ┌─ 📡 Access Points (1fr) ──────────────────────────────────────────┐
    │ BSSID  PWR  Signal  CH  Encryption  ESSID  Vendor  #B  #D  WPS    │
    └───────────────────────────────────────────────────────────────────┘
    ┌─ AP Details ─────┬─ Clients (n) ─────┬─ Live Events ──────────────┐
    │ key/value pairs  │ STA list           │ rolling event log         │
    └──────────────────┴───────────────────┴───────────────────────────┘
    Footer: F2 Sort · F3 Filter · F4 Lock · F5 Pause · q Quit
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
    DeauthSent,
    EAPOLCapture,
    Event,
    EventBus,
    HandshakeComplete,
    ProbeSeen,
)
from cyberm4fia_wifi.core.hopper import ChannelHopper
from cyberm4fia_wifi.core.session import APRecord, Session
from cyberm4fia_wifi.utils.oui import is_locally_administered, oui_for

_REFRESH_INTERVAL = 0.25
_LOG_MAX_LINES = 500
_SORT_COLUMNS = ("pwr", "ch", "essid", "beacon_count", "data_count")

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


def _band_for(channel: int) -> str:
    if channel <= 14:
        return "2.4 GHz"
    if channel <= 177:
        return "5 GHz"
    return "6 GHz"


class ScanApp(App[None]):
    TITLE = "cyberm4fia-wifi"
    SUB_TITLE = "live 802.11 scan"

    CSS = """
    Screen {
        background: $surface;
    }

    #status_bar {
        height: 4;
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
        height: 14;
        margin: 0 1 0 1;
    }

    #details_panel {
        width: 1fr;
        border: round $warning;
        padding: 0 1;
        margin-right: 1;
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
        # F1 is shown in the status bar hint, not the footer — keeps the
        # action keys (F2..F5/q) front-and-centre at the bottom.
        Binding("f1", "help", "Help", show=False),
        Binding("f2", "cycle_sort", "Sort"),
        Binding("f3", "filter_prompt", "Filter"),
        Binding("f4", "lock_channel", "Lock CH"),
        Binding("f5", "toggle_pause", "Pause"),
        Binding("d", "deauth_prompt", "Deauth"),
        Binding("h", "handshake_prompt", "Handshake"),
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
        ap_panel.border_subtitle = "↑↓ select · click row · F4 to lock channel"
        yield ap_panel

        details_panel = Container(Static("(select an AP)", id="details"), id="details_panel")
        details_panel.border_title = "AP Details"

        client_panel = Container(self._build_client_panel(), id="client_panel")
        client_panel.border_title = "Clients"

        log_panel = Container(Log(highlight=False, id="log"), id="log_panel")
        log_panel.border_title = "Live Events"

        yield Horizontal(details_panel, client_panel, log_panel, id="bottom_split")
        yield Footer()

    def _build_ap_table(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="ap_dt")
        table.add_columns(
            "BSSID",
            "PWR",
            "Signal",
            "CH",
            "Encryption",
            "ESSID",
            "Vendor",
            "#Beacon",
            "#Data",
            "WPS",
        )
        return table

    def _build_client_panel(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="client_dt")
        table.add_columns("STATION", "Vendor", "PWR", "Signal", "FRAMES", "LAST")
        return table

    # ---- lifecycle ----------------------------------------------------------

    def on_mount(self) -> None:
        self._bus.subscribe(BeaconSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ProbeSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ClientSeen, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(ChannelChanged, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(DeauthSent, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(EAPOLCapture, self._log_event)  # type: ignore[arg-type]
        self._bus.subscribe(HandshakeComplete, self._log_event)  # type: ignore[arg-type]
        self.set_interval(_REFRESH_INTERVAL, self._tick)

    def _tick(self) -> None:
        if self._paused:
            return
        self._refresh_ap_table()
        self._refresh_client_panel()
        self._refresh_details()
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
        rows.sort(key=lambda ap: _sort_value(ap, sort_key), reverse=(sort_key in ("pwr", "beacon_count", "data_count")))

        table.clear()
        for ap in rows:
            essid_txt = Text(ap.essid) if ap.essid else Text("<hidden>", style="italic dim")
            enc_style = _ENC_STYLES.get(ap.encryption, "white")
            vendor = oui_for(ap.bssid) or "—"
            wps_marker = Text("⚠", style="bold yellow") if ap.wps else Text("·", style="dim")
            table.add_row(
                Text(ap.bssid, style="cyan"),
                Text(f"{ap.signal_dbm:>4}", style=_signal_style(ap.signal_dbm)),
                Text(_signal_bars(ap.signal_dbm), style=_signal_style(ap.signal_dbm)),
                Text(str(ap.channel), style="bright_white"),
                Text(ap.encryption, style=enc_style),
                essid_txt,
                Text(vendor, style="dim white"),
                Text(str(ap.beacon_count), style="dim"),
                Text(str(ap.data_count), style="bold cyan" if ap.data_count else "dim"),
                wps_marker,
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
        panel = self.query_one("#client_panel", Container)
        if not self._selected_bssid:
            panel.border_title = "Clients"
            return

        clients = self._session.clients_of(self._selected_bssid)
        panel.border_title = f"Clients ({len(clients)})"

        for client in clients:
            vendor = oui_for(client.station)
            vendor_text = (
                Text(vendor, style="dim white")
                if vendor
                else Text("random?" if is_locally_administered(client.station) else "—", style="dim")
            )
            table.add_row(
                Text(client.station, style="cyan"),
                vendor_text,
                Text(f"{client.signal_dbm:>4}", style=_signal_style(client.signal_dbm)),
                Text(_signal_bars(client.signal_dbm), style=_signal_style(client.signal_dbm)),
                Text(str(client.frames), style="bright_white"),
                Text(_fmt_ts(client.last_seen), style="dim"),
            )

    def _refresh_details(self) -> None:
        widget = self.query_one("#details", Static)
        if not self._selected_bssid:
            widget.update(Text("Use ↑↓ or click a row to inspect an AP.", style="dim"))
            return
        ap = next(
            (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
            None,
        )
        if ap is None:
            widget.update(Text("(AP no longer present)", style="dim red"))
            return
        widget.update(self._format_details(ap))

    def _format_details(self, ap: APRecord) -> Text:
        now = time.time()
        age = int(now - ap.last_seen)
        seen_for = int(ap.last_seen - ap.first_seen)
        vendor = oui_for(ap.bssid) or "(unknown OUI)"
        wps = Text("yes ⚠", style="bold yellow") if ap.wps else Text("no", style="dim")
        interval = (
            Text(f"{ap.beacon_interval_ms} ms", style="white")
            if ap.beacon_interval_ms
            else Text("—", style="dim")
        )
        return Text.assemble(
            ("ESSID    ", "dim"),
            (ap.essid or "<hidden>", "bold yellow" if not ap.essid else "bold white"),
            "\n",
            ("BSSID    ", "dim"), (ap.bssid, "cyan"), "  ", ("vendor ", "dim"), (vendor, "white"),
            "\n",
            ("Band     ", "dim"), (_band_for(ap.channel), "green"), ("  ch ", "dim"),
            (str(ap.channel), "bright_white"),
            "\n",
            ("Crypto   ", "dim"),
            (ap.encryption, _ENC_STYLES.get(ap.encryption, "white")),
            "\n",
            ("Signal   ", "dim"),
            (f"{ap.signal_dbm} dBm  ", _signal_style(ap.signal_dbm)),
            (_signal_bars(ap.signal_dbm), _signal_style(ap.signal_dbm)),
            "\n",
            ("Beacons  ", "dim"), (f"{ap.beacon_count}  ", "white"),
            ("interval ", "dim"), interval,
            "\n",
            ("Data     ", "dim"),
            (str(ap.data_count), "bold cyan" if ap.data_count else "dim"),
            ("  frames seen via this AP", "dim"),
            "\n",
            ("WPS      ", "dim"), wps,
            "\n",
            ("MFP      ", "dim"),
            (
                ap.mfp_status,
                "bold red" if ap.mfp_status == "required"
                else "yellow" if ap.mfp_status == "capable"
                else "dim",
            ),
            "\n",
            ("Handshakes ", "dim"),
            (
                str(ap.handshake_count),
                "bold green" if ap.handshake_count else "dim",
            ),
            "\n",
            ("Seen     ", "dim"),
            (f"{seen_for}s span", "white"),
            ("  ·  last ", "dim"),
            (f"{age}s ago" if age else "now", "white"),
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
        wps_count = sum(1 for a in aps if a.wps)
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
            ("  ·  2.4 GHz ", "dim"), (str(c24), "green"),
            ("  ·  5 GHz ", "dim"), (str(c5), "green"),
            ("  ·  WPS ", "dim"),
            (str(wps_count), "bold yellow" if wps_count else "dim"),
            ("  ·  clients ", "dim"), (str(clients_total), "bold cyan"),
            ("  ·  filter ", "dim"),
            (f'"{self._filter}"' if self._filter else "<none>",
             "yellow" if self._filter else "dim"),
        )
        line3 = Text(
            "press F1 for help · F2 cycle sort · F3 filter · F4 lock channel · F5 pause",
            style="dim italic",
        )
        return Text.assemble(line1, "\n", line2, "\n", line3)

    # ---- log buffering ------------------------------------------------------

    def _log_event(self, evt: Event) -> None:
        if isinstance(evt, BeaconSeen):
            tag = "WPS " if evt.wps else "    "
            line = (
                f"[beacon] {evt.bssid} ch{evt.channel:>3} {evt.signal_dbm:>4}dBm "
                f"{evt.encryption:14s}{tag}{evt.essid or '<hidden>'}"
            )
        elif isinstance(evt, ProbeSeen):
            line = f"[probe ] {evt.station} → {evt.essid or '<any>'} {evt.signal_dbm:>4}dBm"
        elif isinstance(evt, ClientSeen):
            line = f"[client] {evt.station} on {evt.bssid} {evt.signal_dbm:>4}dBm"
        elif isinstance(evt, ChannelChanged):
            line = f"[chan  ] hop → {evt.channel}"
        elif isinstance(evt, DeauthSent):
            who = evt.target_station or "broadcast"
            line = (
                f"[deauth] → {who} ({evt.sequence}/{evt.total}) "
                f"src={evt.target_bssid}"
            )
        elif isinstance(evt, EAPOLCapture):
            mi = evt.message_index if evt.message_index is not None else "?"
            line = f"[eapol ] M{mi}/4  {evt.bssid} ↔ {evt.station}"
        elif isinstance(evt, HandshakeComplete):
            verdict = "valid" if evt.valid_by_hcxtool else "partial"
            line = f"[handshake] {verdict} → {evt.pcap_path}"
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
            "F2 sort · F3 filter · F4 lock channel · F5 pause · "
            "d/h attack · q quit",
            timeout=10,
        )

    async def action_handshake_prompt(self) -> None:
        if not self._selected_bssid:
            self.notify("select an AP first", severity="warning")
            return
        ap = next(
            (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
            None,
        )
        if ap is None:
            return
        from cyberm4fia_wifi.tui.modals import HandshakeModal  # noqa: PLC0415

        clients = [c.station for c in self._session.clients_of(ap.bssid)]
        req = await self.push_screen_wait(
            HandshakeModal(
                ap_bssid=ap.bssid,
                ap_essid=ap.essid,
                ap_channel=ap.channel,
                clients=clients,
                mfp_status=ap.mfp_status,
            )
        )
        if req is None:
            self.notify("cancelled")
            return
        if self._hopper is not None:
            self._hopper.lock(ap.channel)

        from cyberm4fia_wifi.plugins.handshake import HandshakePlugin  # noqa: PLC0415

        plugin = HandshakePlugin()
        self.run_worker(
            lambda: plugin.execute(
                bus=self._bus,
                gate=_resolve_gate(),
                iface=self._iface,
                target_bssid=ap.bssid,
                target_station=req.target_station,
                essid=ap.essid,
                auto_deauth=req.auto_deauth,
                deauth_count=req.deauth_count,
                timeout=req.timeout,
                reason=req.reason,
            ),
            thread=True,
            description="handshake",
        )

    def action_deauth_prompt(self) -> None:
        self.notify(
            "Use 'h' for handshake (includes auto-deauth). "
            "Standalone deauth via the CLI: cyberm4fia deauth ...",
            timeout=8,
        )


def _resolve_gate():
    from cyberm4fia_wifi.core.auth import AuthorizationGate  # noqa: PLC0415

    return AuthorizationGate.from_xdg()


def _sort_value(ap: Any, column: str) -> Any:
    if column == "pwr":
        return ap.signal_dbm
    if column == "ch":
        return ap.channel
    if column == "essid":
        return (ap.essid or "").lower()
    if column == "beacon_count":
        return ap.beacon_count
    if column == "data_count":
        return ap.data_count
    return 0


def _fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))
