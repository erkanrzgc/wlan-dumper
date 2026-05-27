"""Textual TUI for the scan plugin.

Layout (top to bottom):

    Header (cyberm4fia-wifi)
    Status bar (slim, two lines)
    +------------------------------------------------------------------+
    |  Access Points (full width)                                      |
    +-------------------+-------------------+--------------------------+
    |  AP Details       |  Clients          |  Logs                    |
    +-------------------+-------------------+--------------------------+
    Footer

No custom colour theme: relies on the terminal's own palette. Only the
event log uses the standard 16-colour ANSI tags ("red", "yellow", ...)
that every terminal honours.
"""

from __future__ import annotations

import queue
import time
from contextlib import suppress
from typing import Any, ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
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

# Per-AP cap on beacon log lines — beacons are 10/sec per AP and otherwise
# flood the log faster than the eye can read.
_BEACON_LOG_EVERY = 50

# Fixed-column log layout so every event type lines up under the same header.
#   Time    : 8  ("HH:MM:SS")
#   Event   : 8  ("AP+  ", "STA   ", "DEAUTH", "EAPOL ", "HS    ")
#   Station : 17 (MAC address or "—")
#   BSSID   : 17 (MAC address or "—")
#   Detail  : rest of line
_LOG_COL_WIDTHS = (8, 8, 17, 17)
_LOG_HEADER = (
    f"{'Time':<{_LOG_COL_WIDTHS[0]}}  "
    f"{'Event':<{_LOG_COL_WIDTHS[1]}}  "
    f"{'Station':<{_LOG_COL_WIDTHS[2]}}  "
    f"{'BSSID':<{_LOG_COL_WIDTHS[3]}}  "
    "Detail"
)


def _log_row(time_: str, event: str, station: str, bssid: str, detail: str) -> str:
    return (
        f"{time_:<{_LOG_COL_WIDTHS[0]}}  "
        f"{event:<{_LOG_COL_WIDTHS[1]}}  "
        f"{station:<{_LOG_COL_WIDTHS[2]}}  "
        f"{bssid:<{_LOG_COL_WIDTHS[3]}}  "
        f"{detail}"
    )


def _signal_style(dbm: int) -> str:
    if dbm > -50:
        return "green"
    if dbm > -70:
        return "yellow"
    if dbm > -85:
        return "red"
    return "red dim"


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

    # No background/color overrides — let the terminal palette win.
    CSS = """
    Screen { layout: vertical; }

    #status_bar {
        height: 3;
        padding: 0 1;
    }

    /* Main split: left column (AP table + Details|Clients) vs full-height Logs */
    #main_split {
        height: 1fr;
    }

    #left_pane {
        width: 3fr;
    }

    #ap_panel {
        height: 3fr;
        border: solid white;
        padding: 0;
    }

    #bottom_split {
        height: 2fr;
    }

    #details_panel {
        width: 1fr;
        border: solid white;
        padding: 0 1;
    }

    #client_panel {
        width: 1fr;
        border: solid white;
        padding: 0;
    }

    #log_panel {
        width: 2fr;
        border: solid white;
        padding: 0;
    }

    #log_header {
        height: 1;
        padding: 0 1;
    }

    DataTable { height: 1fr; }
    Log { height: 1fr; }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "help", "Help"),
        Binding("f2", "cycle_sort", "Sort"),
        Binding("f3", "filter_prompt", "Filter"),
        Binding("f4", "lock_channel", "Lock CH"),
        Binding("f5", "toggle_pause", "Pause"),
        Binding("d", "deauth_prompt", "Deauth"),
        Binding("h", "handshake_prompt", "Handshake"),
        Binding("c", "focus_clients", "Clients"),
        Binding("a", "focus_aps", "APs"),
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
    ) -> None:
        super().__init__()
        self._session = session
        self._bus = bus
        self._hopper = hopper
        self._iface = iface
        self._driver_name = driver
        self._sort_idx = 0
        self._filter: str = ""
        self._paused = False
        self._log_queue: queue.Queue[str] = queue.Queue()
        self._selected_bssid: str | None = None
        self._started_at = time.time()
        self._known_bssids: set[str] = set()  # log gating: only-once new APs

    # ---- compose ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._format_status(), id="status_bar")

        ap_panel = Container(self._build_ap_table(), id="ap_panel")
        ap_panel.border_title = "Access Points"
        ap_panel.border_subtitle = "↑↓ select · click row · F4 lock channel"

        details_panel = Container(Static("(select an AP)", id="details"), id="details_panel")
        details_panel.border_title = "AP Details"

        client_panel = Container(self._build_client_panel(), id="client_panel")
        client_panel.border_title = "Clients"

        bottom = Horizontal(details_panel, client_panel, id="bottom_split")
        left_pane = Vertical(ap_panel, bottom, id="left_pane")

        log_header = Static(
            Text(_LOG_HEADER, style="dim"),
            id="log_header",
        )
        log_panel = Container(
            Vertical(log_header, Log(highlight=False, id="log")),
            id="log_panel",
        )
        log_panel.border_title = "Logs"

        yield Horizontal(left_pane, log_panel, id="main_split")
        yield Footer()

    def _build_ap_table(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="ap_dt")
        table.add_columns(
            "BSSID",
            "Pwr",
            "Signal",
            "Ch",
            "Encryption",
            "ESSID",
            "Vendor",
            "Beacon",
            "Data",
            "WPS",
            "HS",
        )
        return table

    def _build_client_panel(self) -> DataTable[Any]:
        table = DataTable[Any](zebra_stripes=True, cursor_type="row", id="client_dt")
        table.add_columns("Station", "Vendor", "Pwr", "Signal", "Frames", "Last")
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
        with suppress(NoMatches):
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
                ap for ap in rows if f in ap.bssid.lower() or (ap.essid and f in ap.essid.lower())
            ]
        sort_key = _SORT_COLUMNS[self._sort_idx % len(_SORT_COLUMNS)]
        rows.sort(
            key=lambda ap: _sort_value(ap, sort_key),
            reverse=(sort_key in ("pwr", "beacon_count", "data_count")),
        )

        table.clear()
        for ap in rows:
            essid_txt = Text(ap.essid) if ap.essid else Text("<hidden>", style="italic dim")
            enc_style = _ENC_STYLES.get(ap.encryption, "")
            vendor = oui_for(ap.bssid) or "—"
            wps_marker = Text("WPS", style="yellow") if ap.wps else Text("·", style="dim")
            hs_marker = (
                Text(f"✓{ap.handshake_count}", style="green")
                if ap.handshake_count
                else Text("·", style="dim")
            )
            table.add_row(
                Text(ap.bssid, style="cyan"),
                Text(f"{ap.signal_dbm:>4}", style=_signal_style(ap.signal_dbm)),
                Text(_signal_bars(ap.signal_dbm), style=_signal_style(ap.signal_dbm)),
                Text(str(ap.channel)),
                Text(ap.encryption, style=enc_style),
                essid_txt,
                Text(vendor, style="dim"),
                Text(str(ap.beacon_count), style="dim"),
                Text(str(ap.data_count), style="cyan" if ap.data_count else "dim"),
                wps_marker,
                hs_marker,
                key=ap.bssid,
            )
        if previous and any(ap.bssid == previous for ap in rows):
            with suppress(ValueError, StopIteration):
                target_row = next(
                    i for i, row in enumerate(table.ordered_rows) if row.key.value == previous
                )
                table.move_cursor(row=target_row)

    def _refresh_client_panel(self) -> None:
        table = self.query_one("#client_dt", DataTable)
        panel = self.query_one("#client_panel", Container)
        table.clear()
        if not self._selected_bssid:
            panel.border_title = "Clients"
            return

        clients = sorted(
            self._session.clients_of(self._selected_bssid),
            key=lambda c: (c.last_seen, c.frames),
            reverse=True,
        )
        panel.border_title = f"Clients ({len(clients)})"
        for client in clients:
            vendor = oui_for(client.station)
            if vendor:
                vendor_text = Text(vendor, style="dim")
            elif is_locally_administered(client.station):
                vendor_text = Text("random", style="dim")
            else:
                vendor_text = Text("—", style="dim")
            table.add_row(
                Text(client.station, style="cyan"),
                vendor_text,
                Text(f"{client.signal_dbm:>4}", style=_signal_style(client.signal_dbm)),
                Text(_signal_bars(client.signal_dbm), style=_signal_style(client.signal_dbm)),
                Text(str(client.frames)),
                Text(_fmt_ts(client.last_seen), style="dim"),
            )

    def _refresh_details(self) -> None:
        widget = self.query_one("#details", Static)
        if not self._selected_bssid:
            widget.update(Text("(select an AP — ↑↓ or click)", style="dim"))
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
        wps = Text("yes", style="yellow") if ap.wps else Text("no", style="dim")
        interval = (
            Text(f"{ap.beacon_interval_ms} ms")
            if ap.beacon_interval_ms
            else Text("—", style="dim")
        )
        return Text.assemble(
            ("ESSID    ", "dim"),
            (ap.essid or "<hidden>", "yellow" if not ap.essid else "default"),
            "\n",
            ("BSSID    ", "dim"),
            (ap.bssid, "cyan"),
            "\n",
            ("Vendor   ", "dim"),
            (vendor, ""),
            "\n",
            ("Band     ", "dim"),
            (_band_for(ap.channel), "green"),
            ("  ch ", "dim"),
            (str(ap.channel), ""),
            "\n",
            ("Crypto   ", "dim"),
            (ap.encryption, _ENC_STYLES.get(ap.encryption, "")),
            "\n",
            ("Signal   ", "dim"),
            (f"{ap.signal_dbm} dBm  ", _signal_style(ap.signal_dbm)),
            (_signal_bars(ap.signal_dbm), _signal_style(ap.signal_dbm)),
            "\n",
            ("Beacons  ", "dim"),
            (f"{ap.beacon_count}  ", ""),
            ("interval ", "dim"),
            interval,
            "\n",
            ("Data     ", "dim"),
            (str(ap.data_count), "cyan" if ap.data_count else "dim"),
            "\n",
            ("WPS      ", "dim"),
            wps,
            "\n",
            ("MFP      ", "dim"),
            (
                ap.mfp_status,
                "red"
                if ap.mfp_status == "required"
                else "yellow"
                if ap.mfp_status == "capable"
                else "dim",
            ),
            "\n",
            ("Hands.   ", "dim"),
            (str(ap.handshake_count), "green" if ap.handshake_count else "dim"),
            "\n",
            ("Seen     ", "dim"),
            (f"{seen_for}s span · last {age}s ago" if age else f"{seen_for}s span · now", ""),
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
            ("iface: ", "dim"), (self._iface, "cyan"),
            ("   driver: ", "dim"), (self._driver_name, ""),
            ("   channel: ", "dim"), (ch_label, "yellow"),
            ("   uptime: ", "dim"), (f"{uptime}s", ""),
            ("    PAUSED", "red") if self._paused else ("", ""),
        )
        line2 = Text.assemble(
            ("APs: ", "dim"), (f"{ap_count}", "green"),
            ("   2.4GHz: ", "dim"), (str(c24), "green"),
            ("   5GHz: ", "dim"), (str(c5), "green"),
            ("   WPS-APs: ", "dim"), (str(wps_count), "yellow" if wps_count else "dim"),
            ("   clients: ", "dim"), (str(clients_total), "cyan"),
            ("   filter: ", "dim"),
            (f'"{self._filter}"' if self._filter else "—",
             "yellow" if self._filter else "dim"),
        )
        return Text.assemble(line1, "\n", line2)

    # ---- log buffering ------------------------------------------------------

    def _log_event(self, evt: Event) -> None:
        line = self._format_log_line(evt)
        if line is None:
            return
        with suppress(queue.Full):
            self._log_queue.put_nowait(line)

    def _format_log_line(self, evt: Event) -> str | None:
        stamp = _fmt_ts(evt.timestamp)
        # Every event lays out as Time | Event | Station | BSSID | Detail
        # so the columns are aligned under the sticky header.
        if isinstance(evt, BeaconSeen):
            # Only log first-seen APs + every Nth beacon for known ones,
            # otherwise the panel floods (~10 beacons/sec per AP).
            first_seen = evt.bssid not in self._known_bssids
            if not first_seen:
                ap = next(
                    (a for a in self._session.aps_snapshot()
                     if a.bssid.lower() == evt.bssid.lower()),
                    None,
                )
                if ap is None or ap.beacon_count % _BEACON_LOG_EVERY != 0:
                    return None
            self._known_bssids.add(evt.bssid)
            tag = "AP+" if first_seen else "AP"
            detail = (
                f"ch{evt.channel:>3}  {evt.signal_dbm:>4}dBm  "
                f"{evt.encryption:<12}  {evt.essid or '<hidden>'}"
            )
            return _log_row(stamp, tag, "-", evt.bssid, detail)
        if isinstance(evt, ProbeSeen):
            return None  # too noisy by default
        if isinstance(evt, ClientSeen):
            return _log_row(
                stamp, "STA", evt.station, evt.bssid, f"{evt.signal_dbm:>4}dBm",
            )
        if isinstance(evt, ChannelChanged):
            return None  # silent hop — channel shown in status bar
        if isinstance(evt, DeauthSent):
            who = evt.target_station or "broadcast"
            return _log_row(
                stamp, "DEAUTH", who, evt.target_bssid,
                f"frame {evt.sequence:>3}/{evt.total}",
            )
        if isinstance(evt, EAPOLCapture):
            mi = evt.message_index if evt.message_index is not None else "?"
            return _log_row(stamp, "EAPOL", evt.station, evt.bssid, f"M{mi}/4")
        if isinstance(evt, HandshakeComplete):
            verdict = "VALID" if evt.valid_by_hcxtool else "PARTIAL"
            artifact = evt.hashcat_path or evt.pcap_path
            return _log_row(
                stamp, "HS", evt.station, evt.bssid,
                f"{verdict}  saved {artifact}",
            )
        return _log_row(stamp, "EVENT", "-", "-", type(evt).__name__)

    def _ap_label(self, bssid: str) -> str:
        needle = bssid.lower()
        for ap in self._session.aps_snapshot():
            if ap.bssid.lower() == needle:
                return ap.essid or "<hidden>"
        return bssid

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

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "ap_dt":
            key = event.row_key.value
            self._selected_bssid = str(key) if key is not None else None
            self._refresh_client_panel()
            self._refresh_details()

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

    def action_focus_aps(self) -> None:
        with suppress(NoMatches):
            self.query_one("#ap_dt", DataTable).focus()

    def action_focus_clients(self) -> None:
        if not self._selected_bssid:
            self.notify("select an AP first to see its clients", severity="warning")
            return
        with suppress(NoMatches):
            self.query_one("#client_dt", DataTable).focus()

    def action_help(self) -> None:
        self.notify(
            "F2 sort · F3 filter · F4 lock channel · F5 pause · d/h attack · q quit",
            timeout=10,
        )

    def action_handshake_prompt(self) -> None:
        if not self._selected_bssid:
            self.notify("select an AP first", severity="warning")
            return
        ap = next(
            (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
            None,
        )
        if ap is None:
            return
        from cyberm4fia_wifi.tui.modals import HandshakeModal

        clients = [c.station for c in self._session.clients_of(ap.bssid)]
        captured = ap

        def on_dismissed(req) -> None:
            if req is None:
                self.notify("cancelled")
                return
            if self._hopper is not None:
                self._hopper.lock(captured.channel)
            self._launch_handshake_worker(captured, req)

        self.push_screen(
            HandshakeModal(
                ap_bssid=ap.bssid,
                ap_essid=ap.essid,
                ap_channel=ap.channel,
                clients=clients,
                mfp_status=ap.mfp_status,
            ),
            on_dismissed,
        )

    def _launch_handshake_worker(self, ap: APRecord, req: Any) -> None:
        from cyberm4fia_wifi.plugins.handshake import HandshakePlugin

        plugin = HandshakePlugin()
        self.notify(
            f"capture started: {ap.essid or ap.bssid} ch{ap.channel} "
            f"({'auto-deauth' if req.auto_deauth else 'passive'})",
            timeout=5,
        )
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
            ),
            thread=True,
            description="handshake",
        )

    def action_deauth_prompt(self) -> None:
        self.notify(
            "'d' alone is reserved. Use 'h' — the handshake modal has an "
            "Auto-deauth toggle; the log shows every frame as it goes out.",
            timeout=8,
        )


_ENC_STYLES = {
    "OPEN": "red",
    "WEP": "red",
    "WPA-PSK": "yellow",
    "WPA2-PSK": "yellow",
    "WPA3-SAE": "green",
    "WPA/WPA2-MIXED": "yellow",
}


def _resolve_gate():
    from cyberm4fia_wifi.core.auth import AuthorizationGate

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


def _clip(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return f"{value[: width - 1]}…"
