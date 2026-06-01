"""Confirm-action modal for the handshake plugin.

No mode system, no reason prompt — the operator is an ethical security pro
and already acknowledged the legal notice at first launch. The modal exists
only to pick the target client, configure the deauth burst, and warn about
MFP when the AP advertises it.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from wlan_dumper.core.crack import DEFAULT_RATES as _CRACK_RATES
from wlan_dumper.core.crack import (
    CrackError,
    detect_backend,
    eta_seconds,
    humanize_count,
    humanize_duration,
    mask_keyspace,
)


def _positive_int(raw: str | None, *, default: int) -> int:
    """Parse the input field as a positive int; fall back to default on garbage.

    Input(type='integer') already filters non-digit keystrokes, but the
    operator can still leave the field empty or paste a negative sign. We
    coerce anything < 1 to the default so the worker thread never sees a
    nonsense count/timeout.
    """
    try:
        value = int((raw or "").strip())
    except (TypeError, ValueError):
        return default
    return value if value >= 1 else default


@dataclass
class HandshakeRequest:
    target_station: str | None
    auto_deauth: bool
    deauth_count: int
    timeout: int
    override_mfp: bool


class HandshakeModal(ModalScreen[HandshakeRequest | None]):
    DEFAULT_CSS = """
    HandshakeModal {
        align: center middle;
    }
    #modal {
        width: 60;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #title {
        text-style: bold;
        margin-bottom: 1;
    }
    #mfp_warn {
        margin-bottom: 1;
        text-align: center;
    }
    #mfp_warn.required { color: $error; text-style: bold; }
    #mfp_warn.capable  { color: $warning; }
    #mfp_warn.none     { color: $success-darken-2; text-style: dim; }
    .field_row {
        height: 3;
        margin-bottom: 1;
    }
    .field_label {
        width: 16;
        content-align: right middle;
        color: $text-muted;
        padding-right: 1;
    }
    Input, Select {
        width: 1fr;
    }
    Checkbox {
        height: 3;
        width: auto;
        background: transparent;
    }
    #auto_deauth_state {
        width: auto;
        content-align: left middle;
        padding-left: 2;
    }
    #row_buttons {
        align: right middle;
        height: 3;
        margin-top: 1;
    }
    #start_btn { margin-left: 1; }
    """

    def __init__(
        self,
        *,
        ap_bssid: str,
        ap_essid: str | None,
        ap_channel: int,
        clients: list[str],
        mfp_status: str,
    ) -> None:
        super().__init__()
        self._bssid = ap_bssid
        self._essid = ap_essid or "<hidden>"
        self._channel = ap_channel
        self._clients = clients
        self._mfp = mfp_status

    def compose(self) -> ComposeResult:
        with Container(id="modal"):
            yield Static(f"Capture handshake — {self._essid}", id="title")
            yield Static(f"{self._bssid} · ch {self._channel}", classes="meta")
            yield Static(self._mfp_text(), id="mfp_warn", classes=self._mfp_class())

            options = [("broadcast", "broadcast")] + [(c, c) for c in self._clients]
            with Horizontal(classes="field_row"):
                yield Label("Target STA:", classes="field_label")
                yield Select(options=options, value="broadcast", id="sta_select")

            with Horizontal(classes="field_row"):
                yield Label("Auto-deauth:", classes="field_label")
                yield Checkbox("provoke reconnect", value=True, id="auto_deauth")
                yield Static(self._deauth_state_text(True), id="auto_deauth_state")

            with Horizontal(classes="field_row"):
                yield Label("Burst count:", classes="field_label")
                yield Input(value="8", id="count_input", type="integer")

            with Horizontal(classes="field_row"):
                yield Label("Timeout (s):", classes="field_label")
                yield Input(value="60", id="timeout_input", type="integer")

            if self._mfp == "required":
                with Horizontal(classes="field_row"):
                    yield Label("MFP override:", classes="field_label")
                    yield Checkbox(
                        "try anyway (usually ineffective)",
                        value=False,
                        id="mfp_override",
                    )

            with Horizontal(id="row_buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button("Start", id="start_btn", variant="primary")

    def _deauth_state_text(self, on: bool) -> Text:
        """Big unambiguous ON/OFF tag so the checkbox state can't be misread."""
        if on:
            return Text("▶ ON — will deauth", style="bold green")
        return Text("■ OFF — capture only", style="bold red")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "auto_deauth":
            self.query_one("#auto_deauth_state", Static).update(
                self._deauth_state_text(event.value)
            )

    def _mfp_text(self) -> str:
        if self._mfp == "required":
            return "⚠  MFP REQUIRED — deauth almost certainly ignored"
        if self._mfp == "capable":
            return "MFP capable — deauth may be inconsistent"
        if self._mfp == "none":
            return "MFP not detected — deauth should work"
        return "MFP unknown"

    def _mfp_class(self) -> str:
        return {
            "required": "required",
            "capable": "capable",
            "none": "none",
        }.get(self._mfp, "")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_btn":
            self.dismiss(None)
            return
        if event.button.id == "start_btn":
            sta = self.query_one("#sta_select", Select).value
            target_sta: str | None = None if sta == "broadcast" else str(sta)
            override = False
            if self._mfp == "required":
                override = bool(self.query_one("#mfp_override", Checkbox).value)
            self.dismiss(
                HandshakeRequest(
                    target_station=target_sta,
                    auto_deauth=self.query_one("#auto_deauth", Checkbox).value,
                    deauth_count=_positive_int(
                        self.query_one("#count_input", Input).value, default=8
                    ),
                    timeout=_positive_int(
                        self.query_one("#timeout_input", Input).value, default=60
                    ),
                    override_mfp=override,
                )
            )


# Common starting points so the operator isn't typing paths from scratch.
_COMMON_WORDLISTS = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
)
# Curated masks ordered by real-world hit rate (ISP routers first).
_COMMON_MASKS = (
    ("8 digits (ISP default)", "?d?d?d?d?d?d?d?d"),
    ("10 digits (phone)", "?d?d?d?d?d?d?d?d?d?d"),
    ("8 lower-alpha", "?l?l?l?l?l?l?l?l"),
)


@dataclass
class CrackRequest:
    mode: str  # "wordlist" | "mask" | "smart"
    wordlist: str | None
    mask: str | None


class CrackModal(ModalScreen["CrackRequest | None"]):
    """Configure an offline crack: mode, wordlist/mask, with live keyspace+ETA.

    The ETA panel recomputes as the mask changes so the operator can make a
    go/no-go decision before committing CPU/GPU hours.
    """

    DEFAULT_CSS = """
    CrackModal { align: center middle; }
    #modal {
        width: 64;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #title { text-style: bold; margin-bottom: 1; }
    #eta { margin: 1 0; text-align: center; text-style: bold; }
    .field_row { height: 3; margin-bottom: 1; }
    .field_label { width: 14; content-align: right middle; color: $text-muted; padding-right: 1; }
    Input, Select { width: 1fr; }
    #row_buttons { align: right middle; height: 3; margin-top: 1; }
    #start_btn { margin-left: 1; }
    """

    def __init__(self, *, ap_bssid: str, ap_essid: str | None) -> None:
        super().__init__()
        self._bssid = ap_bssid
        self._essid = ap_essid or "<hidden>"
        try:
            self._backend = detect_backend()
        except CrackError:
            self._backend = "—"

    def compose(self) -> ComposeResult:
        with Container(id="modal"):
            yield Static(f"Crack — {self._essid}", id="title")
            yield Static(f"{self._bssid} · backend: {self._backend}", classes="meta")

            mode_opts = [("wordlist", "wordlist"), ("mask / brute", "mask"), ("smart", "smart")]
            with Horizontal(classes="field_row"):
                yield Label("Mode:", classes="field_label")
                yield Select(options=mode_opts, value="wordlist", id="mode_select")

            with Horizontal(classes="field_row"):
                yield Label("Wordlist:", classes="field_label")
                yield Input(value=_COMMON_WORDLISTS[0], id="wordlist_input")

            with Horizontal(classes="field_row"):
                yield Label("Mask:", classes="field_label")
                yield Input(
                    value=_COMMON_MASKS[0][1],
                    placeholder="?d?d?d?d?d?d?d?d",
                    id="mask_input",
                )

            yield Static(self._eta_text("?d?d?d?d?d?d?d?d"), id="eta")

            with Horizontal(id="row_buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button("Start", id="start_btn", variant="primary")

    def _eta_text(self, mask: str) -> str:
        try:
            ks = mask_keyspace(mask)
        except CrackError:
            return "invalid mask"
        rate = _CRACK_RATES.get(self._backend)
        eta = eta_seconds(ks, rate) if rate else None
        return f"keyspace {humanize_count(ks)} · ~{humanize_duration(eta)} @ {self._backend}"

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "mask_input":
            self.query_one("#eta", Static).update(self._eta_text(event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_btn":
            self.dismiss(None)
            return
        if event.button.id == "start_btn":
            mode = str(self.query_one("#mode_select", Select).value)
            wordlist = self.query_one("#wordlist_input", Input).value.strip() or None
            mask = self.query_one("#mask_input", Input).value.strip() or None
            self.dismiss(CrackRequest(mode=mode, wordlist=wordlist, mask=mask))
