"""Confirm-action modals for risk=active/high plugins."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static


@dataclass
class HandshakeRequest:
    target_station: str | None
    auto_deauth: bool
    deauth_count: int
    timeout: int
    reason: str
    override_mfp: bool


class HandshakeModal(ModalScreen[HandshakeRequest | None]):
    DEFAULT_CSS = """
    HandshakeModal { align: center middle; }
    #modal { width: 70; height: auto; border: round $primary; padding: 1 2; }
    #mfp_warn { margin: 0 0 1 0; }
    #mfp_warn.required { color: $error; }
    #mfp_warn.capable { color: $warning; }
    Input, Select { width: 100%; }
    Horizontal#row_buttons { align: right middle; height: 3; }
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
            yield Label(
                f"Capture handshake for {self._essid} ({self._bssid}, ch {self._channel})"
            )
            yield Static(self._mfp_text(), id="mfp_warn", classes=self._mfp_class())
            options = [("broadcast", "broadcast")] + [(c, c) for c in self._clients]
            yield Label("Target STA:")
            yield Select(options=options, value="broadcast", id="sta_select")
            yield Checkbox("Auto-deauth", value=True, id="auto_deauth")
            yield Label("Deauth count:")
            yield Input(value="8", id="count_input")
            yield Label("Timeout (s):")
            yield Input(value="60", id="timeout_input")
            yield Label("Reason (required):")
            yield Input(placeholder="why you're allowed to do this", id="reason_input")
            if self._mfp == "required":
                yield Checkbox(
                    "Override MFP (probably ineffective)",
                    value=False, id="mfp_override",
                )
            with Horizontal(id="row_buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button("Start", id="start_btn", variant="primary", disabled=True)

    def _mfp_text(self) -> str:
        if self._mfp == "required":
            return "MFP required on this AP — deauth will be ignored unless overridden."
        if self._mfp == "capable":
            return "MFP capable — deauth may be inconsistent."
        return "MFP not detected."

    def _mfp_class(self) -> str:
        if self._mfp == "required":
            return "required"
        if self._mfp == "capable":
            return "capable"
        return ""

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "reason_input":
            start = self.query_one("#start_btn", Button)
            start.disabled = not event.value.strip()

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
                    deauth_count=int(self.query_one("#count_input", Input).value or "8"),
                    timeout=int(self.query_one("#timeout_input", Input).value or "60"),
                    reason=self.query_one("#reason_input", Input).value.strip(),
                    override_mfp=override,
                )
            )
