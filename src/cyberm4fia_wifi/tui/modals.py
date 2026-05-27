"""Confirm-action modals for risk=active/high plugins."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

_NO_REASON_MODES = {"lab", "ctf"}  # operator pre-acknowledged the scope


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
    HandshakeModal {
        align: center middle;
    }
    #modal {
        width: 64;
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
        width: 18;
        content-align: right middle;
        color: $text-muted;
        padding-right: 1;
    }
    Input, Select {
        width: 1fr;
    }
    Checkbox {
        height: 3;
        background: transparent;
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
        mode: str = "general",
    ) -> None:
        super().__init__()
        self._bssid = ap_bssid
        self._essid = ap_essid or "<hidden>"
        self._channel = ap_channel
        self._clients = clients
        self._mfp = mfp_status
        self._mode = mode

    @property
    def _reason_required(self) -> bool:
        return self._mode not in _NO_REASON_MODES

    def compose(self) -> ComposeResult:
        with Container(id="modal"):
            yield Static(
                f"Capture handshake — {self._essid}",
                id="title",
            )
            yield Static(
                f"{self._bssid} · ch {self._channel} · mode={self._mode}",
                classes="meta",
            )
            yield Static(self._mfp_text(), id="mfp_warn", classes=self._mfp_class())

            options = [("broadcast", "broadcast")] + [(c, c) for c in self._clients]
            with Horizontal(classes="field_row"):
                yield Label("Target STA:", classes="field_label")
                yield Select(options=options, value="broadcast", id="sta_select")

            with Horizontal(classes="field_row"):
                yield Label("Auto-deauth:", classes="field_label")
                yield Checkbox("send burst to provoke reconnect", value=True, id="auto_deauth")

            with Horizontal(classes="field_row"):
                yield Label("Burst count:", classes="field_label")
                yield Input(value="8", id="count_input", type="integer")

            with Horizontal(classes="field_row"):
                yield Label("Timeout (s):", classes="field_label")
                yield Input(value="60", id="timeout_input", type="integer")

            if self._reason_required:
                with Horizontal(classes="field_row"):
                    yield Label("Reason:", classes="field_label")
                    yield Input(
                        placeholder="why you're authorized to do this",
                        id="reason_input",
                    )
            else:
                yield Static(
                    f"Mode '{self._mode}' — reason auto-logged, no prompt.",
                    classes="meta dim",
                )

            if self._mfp == "required":
                with Horizontal(classes="field_row"):
                    yield Label("MFP override:", classes="field_label")
                    yield Checkbox(
                        "try deauth anyway (usually ineffective)",
                        value=False, id="mfp_override",
                    )

            with Horizontal(id="row_buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button(
                    "Start",
                    id="start_btn",
                    variant="primary",
                    disabled=self._reason_required,
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
            if self._reason_required:
                reason = self.query_one("#reason_input", Input).value.strip()
            else:
                reason = f"{self._mode} mode"
            self.dismiss(
                HandshakeRequest(
                    target_station=target_sta,
                    auto_deauth=self.query_one("#auto_deauth", Checkbox).value,
                    deauth_count=int(self.query_one("#count_input", Input).value or "8"),
                    timeout=int(self.query_one("#timeout_input", Input).value or "60"),
                    reason=reason,
                    override_mfp=override,
                )
            )
