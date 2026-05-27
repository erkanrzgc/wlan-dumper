"""Event bus and event dataclasses.

The bus is a tiny synchronous pub/sub used by the sniffer thread to publish
802.11 observations to the TUI and any active plugin. Handlers are invoked on
the publishing thread; consumers that need to hop to another thread or event
loop are responsible for that (the Textual TUI uses ``App.call_from_thread``).

Each event is a frozen dataclass so that handlers cannot mutate shared state
through events. Only ``BeaconSeen``, ``ProbeSeen``, ``ClientSeen`` and
``ChannelChanged`` are emitted in Phase 1; the rest are declared now so
later-phase plugins inherit a stable contract.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar


@dataclass(frozen=True, slots=True)
class Event:
    """Base class for all events. ``timestamp`` is a POSIX float (``time.time()``)."""

    timestamp: float


@dataclass(frozen=True, slots=True)
class BeaconSeen(Event):
    bssid: str
    essid: str | None  # None for hidden networks
    channel: int
    encryption: str  # "OPEN" | "WEP" | "WPA-PSK" | "WPA2-PSK" | "WPA3-SAE" | "WPA2/3-MIXED"
    signal_dbm: int


@dataclass(frozen=True, slots=True)
class ProbeSeen(Event):
    station: str
    essid: str | None
    signal_dbm: int


@dataclass(frozen=True, slots=True)
class ClientSeen(Event):
    bssid: str  # AP the client is associated with (or directed probing at)
    station: str
    signal_dbm: int


@dataclass(frozen=True, slots=True)
class EAPOLCapture(Event):
    """Phase 2 only — declared now to lock the contract."""

    bssid: str
    station: str
    message_index: int  # 1..4 of the 4-way handshake
    pcap_offset: int


@dataclass(frozen=True, slots=True)
class PMKIDFound(Event):
    """Phase 2 only — declared now to lock the contract."""

    bssid: str
    pmkid_hex: str


@dataclass(frozen=True, slots=True)
class ChannelChanged(Event):
    channel: int


@dataclass(frozen=True, slots=True)
class PluginStarted(Event):
    plugin: str


@dataclass(frozen=True, slots=True)
class PluginFinished(Event):
    plugin: str
    exit_code: int


@dataclass(frozen=True, slots=True)
class PluginError(Event):
    plugin: str
    message: str


E = TypeVar("E", bound=Event)
Handler = Callable[[E], None]


class EventBus:
    """Synchronous, thread-safe pub/sub keyed by event class.

    Subscribers register against an event class and receive only instances of
    that exact class (no isinstance fan-out — keep it explicit). Handlers are
    invoked on the publishing thread, in registration order. A handler raising
    an exception does not stop later handlers; the bus collects exceptions and
    returns them from ``publish`` so the caller can log them.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[Event], list[Handler[Event]]] = {}
        self._lock = threading.RLock()

    def subscribe(self, event_type: type[E], handler: Handler[E]) -> None:
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)  # type: ignore[arg-type]

    def unsubscribe(self, event_type: type[E], handler: Handler[E]) -> None:
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event: Event) -> list[BaseException]:
        with self._lock:
            handlers = list(self._handlers.get(type(event), []))

        errors: list[BaseException] = []
        for h in handlers:
            try:
                h(event)
            except BaseException as exc:
                errors.append(exc)
        return errors

    def clear(self) -> None:
        with self._lock:
            self._handlers.clear()
