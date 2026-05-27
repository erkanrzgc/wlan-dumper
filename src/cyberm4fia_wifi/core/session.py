"""In-memory authoritative state for a scan session.

The session owns:
- a dict of APs keyed by BSSID
- a dict of clients keyed by (BSSID, station)
- the currently active channel (per the hopper's last ``ChannelChanged``)

The sniffer thread writes via ``handle_event``; the TUI reads via the snapshot
helpers. A single ``RLock`` guards both maps; reads return fresh lists so the
caller cannot accidentally mutate state.

JSON persistence is opt-in; the format is intentionally simple so it can be
inspected with ``jq`` and is forward-compatible (unknown keys are ignored on
load).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ChannelChanged,
    ClientSeen,
    Event,
    EventBus,
    HandshakeComplete,
)

_SCHEMA_VERSION = 1


@dataclass(slots=True)
class APRecord:
    bssid: str
    essid: str | None
    channel: int
    encryption: str
    signal_dbm: int
    first_seen: float
    last_seen: float
    beacon_count: int = 0
    data_count: int = 0
    wps: bool = False
    beacon_interval_ms: int = 0
    handshake_count: int = 0
    mfp_status: str = "unknown"


@dataclass(slots=True)
class ClientRecord:
    bssid: str
    station: str
    signal_dbm: int
    first_seen: float
    last_seen: float
    frames: int = 0
    probes: list[str] = field(default_factory=list)


class Session:
    """Thread-safe scan state container."""

    def __init__(self) -> None:
        self._aps: dict[str, APRecord] = {}
        self._clients: dict[tuple[str, str], ClientRecord] = {}
        self._active_channel: int | None = None
        self._lock = threading.RLock()

    # ---- public read API ----------------------------------------------------

    @property
    def active_channel(self) -> int | None:
        with self._lock:
            return self._active_channel

    def aps_snapshot(self) -> list[APRecord]:
        with self._lock:
            return [replace(ap) for ap in self._aps.values()]

    def clients_of(self, bssid: str) -> list[ClientRecord]:
        with self._lock:
            return [replace(c) for (b, _), c in self._clients.items() if b == bssid]

    # ---- public write API ---------------------------------------------------

    def handle_event(self, event: Event) -> None:
        if isinstance(event, BeaconSeen):
            self._upsert_ap(event)
        elif isinstance(event, ClientSeen):
            self._upsert_client(event)
        elif isinstance(event, ChannelChanged):
            with self._lock:
                self._active_channel = event.channel
        elif isinstance(event, HandshakeComplete):
            with self._lock:
                ap = self._aps.get(event.bssid) or self._aps.get(event.bssid.lower())
                # Try uppercase too — BSSIDs may be stored either case depending
                # on what the sniffer normalises.
                if ap is None:
                    for key, candidate in self._aps.items():
                        if key.lower() == event.bssid.lower():
                            ap = candidate
                            break
                if ap is not None:
                    ap.handshake_count += 1

    def attach(self, bus: EventBus) -> None:
        """Subscribe to the event types this session cares about."""
        bus.subscribe(BeaconSeen, self.handle_event)
        bus.subscribe(ClientSeen, self.handle_event)
        bus.subscribe(ChannelChanged, self.handle_event)
        bus.subscribe(HandshakeComplete, self.handle_event)

    # ---- persistence --------------------------------------------------------

    def dump_json(self, path: Path) -> None:
        with self._lock:
            payload: dict[str, Any] = {
                "schema": _SCHEMA_VERSION,
                "active_channel": self._active_channel,
                "aps": [asdict(ap) for ap in self._aps.values()],
                "clients": [asdict(c) for c in self._clients.values()],
            }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    @classmethod
    def load_json(cls, path: Path) -> Session:
        payload = json.loads(path.read_text())
        sess = cls()
        with sess._lock:
            sess._active_channel = payload.get("active_channel")
            for ap_dict in payload.get("aps", []):
                ap = APRecord(**_filter_kwargs(ap_dict, APRecord))
                sess._aps[ap.bssid] = ap
            for c_dict in payload.get("clients", []):
                c = ClientRecord(**_filter_kwargs(c_dict, ClientRecord))
                sess._clients[(c.bssid, c.station)] = c
        return sess

    # ---- internals ----------------------------------------------------------

    def _upsert_ap(self, evt: BeaconSeen) -> None:
        with self._lock:
            existing = self._aps.get(evt.bssid)
            if existing is None:
                self._aps[evt.bssid] = APRecord(
                    bssid=evt.bssid,
                    essid=evt.essid,
                    channel=evt.channel,
                    encryption=evt.encryption,
                    signal_dbm=evt.signal_dbm,
                    first_seen=evt.timestamp,
                    last_seen=evt.timestamp,
                    beacon_count=1,
                    wps=evt.wps,
                    beacon_interval_ms=evt.beacon_interval_ms,
                    mfp_status=evt.mfp_status,
                )
                return

            existing.last_seen = evt.timestamp
            existing.beacon_count += 1
            existing.signal_dbm = evt.signal_dbm
            existing.channel = evt.channel
            existing.encryption = evt.encryption
            # Sticky bits: WPS / beacon-interval are stable across beacons but
            # IE walks can occasionally miss one — keep the strongest signal.
            existing.wps = existing.wps or evt.wps
            if evt.beacon_interval_ms:
                existing.beacon_interval_ms = evt.beacon_interval_ms
            # MFP status: an 'unknown' beacon must never wipe a known verdict.
            if evt.mfp_status != "unknown":
                existing.mfp_status = evt.mfp_status
            # Promote a known ESSID over a previously-hidden None, but never
            # overwrite a real ESSID with None (a hidden beacon arriving later).
            if evt.essid is not None:
                existing.essid = evt.essid

    def _upsert_client(self, evt: ClientSeen) -> None:
        with self._lock:
            key = (evt.bssid, evt.station)
            existing = self._clients.get(key)
            if existing is None:
                self._clients[key] = ClientRecord(
                    bssid=evt.bssid,
                    station=evt.station,
                    signal_dbm=evt.signal_dbm,
                    first_seen=evt.timestamp,
                    last_seen=evt.timestamp,
                    frames=1,
                )
            else:
                existing.last_seen = evt.timestamp
                existing.signal_dbm = evt.signal_dbm
                existing.frames += 1

            # Bump the parent AP's data-frame count when we know the AP.
            # ClientSeen is emitted from data frames and probe responses; both
            # are evidence that the AP has live RF activity.
            ap = self._aps.get(evt.bssid)
            if ap is not None:
                ap.data_count += 1


def _filter_kwargs(raw: dict[str, Any], cls: type) -> dict[str, Any]:
    """Drop keys that aren't fields of ``cls`` so unknown JSON keys load cleanly."""
    valid: Iterable[str] = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    return {k: v for k, v in raw.items() if k in valid}
