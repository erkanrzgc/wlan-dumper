"""scapy-based 802.11 sniffer.

Two pieces:

- ``dissect_packet`` — a pure function that takes a scapy ``Packet`` and yields
  zero or more events. It owns all the per-frame knowledge (beacon ESSID/
  channel/encryption parsing, probe extraction, client identification from
  data frames). Pure functions are easy to test against synthetic packets.

- ``Sniffer`` — wraps ``scapy.AsyncSniffer`` on the configured interface and
  publishes everything ``dissect_packet`` produces to the event bus.

Encryption is derived from RSN / WPA information elements (vendor specific
OUI 00:50:F2). The cipher labels follow what airodump-ng prints
(``OPEN``, ``WEP``, ``WPA-PSK``, ``WPA2-PSK``, ``WPA3-SAE``,
``WPA2/3-MIXED``).
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from typing import Any

from wlan_dumper.core.events import (
    BeaconSeen,
    ClientSeen,
    EAPOLCapture,
    Event,
    EventBus,
    ProbeSeen,
)

# scapy is required at runtime; tests that exercise dissect_packet build
# scapy packets directly. We do not import scapy at module top to keep import
# time fast for callers that only touch the dataclasses.


def _scapy() -> Any:
    import scapy.all

    return scapy.all


def _signal_from_radiotap(pkt: Any) -> int:
    """Read dBm signal from RadioTap if present, else default to 0."""
    try:
        RadioTap = _scapy().RadioTap
    except AttributeError:
        return 0
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        sig = getattr(rt, "dBm_AntSignal", None)
        if sig is not None:
            return int(sig)
    return 0


def _extract_essid(elt: Any) -> str | None:
    """Read the SSID from a Dot11Elt chain (ID=0). None if hidden/empty."""
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            info = bytes(getattr(elt, "info", b"") or b"")
            if not info or all(b == 0 for b in info):
                return None
            try:
                return info.decode("utf-8", errors="replace")
            except Exception:
                return info.decode("latin-1", errors="replace")
        elt = getattr(elt, "payload", None) if elt is not None else None
    return None


def _extract_channel(elt: Any) -> int:
    """Read the channel from the DS Parameter Set IE (ID=3); 0 if absent."""
    while elt is not None:
        if getattr(elt, "ID", None) == 3:
            info = bytes(getattr(elt, "info", b"") or b"")
            if info:
                return int(info[0])
        elt = getattr(elt, "payload", None) if elt is not None else None
    return 0


def _extract_encryption(pkt: Any) -> str:
    """Walk the IEs once and label encryption like airodump-ng does."""
    has_rsn = False
    has_wpa = False
    sae = False

    try:
        Dot11Elt = _scapy().Dot11Elt
        Dot11EltVendorSpecific = _scapy().Dot11EltVendorSpecific
        Dot11EltRSN = getattr(_scapy(), "Dot11EltRSN", None)
    except AttributeError:
        return "OPEN"

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if Dot11EltRSN is not None and isinstance(elt, Dot11EltRSN):
            has_rsn = True
            akm = getattr(elt, "akm_suites", None) or []
            for suite in akm:
                if getattr(suite, "suite", None) == 8:  # SAE
                    sae = True
        elif isinstance(elt, Dot11EltVendorSpecific):
            oui = getattr(elt, "oui", 0)
            if oui == 0x0050F2 and getattr(elt, "info", b"")[0:1] == b"\x01":
                has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn and has_wpa:
        return "WPA/WPA2-MIXED"
    if has_rsn and sae:
        return "WPA3-SAE"
    if has_rsn:
        return "WPA2-PSK"
    if has_wpa:
        return "WPA-PSK"

    # Privacy bit but no RSN/WPA → WEP
    if (getattr(pkt, "cap", 0) & 0x10) != 0:
        return "WEP"
    return "OPEN"


def _has_wps_ie(elt: Any) -> bool:
    """True iff a Wi-Fi Protected Setup IE (vendor specific OUI 0x0050F2, type 0x04) is present."""
    try:
        Dot11Elt = _scapy().Dot11Elt
        Dot11EltVendorSpecific = _scapy().Dot11EltVendorSpecific
    except AttributeError:
        return False
    while elt is not None:
        if isinstance(elt, Dot11EltVendorSpecific):
            oui = getattr(elt, "oui", 0)
            info = bytes(getattr(elt, "info", b"") or b"")
            if oui == 0x0050F2 and info[:1] == b"\x04":
                return True
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, "payload") else None
    return False


def _mfp_status(pkt: Any) -> str:
    """Read MFP capable / required bits from the RSN Capabilities field.

    Returns ``required`` / ``capable`` / ``none`` when an RSN IE is present,
    ``unknown`` otherwise.
    """
    try:
        Dot11EltRSN = getattr(_scapy(), "Dot11EltRSN", None)
    except AttributeError:
        return "unknown"
    if Dot11EltRSN is None:
        return "unknown"
    rsn = pkt.getlayer(Dot11EltRSN)
    if rsn is None:
        return "unknown"
    capable = bool(getattr(rsn, "mfp_capable", 0))
    required = bool(getattr(rsn, "mfp_required", 0))
    if required:
        return "required"
    if capable:
        return "capable"
    return "none"


def dissect_packet(pkt: Any, *, now: float | None = None) -> list[Event]:
    """Convert a single 802.11 frame into zero or more events."""
    s = _scapy()
    Dot11 = s.Dot11
    Dot11Beacon = s.Dot11Beacon
    Dot11Elt = s.Dot11Elt
    Dot11ProbeReq = s.Dot11ProbeReq
    Dot11ProbeResp = getattr(s, "Dot11ProbeResp", None)

    if not pkt.haslayer(Dot11):
        return []

    ts = time.time() if now is None else now
    out: list[Event] = []

    dot11 = pkt[Dot11]

    if pkt.haslayer(Dot11Beacon):
        bssid = (dot11.addr3 or dot11.addr2 or "").lower()
        if bssid:
            essid = _extract_essid(pkt.getlayer(Dot11Elt))
            channel = _extract_channel(pkt.getlayer(Dot11Elt))
            beacon = pkt[Dot11Beacon]
            # cap is on Dot11Beacon (and Dot11ProbeResp); attach to pkt for _extract_encryption
            pkt.cap = getattr(beacon, "cap", 0)
            encryption = _extract_encryption(pkt)
            wps = _has_wps_ie(pkt.getlayer(Dot11Elt))
            # beacon_interval is in TUs (1 TU = 1.024 ms); convert to ms.
            interval_tu = int(getattr(beacon, "beacon_interval", 0) or 0)
            interval_ms = round(interval_tu * 1.024) if interval_tu else 0
            out.append(
                BeaconSeen(
                    timestamp=ts,
                    bssid=bssid,
                    essid=essid,
                    channel=channel,
                    encryption=encryption,
                    signal_dbm=_signal_from_radiotap(pkt),
                    wps=wps,
                    beacon_interval_ms=interval_ms,
                    mfp_status=_mfp_status(pkt),
                )
            )
        return out

    EAPOL = getattr(s, "EAPOL", None)
    if EAPOL is not None and pkt.haslayer(EAPOL):
        from wlan_dumper.utils.eapol import message_index

        bssid = (dot11.addr3 or dot11.addr1 or "").lower()
        station = (dot11.addr2 or "").lower()
        if bssid and station:
            out.append(
                EAPOLCapture(
                    timestamp=ts,
                    bssid=bssid,
                    station=station,
                    message_index=message_index(pkt),
                    raw=bytes(pkt),
                )
            )
        return out

    if pkt.haslayer(Dot11ProbeReq):
        station = (dot11.addr2 or "").lower()
        if station:
            essid = _extract_essid(pkt.getlayer(Dot11Elt))
            out.append(
                ProbeSeen(
                    timestamp=ts,
                    station=station,
                    essid=essid,
                    signal_dbm=_signal_from_radiotap(pkt),
                )
            )
        return out

    if Dot11ProbeResp is not None and pkt.haslayer(Dot11ProbeResp):
        bssid = (dot11.addr3 or dot11.addr2 or "").lower()
        client = (dot11.addr1 or "").lower()
        if bssid and client and not _is_broadcast(client):
            out.append(
                ClientSeen(
                    timestamp=ts,
                    bssid=bssid,
                    station=client,
                    signal_dbm=_signal_from_radiotap(pkt),
                )
            )
        return out

    # Data frame: type=2 in FCfield. Extract (bssid, client) pair when possible.
    fcfield = int(getattr(dot11, "type", -1))
    if fcfield == 2:
        addr1 = (dot11.addr1 or "").lower()
        addr2 = (dot11.addr2 or "").lower()
        addr3 = (dot11.addr3 or "").lower()
        # Heuristic: in to-DS frames addr1=BSSID, addr2=client; in from-DS
        # frames addr1=client, addr2=BSSID. addr3 is the other endpoint.
        data_bssid = ""
        client = ""
        if not _is_broadcast(addr1) and not _is_broadcast(addr2):
            # Without parsing FCfield.ToDS/FromDS we pick the safer pair: addr3
            # is always either BSSID or remote endpoint; treat addr2 as station.
            data_bssid = addr3 or addr1
            client = addr2
        if data_bssid and client:
            out.append(
                ClientSeen(
                    timestamp=ts,
                    bssid=data_bssid,
                    station=client,
                    signal_dbm=_signal_from_radiotap(pkt),
                )
            )
    return out


def _is_broadcast(mac: str) -> bool:
    return mac in ("", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")


# ---- Sniffer wrapper -------------------------------------------------------


@dataclass
class Sniffer:
    iface: str
    bus: EventBus
    _async_sniffer: Any = field(default=None, init=False, repr=False)

    def _on_packet(self, pkt: Any) -> None:
        for evt in dissect_packet(pkt):
            self.bus.publish(evt)

    def start(self) -> None:
        s = _scapy()
        self._async_sniffer = s.AsyncSniffer(
            iface=self.iface,
            prn=self._on_packet,
            store=False,
            monitor=True,
        )
        self._async_sniffer.start()

    def stop(self) -> None:
        if self._async_sniffer is not None:
            with contextlib.suppress(Exception):
                self._async_sniffer.stop()
            self._async_sniffer = None
