"""EAPOL key-frame parsing — return the 4-way handshake message index.

The WPA 4-way handshake is four EAPOL-Key frames. Their position (1, 2, 3, 4)
is encoded in the Key Information field of the key descriptor, per IEEE
802.11-2016 §12.7.6. We decode just enough bits to disambiguate:

  message 1 (AP → STA): ack=1, mic=0, install=0
  message 2 (STA → AP): ack=0, mic=1, install=0, secure=0
  message 3 (AP → STA): ack=1, mic=1, install=1
  message 4 (STA → AP): ack=0, mic=1, install=0, secure=1
"""

from __future__ import annotations

from typing import Any


def _scapy() -> Any:
    import scapy.all

    return scapy.all


_ACK = 1 << 7
_MIC = 1 << 8
_INSTALL = 1 << 6
_SECURE = 1 << 9


def message_index(pkt: Any) -> int | None:
    """Return 1, 2, 3, or 4 for a WPA 4-way handshake key frame; None otherwise."""
    s = _scapy()
    EAPOL = s.EAPOL
    if not pkt.haslayer(EAPOL):
        return None

    eapol = pkt[EAPOL]
    if int(getattr(eapol, "type", -1)) != 3:
        return None

    payload = bytes(eapol.payload)
    if len(payload) < 3:
        return None

    key_info = int.from_bytes(payload[1:3], "big")
    ack = bool(key_info & _ACK)
    mic = bool(key_info & _MIC)
    install = bool(key_info & _INSTALL)
    secure = bool(key_info & _SECURE)

    if ack and not mic and not install:
        return 1
    if mic and not ack and not install and not secure:
        return 2
    if ack and mic and install:
        return 3
    if mic and not ack and not install and secure:
        return 4
    return None


def replay_counter(pkt: Any) -> int | None:
    """Return the 64-bit EAPOL-Key Replay Counter, or None if unparseable.

    A matched 4-way handshake pair shares one replay counter: M1↔M2 use the
    AP's counter N, M3↔M4 use N+1. Comparing counters is how we tell whether
    two captured frames belong to the *same* exchange (vs. a broadcast-deauth
    storm where frames from different clients get interleaved).
    """
    s = _scapy()
    EAPOL = s.EAPOL
    if not pkt.haslayer(EAPOL):
        return None
    eapol = pkt[EAPOL]
    if int(getattr(eapol, "type", -1)) != 3:
        return None
    payload = bytes(eapol.payload)
    # key descriptor: [0]=type, [1:3]=key_info, [3:5]=key_len, [5:13]=replay
    if len(payload) < 13:
        return None
    return int.from_bytes(payload[5:13], "big")
