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
    import scapy.all  # noqa: PLC0415

    return scapy.all


_ACK = 1 << 7
_MIC = 1 << 8
_INSTALL = 1 << 6
_SECURE = 1 << 9


def message_index(pkt: Any) -> int | None:
    """Return 1, 2, 3, or 4 for a WPA 4-way handshake key frame; None otherwise."""
    s = _scapy()
    EAPOL = s.EAPOL  # noqa: N806
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
