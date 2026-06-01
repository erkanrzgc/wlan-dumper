"""Append-mode pcap writer.

scapy's ``PcapWriter`` supports ``append=True``, but it does not create the
parent directory and refuses an empty list. This wrapper does both, and forces
``sync=True`` so a crash mid-capture still leaves a valid pcap on disk.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any


def _scapy() -> Any:
    import scapy.all

    return scapy.all


def append_packets(path: Path, packets: Iterable[Any], *, linktype: int | None = None) -> None:
    """Append ``packets`` to the pcap at ``path`` (creates if missing).

    ``linktype`` pins the libpcap DLT written into a *new* file's global header
    (e.g. ``127`` = ``DLT_IEEE802_11_RADIO`` for radiotap-prefixed 802.11). It
    matters because downstream tooling such as ``hcxpcapngtool`` keys off this
    header: a radiotap frame saved under the wrong DLT (scapy's default
    ``DLT_EN10MB``) is silently unreadable. When appending to an existing file
    the DLT comes from that file's header and ``linktype`` is ignored.
    """
    pkt_list = list(packets)
    if not pkt_list:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    s = _scapy()
    writer = s.PcapWriter(str(path), append=path.exists(), sync=True, linktype=linktype)
    try:
        for pkt in pkt_list:
            writer.write(pkt)
    finally:
        writer.close()
