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
    import scapy.all  # noqa: PLC0415

    return scapy.all


def append_packets(path: Path, packets: Iterable[Any]) -> None:
    """Append ``packets`` to the pcap at ``path`` (creates if missing)."""
    pkt_list = list(packets)
    if not pkt_list:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    s = _scapy()
    writer = s.PcapWriter(str(path), append=path.exists(), sync=True)
    try:
        for pkt in pkt_list:
            writer.write(pkt)
    finally:
        writer.close()
