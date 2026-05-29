"""Tests for the append-mode pcap writer."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import IP, Ether, rdpcap

from wlan_dumper.utils.pcap_writer import append_packets


def _pkt(payload: str) -> Ether:
    return Ether() / IP(dst="10.0.0.1") / payload.encode()


class TestAppendPackets:
    def test_writes_packets_when_file_absent(self, tmp_path: Path) -> None:
        out = tmp_path / "x.pcap"
        append_packets(out, [_pkt("a"), _pkt("b")])

        assert out.exists()
        read_back = rdpcap(str(out))
        assert len(read_back) == 2

    def test_appends_to_existing_file(self, tmp_path: Path) -> None:
        out = tmp_path / "x.pcap"
        append_packets(out, [_pkt("a")])
        append_packets(out, [_pkt("b"), _pkt("c")])

        read_back = rdpcap(str(out))
        assert len(read_back) == 3

    def test_empty_packet_list_is_noop(self, tmp_path: Path) -> None:
        out = tmp_path / "x.pcap"
        append_packets(out, [])
        assert not out.exists()

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "deep" / "x.pcap"
        append_packets(out, [_pkt("a")])
        assert out.exists()
