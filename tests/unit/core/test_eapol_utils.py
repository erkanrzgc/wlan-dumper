"""Tests for the EAPOL key-info → 4-way message index parser."""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import EAPOL

from wlan_dumper.utils.eapol import message_index, replay_counter

# Practical Key Information patterns per IEEE 802.11-2016 §12.7.6.
M1_KEY_INFO = 0x008A  # version=2, type=pairwise, ack=1
M2_KEY_INFO = 0x010A  # version=2, type=pairwise, mic=1
M3_KEY_INFO = 0x13CA  # install=1, ack=1, mic=1, secure=1
M4_KEY_INFO = 0x030A  # mic=1, secure=1


def _make_key_frame(key_info: int, replay: int = 0) -> EAPOL:
    body = bytes([2])
    body += key_info.to_bytes(2, "big")
    body += b"\x00\x00"  # key length
    body += replay.to_bytes(8, "big")  # replay counter
    body += b"\x00" * 81
    return EAPOL(version=2, type=3, len=len(body)) / body


class TestMessageIndex:
    def test_m1_has_index_1(self) -> None:
        assert message_index(_make_key_frame(M1_KEY_INFO)) == 1

    def test_m2_has_index_2(self) -> None:
        assert message_index(_make_key_frame(M2_KEY_INFO)) == 2

    def test_m3_has_index_3(self) -> None:
        assert message_index(_make_key_frame(M3_KEY_INFO)) == 3

    def test_m4_has_index_4(self) -> None:
        assert message_index(_make_key_frame(M4_KEY_INFO)) == 4

    def test_non_eapol_returns_none(self) -> None:
        from scapy.all import IP, Ether

        pkt = Ether() / IP(dst="1.1.1.1")
        assert message_index(pkt) is None

    def test_eapol_without_key_payload_returns_none(self) -> None:
        pkt = EAPOL(version=2, type=0)
        assert message_index(pkt) is None


class TestReplayCounter:
    def test_reads_counter(self) -> None:
        assert replay_counter(_make_key_frame(M1_KEY_INFO, replay=7)) == 7

    def test_large_counter(self) -> None:
        assert replay_counter(_make_key_frame(M2_KEY_INFO, replay=0xABCD)) == 0xABCD

    def test_non_eapol_returns_none(self) -> None:
        from scapy.all import IP, Ether

        assert replay_counter(Ether() / IP(dst="1.1.1.1")) is None

    def test_short_payload_returns_none(self) -> None:
        assert replay_counter(EAPOL(version=2, type=3) / b"\x02\x00\x8a") is None
