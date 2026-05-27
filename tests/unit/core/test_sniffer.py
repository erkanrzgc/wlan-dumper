"""Tests for the scapy-based 802.11 dissector.

Test packets are synthesized in-process with scapy so we don't need to ship
pre-recorded pcap fixtures for unit-level coverage. (Real captures live in
``tests/fixtures/pcaps/`` once they're curated.)
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")

from scapy.all import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
    RSNCipherSuite,
    AKMSuite,
)

from cyberm4fia_wifi.core.events import BeaconSeen, ClientSeen, ProbeSeen  # noqa: E402
from cyberm4fia_wifi.core.sniffer import dissect_packet  # noqa: E402


def _radiotap(signal_dbm: int) -> RadioTap:
    return RadioTap(present="dBm_AntSignal", dBm_AntSignal=signal_dbm)


def _make_beacon(
    bssid: str = "aa:bb:cc:dd:ee:01",
    essid: bytes | None = b"MyHome",
    channel: int = 6,
    signal_dbm: int = -42,
    rsn: bool = True,
    cap: int = 0x1100,
) -> RadioTap:
    elts = Dot11Elt(ID=0, info=(essid if essid is not None else b""))
    elts = elts / Dot11Elt(ID=3, info=bytes([channel]))
    if rsn:
        elts = elts / Dot11EltRSN(
            version=1,
            group_cipher_suite=RSNCipherSuite(cipher="CCMP-128"),
            pairwise_cipher_suites=[RSNCipherSuite(cipher="CCMP-128")],
            akm_suites=[AKMSuite(suite=0x02)],  # PSK
        )
    frame = (
        _radiotap(signal_dbm)
        / Dot11(
            type=0,
            subtype=8,  # beacon
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Beacon(cap=cap)
        / elts
    )
    return frame


def _make_probe_req(
    station: str = "11:22:33:44:55:66",
    essid: bytes | None = b"FreeWiFi",
    signal_dbm: int = -60,
) -> RadioTap:
    return (
        _radiotap(signal_dbm)
        / Dot11(
            type=0,
            subtype=4,  # probe request
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=station,
            addr3="ff:ff:ff:ff:ff:ff",
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=(essid if essid is not None else b""))
    )


def _make_probe_resp(
    bssid: str = "aa:bb:cc:dd:ee:01",
    client: str = "11:22:33:44:55:66",
    signal_dbm: int = -55,
) -> RadioTap:
    return (
        _radiotap(signal_dbm)
        / Dot11(
            type=0,
            subtype=5,  # probe response
            addr1=client,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11ProbeResp(cap=0x1100)
        / Dot11Elt(ID=0, info=b"MyHome")
        / Dot11Elt(ID=3, info=b"\x06")
    )


def _make_data_frame(
    bssid: str = "aa:bb:cc:dd:ee:01",
    client: str = "11:22:33:44:55:66",
    signal_dbm: int = -50,
) -> RadioTap:
    return _radiotap(signal_dbm) / Dot11(
        type=2,
        subtype=0,
        addr1=bssid,
        addr2=client,
        addr3=bssid,
    )


class TestBeaconDissection:
    def test_open_beacon(self) -> None:
        evts = dissect_packet(_make_beacon(rsn=False, cap=0x0000), now=100.0)
        assert len(evts) == 1
        b = evts[0]
        assert isinstance(b, BeaconSeen)
        assert b.bssid == "aa:bb:cc:dd:ee:01"
        assert b.essid == "MyHome"
        assert b.channel == 6
        assert b.encryption == "OPEN"
        assert b.signal_dbm == -42

    def test_wpa2_beacon(self) -> None:
        evts = dissect_packet(_make_beacon(rsn=True), now=100.0)
        b = evts[0]
        assert isinstance(b, BeaconSeen)
        assert b.encryption == "WPA2-PSK"

    def test_hidden_essid(self) -> None:
        evts = dissect_packet(_make_beacon(essid=b""), now=100.0)
        assert evts[0].essid is None  # type: ignore[union-attr]

    def test_hidden_essid_zero_bytes(self) -> None:
        evts = dissect_packet(_make_beacon(essid=b"\x00\x00\x00"), now=100.0)
        assert evts[0].essid is None  # type: ignore[union-attr]


class TestProbeDissection:
    def test_probe_request(self) -> None:
        evts = dissect_packet(_make_probe_req(), now=100.0)
        assert len(evts) == 1
        p = evts[0]
        assert isinstance(p, ProbeSeen)
        assert p.station == "11:22:33:44:55:66"
        assert p.essid == "FreeWiFi"

    def test_probe_request_wildcard_essid(self) -> None:
        evts = dissect_packet(_make_probe_req(essid=b""), now=100.0)
        assert evts[0].essid is None  # type: ignore[union-attr]

    def test_probe_response_creates_client(self) -> None:
        evts = dissect_packet(_make_probe_resp(), now=100.0)
        assert len(evts) == 1
        c = evts[0]
        assert isinstance(c, ClientSeen)
        assert c.bssid == "aa:bb:cc:dd:ee:01"
        assert c.station == "11:22:33:44:55:66"


class TestDataFrameDissection:
    def test_data_frame_produces_client_seen(self) -> None:
        evts = dissect_packet(_make_data_frame(), now=100.0)
        assert len(evts) == 1
        c = evts[0]
        assert isinstance(c, ClientSeen)
        assert c.bssid == "aa:bb:cc:dd:ee:01"
        assert c.station == "11:22:33:44:55:66"

    def test_data_frame_to_broadcast_is_ignored(self) -> None:
        pkt = _radiotap(-50) / Dot11(
            type=2,
            subtype=0,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="11:22:33:44:55:66",
            addr3="aa:bb:cc:dd:ee:01",
        )
        evts = dissect_packet(pkt, now=100.0)
        assert evts == []


class TestNonDot11:
    def test_non_dot11_returns_empty(self) -> None:
        from scapy.all import Ether, IP

        pkt = Ether() / IP(dst="1.1.1.1")
        assert dissect_packet(pkt, now=100.0) == []
