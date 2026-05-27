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
        pcap.write_bytes(b"x")

        plan = {"hcxpcapngtool": _FakeRun(returncode=0)}
        run, calls = _fake_runner(plan)
        monkeypatch.setattr(hcxtools, "_run", run)
        monkeypatch.setattr(hcxtools, "_which", lambda _name: "/usr/bin/hcxpcapngtool")

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

        assert hcxtools.convert_to_22000(pcap) is None
