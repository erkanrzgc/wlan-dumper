"""Tests for the crack-engine core math + backend selection."""

from __future__ import annotations

import pytest

from wlan_dumper.core.crack import (
    CrackError,
    CrackJob,
    detect_backend,
    eta_seconds,
    humanize_count,
    humanize_duration,
    mask_keyspace,
)


class TestMaskKeyspace:
    @pytest.mark.parametrize(
        "mask,expected",
        [
            ("?d?d?d?d", 10_000),
            ("?d", 10),
            ("?l?l", 26 * 26),
            ("?a?a", 95 * 95),
            ("?h?h", 16 * 16),
            ("router", 1),  # all literals
            ("wifi?d?d", 100),  # literals + tokens
            ("?d?d??", 100),  # ?? is a literal '?'
        ],
    )
    def test_keyspace(self, mask: str, expected: int) -> None:
        assert mask_keyspace(mask) == expected

    def test_dangling_question_mark_raises(self) -> None:
        with pytest.raises(CrackError):
            mask_keyspace("?d?")

    def test_unknown_token_raises(self) -> None:
        with pytest.raises(CrackError):
            mask_keyspace("?z")


class TestEta:
    def test_basic(self) -> None:
        assert eta_seconds(10_000, 1_000) == 10.0

    def test_unknown_keyspace_is_none(self) -> None:
        assert eta_seconds(None, 1_000) is None

    def test_zero_rate_is_none(self) -> None:
        assert eta_seconds(10_000, 0) is None


class TestHumanize:
    @pytest.mark.parametrize(
        "n,expected",
        [(None, "?"), (5, "5"), (999, "999"), (1500, "1.5K"), (9_400_000_000, "9.4G")],
    )
    def test_count(self, n: int | None, expected: str) -> None:
        assert humanize_count(n) == expected

    @pytest.mark.parametrize(
        "seconds,expected",
        [
            (None, "∞"),
            (0.5, "<1s"),
            (45, "45s"),
            (192, "3m 12s"),
            (3700, "1h 1m"),
            (370_000, "4d 6h"),
        ],
    )
    def test_duration(self, seconds: float | None, expected: str) -> None:
        assert humanize_duration(seconds) == expected


class TestDetectBackend:
    def test_prefers_hashcat(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "wlan_dumper.core.crack.shutil.which",
            lambda name: f"/usr/bin/{name}" if name in ("hashcat", "aircrack-ng") else None,
        )
        assert detect_backend() == "hashcat"

    def test_falls_back_to_aircrack(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "wlan_dumper.core.crack.shutil.which",
            lambda name: "/usr/bin/aircrack-ng" if name == "aircrack-ng" else None,
        )
        assert detect_backend() == "aircrack-ng"

    def test_none_available_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wlan_dumper.core.crack.shutil.which", lambda name: None)
        with pytest.raises(CrackError):
            detect_backend()

    def test_preferred_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wlan_dumper.core.crack.shutil.which", lambda name: None)
        with pytest.raises(CrackError):
            detect_backend("hashcat")


class TestCrackJob:
    def test_mask_mode_keyspace_and_eta(self) -> None:
        job = CrackJob(
            bssid="aa:bb:cc:dd:ee:ff",
            essid="net",
            hash_path="/tmp/x.22000",
            mode="mask",
            backend="hashcat",
            mask="?d?d?d?d",
        )
        assert job.keyspace() == 10_000
        assert job.estimated_eta(rate=10_000) == 1.0

    def test_wordlist_mode_keyspace_unknown(self) -> None:
        job = CrackJob(
            bssid="aa:bb:cc:dd:ee:ff",
            essid="net",
            hash_path="/tmp/x.22000",
            mode="wordlist",
            backend="hashcat",
            wordlist="/usr/share/wordlists/rockyou.txt",
        )
        assert job.keyspace() is None
        assert job.estimated_eta() is None
