"""Tests for the hashcat + aircrack-ng argv builders and output parsers."""

from __future__ import annotations

import pytest

from wlan_dumper.core.crack import CrackJob
from wlan_dumper.utils import aircrack, hashcat


def _job(**kw: object) -> CrackJob:
    base: dict[str, object] = {
        "bssid": "aa:bb:cc:dd:ee:ff",
        "essid": "net",
        "hash_path": "/tmp/x.22000",
        "mode": "wordlist",
        "backend": "hashcat",
    }
    base.update(kw)
    return CrackJob(**base)  # type: ignore[arg-type]


class TestHashcatArgv:
    def test_wordlist(self) -> None:
        argv = hashcat.build_argv(_job(wordlist="/w/rockyou.txt"))
        assert argv == [
            "hashcat", "-m", "22000", "--quiet",
            "-a", "0", "/tmp/x.22000", "/w/rockyou.txt",
        ]

    def test_wordlist_with_rules(self) -> None:
        argv = hashcat.build_argv(_job(wordlist="/w/rockyou.txt", rules="/r/best64.rule"))
        assert argv[-2:] == ["-r", "/r/best64.rule"]

    def test_mask(self) -> None:
        argv = hashcat.build_argv(_job(mode="mask", mask="?d?d?d?d?d?d?d?d"))
        assert argv == [
            "hashcat", "-m", "22000", "--quiet",
            "-a", "3", "/tmp/x.22000", "?d?d?d?d?d?d?d?d",
        ]

    def test_mask_without_mask_raises(self) -> None:
        with pytest.raises(ValueError):
            hashcat.build_argv(_job(mode="mask"))

    def test_wordlist_without_wordlist_raises(self) -> None:
        with pytest.raises(ValueError):
            hashcat.build_argv(_job(mode="wordlist"))

    def test_show_argv(self) -> None:
        assert hashcat.build_show_argv("/tmp/x.22000") == [
            "hashcat", "-m", "22000", "--show", "/tmp/x.22000",
        ]


class TestHashcatParse:
    def test_show_output_extracts_password(self) -> None:
        line = "a1b2*c3d4*e5f6*WIFI:hunter2"
        assert hashcat.parse_show_output(line) == "hunter2"

    def test_show_output_password_with_no_colon_returns_none(self) -> None:
        assert hashcat.parse_show_output("no-colon-here\n") is None

    def test_show_output_empty(self) -> None:
        assert hashcat.parse_show_output("") is None

    def test_progress(self) -> None:
        text = (
            "Progress.........: 1000/10000 (10.00%)\n"
            "Speed.#1.........:    52034 H/s (1.23ms)\n"
            "Progress.........: 2000/10000 (20.00%)\n"
            "Speed.#1.........:    53000 H/s\n"
        )
        tried, total, rate = hashcat.parse_progress(text)
        assert (tried, total, rate) == (2000, 10000, 53000.0)

    def test_progress_empty(self) -> None:
        assert hashcat.parse_progress("") == (0, None, None)


class TestAircrackArgv:
    def test_wordlist(self) -> None:
        argv = aircrack.build_argv(_job(backend="aircrack-ng", wordlist="/w/rockyou.txt"))
        assert argv == [
            "aircrack-ng", "-w", "/w/rockyou.txt", "-b", "aa:bb:cc:dd:ee:ff", "/tmp/x.22000",
        ]

    def test_wordlist_without_wordlist_raises(self) -> None:
        with pytest.raises(ValueError):
            aircrack.build_argv(_job(backend="aircrack-ng"))

    def test_stream_cmd_for_digits(self) -> None:
        producer, consumer = aircrack.build_stream_cmd(
            _job(backend="aircrack-ng", mode="mask", mask="?d?d?d?d?d?d?d?d")
        )
        assert producer == ["crunch", "8", "8", "0123456789"]
        assert consumer == ["aircrack-ng", "-w", "-", "-b", "aa:bb:cc:dd:ee:ff", "/tmp/x.22000"]

    def test_stream_cmd_mixed_mask_raises(self) -> None:
        with pytest.raises(ValueError):
            aircrack.build_stream_cmd(
                _job(backend="aircrack-ng", mode="mask", mask="?d?l?d?l")
            )

    def test_stream_cmd_no_mask_raises(self) -> None:
        with pytest.raises(ValueError):
            aircrack.build_stream_cmd(_job(backend="aircrack-ng", mode="mask"))


class TestAircrackParse:
    def test_key_found(self) -> None:
        assert aircrack.parse_key_found("KEY FOUND! [ hunter2 ]") == "hunter2"

    def test_key_found_with_spaces(self) -> None:
        assert aircrack.parse_key_found("KEY FOUND! [ correct horse ]") == "correct horse"

    def test_key_not_found(self) -> None:
        assert aircrack.parse_key_found("Passphrase not in dictionary") is None

    def test_progress(self) -> None:
        text = "  1000/  60000 keys tested (1234.56 k/s)\n"
        tried, rate = aircrack.parse_progress(text)
        assert tried == 1000
        assert rate == pytest.approx(1_234_560.0)

    def test_progress_empty(self) -> None:
        assert aircrack.parse_progress("") == (0, None)
