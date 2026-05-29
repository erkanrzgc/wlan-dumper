"""Tests for the interactive adapter picker and the capture-path helpers."""

from __future__ import annotations

import io

import click
import pytest

from wlan_dumper.core.adapter import ADAPTERS, AdapterProfile, DetectedAdapter
from wlan_dumper.plugins.scan import interactive_pick_adapter
from wlan_dumper.utils import paths


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _ad(iface: str, profile: AdapterProfile) -> DetectedAdapter:
    return DetectedAdapter(iface=iface, profile=profile, vendor_id=0, product_id=0)


class TestInteractivePicker:
    def test_single_adapter_is_auto_picked_silently(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        out = io.StringIO()
        chosen = interactive_pick_adapter(
            [a], preferred_iface=None, stdin=io.StringIO(""), stdout=out
        )
        assert chosen is a
        assert out.getvalue() == ""  # no prompt shown

    def test_single_adapter_uses_tui_picker_when_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from wlan_dumper.plugins import scan

        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        called = False

        def fake_picker(adapters: list[DetectedAdapter], **_kwargs: object) -> DetectedAdapter:
            nonlocal called
            called = True
            assert adapters == [a]
            return a

        monkeypatch.setattr(scan, "_pick_adapter_tui", fake_picker)

        chosen = interactive_pick_adapter([a], preferred_iface=None, stdin=_TTY(), stdout=_TTY())

        assert chosen is a
        assert called is True

    def test_explicit_iface_skips_prompt(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        out = io.StringIO()
        chosen = interactive_pick_adapter(
            [a, b], preferred_iface="wlan1", stdin=io.StringIO(""), stdout=out
        )
        assert chosen is b
        assert out.getvalue() == ""

    def test_multiple_adapters_prompts_and_returns_choice(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        out = io.StringIO()
        chosen = interactive_pick_adapter(
            [a, b], preferred_iface=None, stdin=io.StringIO("2\n"), stdout=out
        )
        assert chosen is b
        rendered = out.getvalue()
        assert "[1] wlan0" in rendered
        assert "[2] wlan1" in rendered
        assert "RTL8812AU" in rendered

    def test_empty_input_defaults_to_first(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        chosen = interactive_pick_adapter(
            [a, b], preferred_iface=None, stdin=io.StringIO("\n"), stdout=io.StringIO()
        )
        assert chosen is a

    def test_out_of_range_raises(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        with pytest.raises(click.ClickException):
            interactive_pick_adapter(
                [a, b], preferred_iface=None, stdin=io.StringIO("9\n"), stdout=io.StringIO()
            )

    def test_non_numeric_raises(self) -> None:
        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        with pytest.raises(click.ClickException):
            interactive_pick_adapter(
                [a, b],
                preferred_iface=None,
                stdin=io.StringIO("abc\n"),
                stdout=io.StringIO(),
            )

    def test_no_adapters_raises_in_non_tty(self) -> None:
        # Scripts / pipes still hard-fail; only the interactive picker waits.
        with pytest.raises(click.ClickException):
            interactive_pick_adapter(
                [], preferred_iface=None, stdin=io.StringIO(""), stdout=io.StringIO()
            )

    def test_empty_adapters_opens_picker_when_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With a TTY, zero adapters must NOT raise — the picker opens and waits
        # for one to be plugged in.
        from wlan_dumper.plugins import scan

        a = _ad("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        seen_args: dict[str, object] = {}

        def fake_picker(adapters: list[DetectedAdapter], **kwargs: object) -> DetectedAdapter:
            seen_args["adapters"] = adapters
            seen_args.update(kwargs)
            return a  # pretend one showed up and the operator picked it

        monkeypatch.setattr(scan, "_pick_adapter_tui", fake_picker)

        chosen = interactive_pick_adapter(
            [], preferred_iface=None, stdin=_TTY(), stdout=_TTY()
        )
        assert chosen is a
        assert seen_args["adapters"] == []  # picker started empty

    def test_unmatched_iface_falls_through_to_picker_when_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # --iface points at an adapter that isn't present yet; in a TTY this
        # should open the picker (which keeps watching) rather than error.
        from wlan_dumper.plugins import scan

        b = _ad("wlan1", ADAPTERS[(0x0BDA, 0x8812)])

        def fake_picker(adapters: list[DetectedAdapter], **kwargs: object) -> DetectedAdapter:
            assert kwargs.get("preferred_iface") == "wlan1"
            return b

        monkeypatch.setattr(scan, "_pick_adapter_tui", fake_picker)

        chosen = interactive_pick_adapter(
            [], preferred_iface="wlan1", stdin=_TTY(), stdout=_TTY()
        )
        assert chosen is b


class TestCapturePaths:
    def test_handshake_path_shape(self) -> None:
        p = paths.handshake_path("MyHome", "AA:BB:CC:DD:EE:01", ts=1717000000.0)
        assert p.parent.name == "handshakes"
        assert p.suffix == ".pcap"
        # safe ESSID + lowercased BSSID without separators
        assert "MyHome_aabbccddee01_" in p.name

    def test_hidden_essid_falls_back_to_label(self) -> None:
        p = paths.handshake_path(None, "AA:BB:CC:DD:EE:01", ts=1717000000.0)
        assert p.name.startswith("hidden_")

    def test_essid_with_unsafe_chars_is_sanitised(self) -> None:
        p = paths.handshake_path("Cudy/Outdoor 5G!", "00:11:22:33:44:55", ts=1717000000.0)
        # No spaces, no slashes, no ! — only [A-Za-z0-9_-.]
        assert "/" not in p.name
        assert " " not in p.name
        assert "!" not in p.name

    def test_long_essid_is_truncated(self) -> None:
        p = paths.handshake_path("a" * 200, "00:11:22:33:44:55", ts=1717000000.0)
        # essid part of the name (split on the bssid) capped at 32 chars
        essid_part = p.name.split("_")[0]
        assert len(essid_part) == 32

    def test_directories_get_created_on_demand(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(paths, "_CAPTURES", tmp_path / "captures")
        d = paths.handshake_dir()
        assert d.exists()
        assert d.name == "handshakes"
