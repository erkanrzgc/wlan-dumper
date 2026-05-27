"""Tests for the scan plugin orchestration glue (no real adapter required)."""

from __future__ import annotations

from cyberm4fia_wifi.core.adapter import ADAPTERS, AdapterProfile, DetectedAdapter
from cyberm4fia_wifi.plugins.scan import REGISTRY, ScanPlugin, pick_adapter


def _adapter(iface: str, profile: AdapterProfile) -> DetectedAdapter:
    return DetectedAdapter(iface=iface, profile=profile, vendor_id=0, product_id=0)


class TestRegistry:
    def test_scan_plugin_registered(self) -> None:
        assert any(isinstance(p, ScanPlugin) for p in REGISTRY)

    def test_scan_metadata(self) -> None:
        plugin = next(p for p in REGISTRY if isinstance(p, ScanPlugin))
        assert plugin.name == "scan"
        assert plugin.risk.value == "passive"
        assert plugin.requires_injection is False


class TestPickAdapter:
    def test_single_adapter_is_picked(self) -> None:
        a = _adapter("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        assert pick_adapter([a], preferred_iface=None) is a

    def test_explicit_iface_takes_precedence(self) -> None:
        a = _adapter("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        b = _adapter("wlan1", ADAPTERS[(0x0BDA, 0x8812)])
        assert pick_adapter([a, b], preferred_iface="wlan1") is b

    def test_prefers_injection_capable_when_ambiguous(self) -> None:
        generic = _adapter(
            "wlan0",
            AdapterProfile(
                name="generic",
                bands=("2.4",),
                injection=False,
                driver="x",
                injection_unverified=True,
            ),
        )
        good = _adapter("wlan1", ADAPTERS[(0x0CF3, 0x9271)])
        assert pick_adapter([generic, good], preferred_iface=None) is good

    def test_no_adapters_raises(self) -> None:
        import click
        import pytest

        with pytest.raises(click.ClickException):
            pick_adapter([], preferred_iface=None)

    def test_missing_requested_iface_raises(self) -> None:
        import click
        import pytest

        a = _adapter("wlan0", ADAPTERS[(0x0CF3, 0x9271)])
        with pytest.raises(click.ClickException):
            pick_adapter([a], preferred_iface="wlan99")
