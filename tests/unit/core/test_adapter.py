"""Tests for adapter detection and monitor-mode toggle."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from wlan_dumper.core.adapter import (
    ADAPTERS,
    AdapterError,
    AdapterManager,
    AdapterProfile,
    detect_adapters,
)

_IW_DEV_TWO_IFACES = """\
phy#1
\tInterface wlan1
\t\tifindex 4
\t\twdev 0x100000001
\t\taddr 00:c0:ca:aa:bb:cc
\t\ttype managed
\t\ttxpower 30.00 dBm
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr 00:c0:ca:dd:ee:ff
\t\ttype managed
\t\ttxpower 20.00 dBm
"""

_UDEVADM_AR9271 = """\
ID_VENDOR_ID=0cf3
ID_MODEL_ID=9271
ID_VENDOR=Atheros_Communications
ID_MODEL=AR9271_802.11n
"""

_UDEVADM_RTL8812AU = """\
ID_VENDOR_ID=0bda
ID_MODEL_ID=8812
ID_VENDOR=Realtek
ID_MODEL=RTL8812AU
"""

_AIRMON_START_OK = """\
PHY     Interface       Driver          Chipset

phy0    wlan0           ath9k_htc       Qualcomm Atheros AR9271

                (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                (mac80211 station mode vif disabled for [phy0]wlan0)
"""

_IW_DEV_WLAN0MON_MONITOR = """\
phy#0
\tInterface wlan0mon
\t\tifindex 6
\t\ttype monitor
"""

_IW_DEV_WLAN0_INPLACE_MONITOR = """\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\ttype monitor
"""


@dataclass
class FakeRun:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


@dataclass
class FakeSubprocess:
    plan: dict[tuple[str, ...], FakeRun] = field(default_factory=dict)
    calls: list[list[str]] = field(default_factory=list)
    sysfs: dict[str, tuple[int, int]] = field(default_factory=dict)


@pytest.fixture
def fake_subprocess(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSubprocess]:
    """Record subprocess calls and return canned outputs based on argv prefix."""
    fixture = FakeSubprocess()

    def run(argv: list[str], **_kwargs: Any) -> FakeRun:
        match: FakeRun | None = None
        match_len = -1
        for key, val in fixture.plan.items():
            if tuple(argv[: len(key)]) == key and len(key) > match_len:
                match = val
                match_len = len(key)
        if match is None:
            match = FakeRun(stdout="", returncode=0)
        fixture.calls.append(argv)
        return match

    from wlan_dumper.core import adapter

    monkeypatch.setattr(adapter, "_run", run)
    # Stub sysfs lookup so tests exercise the udevadm fallback deterministically;
    # individual tests can override fixture.sysfs to simulate the sysfs hit path.
    monkeypatch.setattr(
        adapter,
        "_sysfs_vendor_product",
        lambda iface: fixture.sysfs.get(iface),
    )
    yield fixture


class TestAdapterMatrix:
    def test_ar9271_present_in_matrix(self) -> None:
        profile = ADAPTERS[(0x0CF3, 0x9271)]
        assert profile.name == "AR9271"
        assert "2.4" in profile.bands
        assert profile.injection is True

    def test_rtl8812au_present_in_matrix(self) -> None:
        profile = ADAPTERS[(0x0BDA, 0x8812)]
        assert profile.name == "RTL8812AU"
        assert set(profile.bands) == {"2.4", "5"}


class TestDetectAdapters:
    def test_detects_two_known_chipsets(self, fake_subprocess: FakeSubprocess) -> None:
        fake_subprocess.plan.update(
            {
                ("iw", "dev"): FakeRun(stdout=_IW_DEV_TWO_IFACES),
                ("udevadm", "info", "-q", "property", "/sys/class/net/wlan0/device"): FakeRun(
                    stdout=_UDEVADM_AR9271
                ),
                ("udevadm", "info", "-q", "property", "/sys/class/net/wlan1/device"): FakeRun(
                    stdout=_UDEVADM_RTL8812AU
                ),
            }
        )

        found = detect_adapters()

        names = sorted(a.profile.name for a in found)
        assert names == ["AR9271", "RTL8812AU"]
        ifaces = sorted(a.iface for a in found)
        assert ifaces == ["wlan0", "wlan1"]

    def test_unknown_vendor_returns_generic_profile(self, fake_subprocess: FakeSubprocess) -> None:
        fake_subprocess.plan.update(
            {
                ("iw", "dev"): FakeRun(
                    stdout="phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\ttype managed\n"
                ),
                ("udevadm",): FakeRun(stdout="ID_VENDOR_ID=ffff\nID_MODEL_ID=ffff\n"),
            }
        )

        found = detect_adapters()

        assert len(found) == 1
        assert found[0].profile.name == "generic"
        assert found[0].profile.injection_unverified is True

    def test_no_interfaces_returns_empty(self, fake_subprocess: FakeSubprocess) -> None:
        fake_subprocess.plan[("iw", "dev")] = FakeRun(stdout="")

        assert detect_adapters() == []


class TestAdapterManager:
    def test_enter_monitor_mode_parses_new_iface_name(
        self, fake_subprocess: FakeSubprocess
    ) -> None:
        profile: AdapterProfile = ADAPTERS[(0x0CF3, 0x9271)]
        fake_subprocess.plan[("airmon-ng", "start", "wlan0")] = FakeRun(stdout=_AIRMON_START_OK)
        fake_subprocess.plan[("iw", "dev")] = FakeRun(stdout=_IW_DEV_WLAN0MON_MONITOR)

        mgr = AdapterManager(iface="wlan0", profile=profile)
        mon_iface = mgr.enter_monitor_mode()

        assert mon_iface == "wlan0mon"
        argv_set = [tuple(call) for call in fake_subprocess.calls]
        assert ("nmcli", "device", "set", "wlan0", "managed", "no") in argv_set
        assert ("airmon-ng", "start", "wlan0") in argv_set

    def test_enter_monitor_mode_when_driver_keeps_name(
        self, fake_subprocess: FakeSubprocess
    ) -> None:
        """rtl88x2bu / mt76 case: airmon-ng flips type in place, no rename."""
        profile = ADAPTERS[(0x0BDA, 0xB812)]
        fake_subprocess.plan[("airmon-ng", "start", "wlan0")] = FakeRun(stdout="")
        fake_subprocess.plan[("iw", "dev")] = FakeRun(stdout=_IW_DEV_WLAN0_INPLACE_MONITOR)

        mgr = AdapterManager(iface="wlan0", profile=profile)
        mon_iface = mgr.enter_monitor_mode()

        assert mon_iface == "wlan0"  # name preserved

    def test_failed_monitor_mode_raises(self, fake_subprocess: FakeSubprocess) -> None:
        profile = ADAPTERS[(0x0CF3, 0x9271)]
        fake_subprocess.plan[("airmon-ng", "start", "wlan0")] = FakeRun(
            stdout="", stderr="device busy", returncode=1
        )

        mgr = AdapterManager(iface="wlan0", profile=profile)
        with pytest.raises(AdapterError):
            mgr.enter_monitor_mode()

    def test_restore_calls_airmon_stop_on_monitor_iface(
        self, fake_subprocess: FakeSubprocess
    ) -> None:
        profile = ADAPTERS[(0x0CF3, 0x9271)]
        fake_subprocess.plan.update(
            {
                ("airmon-ng", "start", "wlan0"): FakeRun(stdout=_AIRMON_START_OK),
                ("iw", "dev"): FakeRun(stdout=_IW_DEV_WLAN0MON_MONITOR),
                ("airmon-ng", "stop", "wlan0mon"): FakeRun(stdout=""),
            }
        )

        mgr = AdapterManager(iface="wlan0", profile=profile)
        mgr.enter_monitor_mode()
        mgr.restore()

        argvs = [tuple(call) for call in fake_subprocess.calls]
        assert ("nmcli", "device", "set", "wlan0", "managed", "no") in argvs
        assert ("airmon-ng", "stop", "wlan0mon") in argvs
        assert ("nmcli", "device", "set", "wlan0", "managed", "yes") in argvs

    def test_failed_monitor_mode_restores_networkmanager(
        self, fake_subprocess: FakeSubprocess
    ) -> None:
        profile = ADAPTERS[(0x0CF3, 0x9271)]
        fake_subprocess.plan[("airmon-ng", "start", "wlan0")] = FakeRun(
            stdout="", stderr="device busy", returncode=1
        )

        mgr = AdapterManager(iface="wlan0", profile=profile)
        with pytest.raises(AdapterError):
            mgr.enter_monitor_mode()

        argvs = [tuple(call) for call in fake_subprocess.calls]
        assert ("nmcli", "device", "set", "wlan0", "managed", "no") in argvs
        assert ("nmcli", "device", "set", "wlan0", "managed", "yes") in argvs
