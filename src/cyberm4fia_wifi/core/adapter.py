"""USB adapter detection and monitor-mode management.

Walks ``iw dev`` to enumerate wireless interfaces, resolves each interface to
its USB vendor/product ID via ``udevadm info``, and matches against the
``ADAPTERS`` capability matrix. Unknown chipsets fall back to a generic profile
with ``injection_unverified=True`` so the operator gets a warning instead of a
silent guess.

Monitor mode is entered with ``airmon-ng start`` and the resulting interface
name is parsed from stdout. ``AdapterManager.restore`` runs ``airmon-ng stop``
on the monitor interface; the manager is also usable as a context manager,
and ``AdapterManager.enter_monitor_mode`` registers an ``atexit`` callback so
a hard crash still attempts cleanup.

Subprocess calls go through the module-level ``_run`` indirection so tests can
patch them with a single ``monkeypatch.setattr`` and never touch the real
``subprocess`` module.
"""

from __future__ import annotations

import atexit
import contextlib
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AdapterProfile:
    name: str
    bands: tuple[str, ...]
    injection: bool
    driver: str
    injection_unverified: bool = False


_GENERIC = AdapterProfile(
    name="generic",
    bands=("2.4",),
    injection=False,
    driver="unknown",
    injection_unverified=True,
)


# Public capability matrix. Extend by adding (vendor, product) -> AdapterProfile.
ADAPTERS: dict[tuple[int, int], AdapterProfile] = {
    (0x0CF3, 0x9271): AdapterProfile(
        name="AR9271",
        bands=("2.4",),
        injection=True,
        driver="ath9k_htc",
    ),
    (0x0BDA, 0x8812): AdapterProfile(
        name="RTL8812AU",
        bands=("2.4", "5"),
        injection=True,
        driver="88XXau",
    ),
    (0x0BDA, 0x881A): AdapterProfile(  # AC1300 variant
        name="RTL8812AU",
        bands=("2.4", "5"),
        injection=True,
        driver="88XXau",
    ),
    (0x0BDA, 0xB812): AdapterProfile(  # AC1200 (Techkey and similar)
        name="RTL8822BU",
        bands=("2.4", "5"),
        injection=True,
        driver="88x2bu",
        injection_unverified=True,  # depends heavily on which OOT driver is loaded
    ),
}


@dataclass(slots=True)
class DetectedAdapter:
    iface: str
    profile: AdapterProfile
    vendor_id: int
    product_id: int


class AdapterError(Exception):
    """Raised when adapter operations fail (detection or monitor toggle)."""


# ---- subprocess indirection (tests patch this) -----------------------------

_subprocess_plan: dict[tuple[str, ...], Any] = {}  # unused at runtime; tests patch


def _run(argv: list[str], **_kwargs: Any) -> Any:  # pragma: no cover — patched in tests
    completed = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed


# ---- detection -------------------------------------------------------------


_IW_IFACE_RE = re.compile(r"Interface\s+(\S+)")


def _iw_dev_interfaces() -> list[str]:
    res = _run(["iw", "dev"])
    if res.returncode != 0:
        return []
    return _IW_IFACE_RE.findall(res.stdout)


_UDEV_VENDOR_RE = re.compile(r"^ID_VENDOR_ID=([0-9a-fA-F]+)", re.MULTILINE)
_UDEV_MODEL_RE = re.compile(r"^ID_MODEL_ID=([0-9a-fA-F]+)", re.MULTILINE)


def _sysfs_vendor_product(iface: str) -> tuple[int, int] | None:
    """Read parent USB device's idVendor/idProduct from sysfs.

    The interface device (e.g. ``3-2:1.0``) doesn't carry these attributes,
    but its parent USB device (``3-2``) does. Returns None when the files
    are missing (non-USB radio, restricted container, etc.).
    """
    try:
        from pathlib import Path

        device = Path(f"/sys/class/net/{iface}/device").resolve()
        parent = device.parent
        v_file = parent / "idVendor"
        p_file = parent / "idProduct"
        if v_file.exists() and p_file.exists():
            return (
                int(v_file.read_text().strip(), 16),
                int(p_file.read_text().strip(), 16),
            )
    except (OSError, ValueError):
        return None
    return None


def _vendor_product_for(iface: str) -> tuple[int, int] | None:
    # Preferred path: sysfs is authoritative when present and survives the
    # cases where udevadm only fills ID_VENDOR_FROM_DATABASE (no _ID_).
    sysfs = _sysfs_vendor_product(iface)
    if sysfs is not None:
        return sysfs

    # Fallback: scrape udevadm output. Useful when sysfs isn't accessible
    # (chroots, restricted containers) but ID_VENDOR_ID is populated upstream.
    res = _run(["udevadm", "info", "-q", "property", f"/sys/class/net/{iface}/device"])
    if res.returncode != 0:
        return None
    v = _UDEV_VENDOR_RE.search(res.stdout)
    p = _UDEV_MODEL_RE.search(res.stdout)
    if not (v and p):
        return None
    return int(v.group(1), 16), int(p.group(1), 16)


def detect_adapters() -> list[DetectedAdapter]:
    """Enumerate wireless interfaces and resolve each to an AdapterProfile."""
    found: list[DetectedAdapter] = []
    for iface in _iw_dev_interfaces():
        ids = _vendor_product_for(iface)
        if ids is None:
            # Couldn't read USB IDs (perhaps a non-USB radio); use generic profile.
            found.append(DetectedAdapter(iface=iface, profile=_GENERIC, vendor_id=0, product_id=0))
            continue
        vendor, product = ids
        profile = ADAPTERS.get((vendor, product), _GENERIC)
        found.append(
            DetectedAdapter(iface=iface, profile=profile, vendor_id=vendor, product_id=product)
        )
    return found


# ---- monitor-mode manager --------------------------------------------------


_AIRMON_NEW_IFACE_RE = re.compile(
    r"monitor mode vif enabled for \[phy\d+\](\w+) on \[phy\d+\](\w+)"
)

# Parses `iw dev` to discover the current interface name + its type. Some
# drivers (rtl88x2bu, mt76, ...) leave the interface name unchanged after
# airmon-ng start and only flip the type to monitor — the parsed name from
# airmon-ng's stdout then doesn't correspond to a real device.
_IW_DEV_BLOCK_RE = re.compile(
    r"Interface\s+(\S+).*?type\s+(\S+)",
    re.DOTALL,
)


def _monitor_ifaces() -> list[str]:
    """Return every interface currently in monitor type, from ``iw dev``."""
    res = _run(["iw", "dev"])
    if res.returncode != 0:
        return []
    return [name for (name, kind) in _IW_DEV_BLOCK_RE.findall(res.stdout) if kind == "monitor"]


def _set_nm_managed(iface: str, *, managed: bool) -> bool:
    """Best-effort NetworkManager detach/restore for the selected interface."""
    state = "yes" if managed else "no"
    with contextlib.suppress(Exception):
        res = _run(["nmcli", "device", "set", iface, "managed", state])
        return res.returncode == 0
    return False


@dataclass(slots=True)
class AdapterManager:
    iface: str
    profile: AdapterProfile
    monitor_iface: str | None = None
    _atexit_registered: bool = field(default=False, init=False, repr=False)
    _nm_detached: bool = field(default=False, init=False, repr=False)

    def enter_monitor_mode(self) -> str:
        self._nm_detached = _set_nm_managed(self.iface, managed=False)
        res = _run(["airmon-ng", "start", self.iface])
        if res.returncode != 0:
            if self._nm_detached:
                _set_nm_managed(self.iface, managed=True)
                self._nm_detached = False
            raise AdapterError(
                f"airmon-ng start {self.iface} failed (rc={res.returncode}): "
                f"{(res.stderr or res.stdout).strip()}"
            )

        # Resolution order:
        # 1. Ask `iw dev` for whatever is currently in monitor type — that's
        #    the authoritative source. Some drivers (rtl88x2bu, mt76 family)
        #    leave the interface name unchanged after airmon-ng start and
        #    only flip the type; the name parsed from airmon-ng's stdout
        #    then points at a device that does not exist.
        # 2. Parse airmon-ng's stdout if iw didn't surface anything (older
        #    drivers create a separate vif and stdout is the only signal).
        # 3. Last-resort heuristic: <iface>mon.
        monitors = _monitor_ifaces()
        if self.iface in monitors:
            mon_iface = self.iface
        elif monitors:
            mon_iface = monitors[0]
        else:
            m = _AIRMON_NEW_IFACE_RE.search(res.stdout or "")
            mon_iface = m.group(2) if m else f"{self.iface}mon"
            if mon_iface not in _monitor_ifaces():
                raise AdapterError(
                    f"airmon-ng reported success but no monitor-mode interface "
                    f"is present (expected {mon_iface!r}). 'iw dev' output:\n"
                    f"{_run(['iw', 'dev']).stdout}"
                )
        self.monitor_iface = mon_iface
        if not self._atexit_registered:
            atexit.register(self._atexit_restore)
            self._atexit_registered = True
        return mon_iface

    def restore(self) -> None:
        if self.monitor_iface is None:
            if self._nm_detached:
                _set_nm_managed(self.iface, managed=True)
                self._nm_detached = False
            return
        _run(["airmon-ng", "stop", self.monitor_iface])
        self.monitor_iface = None
        if self._nm_detached:
            _set_nm_managed(self.iface, managed=True)
            self._nm_detached = False

    # ---- atexit / context manager ------------------------------------------

    def _atexit_restore(self) -> None:  # pragma: no cover - atexit path
        with contextlib.suppress(Exception):
            self.restore()

    def __enter__(self) -> str:
        return self.enter_monitor_mode()

    def __exit__(self, *_exc: object) -> None:
        self.restore()
