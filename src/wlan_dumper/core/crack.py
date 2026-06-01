"""Crack-engine core: keyspace/ETA math and backend selection.

This module owns the *pure* logic of Phase 3a — how big a keyspace a mask
implies, how long it will take at a given rate, and how to render those numbers
for a human. The actual subprocess plumbing lives in ``utils/hashcat.py`` and
``utils/aircrack.py``; the orchestration lives in ``plugins/crack.py``.

Keeping the math here (free of subprocess/IO) means it is trivially unit-tested
and the operator-facing ETA shown in the TUI is the same number the engine uses.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

# hashcat mask charset sizes. ``?d`` digits, ``?l`` lower, ``?u`` upper,
# ``?s`` the printable-special set hashcat defines (33 chars), ``?a`` = all of
# the above printable ASCII (95). ``?h``/``?H`` are hex nibbles (16) — note
# ``?h`` is lower-hex (0-9a-f), NOT lower+digit.
_CHARSET_SIZES: dict[str, int] = {
    "d": 10,
    "l": 26,
    "u": 26,
    "s": 33,
    "a": 95,
    "h": 16,
    "H": 16,
    "b": 256,
}

# Conservative default candidate rates (candidates/sec) when we have not
# benchmarked. hashcat on a modest GPU does far more, but assuming low keeps the
# ETA honest (over-promising "done in 10 min" then taking hours is worse).
DEFAULT_RATES: dict[str, float] = {
    "hashcat": 50_000.0,
    "aircrack-ng": 2_000.0,
}


class CrackError(Exception):
    """Raised for invalid crack configuration (bad mask, no backend, ...)."""


def mask_keyspace(mask: str) -> int:
    """Total candidate count for a hashcat-style mask.

    A mask is a sequence of literal characters and ``?x`` tokens. The keyspace
    is the product of each position's charset size (literals count as 1).

    >>> mask_keyspace("?d?d?d?d")
    10000
    >>> mask_keyspace("router?d?d")
    100

    Raises ``CrackError`` on an unterminated ``?`` or an unknown token.
    """
    total = 1
    i = 0
    n = len(mask)
    while i < n:
        ch = mask[i]
        if ch == "?":
            if i + 1 >= n:
                raise CrackError(f"dangling '?' at end of mask: {mask!r}")
            token = mask[i + 1]
            if token == "?":  # literal '?'
                size = 1
            else:
                size = _CHARSET_SIZES.get(token)
                if size is None:
                    raise CrackError(f"unknown mask token '?{token}' in {mask!r}")
            total *= size
            i += 2
        else:
            i += 1  # literal char, size 1
    return total


def eta_seconds(keyspace: int | None, rate: float) -> float | None:
    """Seconds to exhaust ``keyspace`` at ``rate`` candidates/sec.

    Returns ``None`` when the keyspace is unknown (e.g. an open-ended wordlist
    whose length we have not counted) so callers can render "?" rather than a
    fabricated number. ``rate <= 0`` also yields ``None`` (unknowable).
    """
    if keyspace is None or rate <= 0:
        return None
    return keyspace / rate


def humanize_count(n: int | None) -> str:
    """Render a candidate count compactly: 1234 -> '1.2K', 9.4e9 -> '9.4G'."""
    if n is None:
        return "?"
    if n < 1000:
        return str(n)
    for unit, threshold in (("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if n >= threshold:
            return f"{n / threshold:.1f}{unit}"
    return str(n)


def humanize_duration(seconds: float | None) -> str:
    """Render a duration: 192 -> '3m 12s', 370000 -> '4d 6h', None -> '∞'."""
    if seconds is None:
        return "∞"
    if seconds < 1:
        return "<1s"
    secs = int(seconds)
    days, rem = divmod(secs, 86_400)
    hours, rem = divmod(rem, 3_600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def detect_backend(preferred: str | None = None) -> str:
    """Pick a crack backend: prefer hashcat, fall back to aircrack-ng.

    ``preferred`` forces a specific backend when it is installed. Raises
    ``CrackError`` when no usable backend is on PATH.
    """
    if preferred:
        if shutil.which(preferred):
            return preferred
        raise CrackError(f"requested backend {preferred!r} not found on PATH")
    if shutil.which("hashcat"):
        return "hashcat"
    if shutil.which("aircrack-ng"):
        return "aircrack-ng"
    raise CrackError("no crack backend found (install hashcat or aircrack-ng)")


@dataclass(frozen=True)
class CrackJob:
    """A fully-resolved crack request, ready to hand to a backend runner."""

    bssid: str
    essid: str | None
    hash_path: str  # the .22000 (hashcat) or .pcap/.cap (aircrack) artifact
    mode: str  # "wordlist" | "mask" | "smart"
    backend: str  # "hashcat" | "aircrack-ng"
    wordlist: str | None = None
    mask: str | None = None
    rules: str | None = None  # hashcat rule file, optional

    def keyspace(self) -> int | None:
        """Total candidates if computable (mask mode); ``None`` otherwise."""
        if self.mode == "mask" and self.mask:
            return mask_keyspace(self.mask)
        return None

    def estimated_eta(self, rate: float | None = None) -> float | None:
        r = rate if rate is not None else DEFAULT_RATES.get(self.backend, 0.0)
        return eta_seconds(self.keyspace(), r)
