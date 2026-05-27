"""Project-local capture directory layout.

Everything we persist for the operator (pcaps, session JSON dumps, future
crack-result files) lives under ``<repo>/captures/`` so they are easy to
find, easy to clean (``rm -rf captures``), and easy to .gitignore wholesale.

Layout
    captures/
    ├── handshakes/   # Phase 2: WPA 4-way handshake pcaps
    ├── pmkid/        # Phase 2: PMKID hashes (.22000)
    ├── sessions/     # Phase 1: optional Session.dump_json output
    └── cracked/      # Phase 3: recovered passphrases
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

# ``Path(__file__).resolve()`` walks up:
#   src/cyberm4fia_wifi/utils/paths.py  →
#   src/cyberm4fia_wifi/utils           →  parents[0]
#   src/cyberm4fia_wifi                 →  parents[1]
#   src                                 →  parents[2]
#   <repo>                              →  parents[3]
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CAPTURES = _REPO_ROOT / "captures"


def captures_root() -> Path:
    _CAPTURES.mkdir(parents=True, exist_ok=True)
    return _CAPTURES


def handshake_dir() -> Path:
    d = captures_root() / "handshakes"
    d.mkdir(parents=True, exist_ok=True)
    return d


def pmkid_dir() -> Path:
    d = captures_root() / "pmkid"
    d.mkdir(parents=True, exist_ok=True)
    return d


def sessions_dir() -> Path:
    d = captures_root() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cracked_dir() -> Path:
    d = captures_root() / "cracked"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_essid(essid: str | None) -> str:
    """Make an ESSID safe for use in a filename.

    Replaces path separators and whitespace, drops anything outside printable
    ASCII, and caps at 32 chars so we never blow past a sane filename length.
    Falls back to ``hidden`` for unknown / hidden networks.
    """
    if not essid:
        return "hidden"
    cleaned = "".join(
        c if (c.isalnum() or c in "-_.") else "_" for c in essid
    )
    cleaned = cleaned.strip("_") or "hidden"
    return cleaned[:32]


def _safe_bssid(bssid: str) -> str:
    return bssid.replace(":", "").replace("-", "").lower()


def _timestamp(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time()).strftime("%Y%m%d-%H%M%S")


def handshake_path(essid: str | None, bssid: str, ts: float | None = None) -> Path:
    """``captures/handshakes/<essid>_<bssid>_<ts>.pcap`` (directory auto-created)."""
    name = f"{_safe_essid(essid)}_{_safe_bssid(bssid)}_{_timestamp(ts)}.pcap"
    return handshake_dir() / name


def pmkid_path(essid: str | None, bssid: str, ts: float | None = None) -> Path:
    name = f"{_safe_essid(essid)}_{_safe_bssid(bssid)}_{_timestamp(ts)}.22000"
    return pmkid_dir() / name


def session_dump_path(ts: float | None = None) -> Path:
    return sessions_dir() / f"session_{_timestamp(ts)}.json"
