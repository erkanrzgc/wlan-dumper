"""hashcat backend helpers: build argv and parse output.

hashcat cracks the WPA ``.22000`` artifact in mode 22000. We support two attack
modes:

- wordlist (``-a 0``): a dictionary, optionally with a rule file (``-r``).
- mask / brute (``-a 3``): an on-the-fly keyspace, no candidate file on disk.

The recovered passphrase is read back with ``--show`` (hashcat prints
``<hash>:<password>``) rather than scraped from the cracking run's stdout, which
keeps recovery robust across hashcat versions.

Everything here is pure (argv construction + text parsing) so it is unit-tested
without invoking hashcat; the subprocess orchestration lives in the plugin.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wlan_dumper.core.crack import CrackJob

_MODE_22000 = "22000"

# "Progress.........: 12345/100000 (12.34%)" — done/total candidates.
_PROGRESS_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)")
# "Speed.#1.........:    52034 H/s" (may carry a (xx.xxms) suffix).
_SPEED_RE = re.compile(r"Speed\.[#\.\d]*:\s*([\d,]+)\s*H/s")


def build_argv(job: CrackJob) -> list[str]:
    """hashcat command line for ``job`` (mode 22000). Raises on bad config."""
    argv = ["hashcat", "-m", _MODE_22000, "--quiet"]
    if job.mode == "mask":
        if not job.mask:
            raise ValueError("mask mode requires a mask")
        argv += ["-a", "3", job.hash_path, job.mask]
    else:  # wordlist (smart resolves to wordlist passes upstream)
        if not job.wordlist:
            raise ValueError("wordlist mode requires a wordlist")
        argv += ["-a", "0", job.hash_path, job.wordlist]
        if job.rules:
            argv += ["-r", job.rules]
    return argv


def build_show_argv(hash_path: str) -> list[str]:
    """``hashcat --show`` argv to read back any already-cracked passphrase."""
    return ["hashcat", "-m", _MODE_22000, "--show", hash_path]


def parse_show_output(text: str) -> str | None:
    """Extract the passphrase from ``hashcat --show`` output.

    The line format is ``<hash-fields>:<password>``. The 22000 hash itself uses
    ``*`` as its internal separator and ``:`` only appears between the hash and
    the recovered password, so the passphrase is everything after the LAST
    colon on the first non-empty line.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        return line.rsplit(":", 1)[1]
    return None


def parse_progress(text: str) -> tuple[int, int | None, float | None]:
    """Parse hashcat's ``--status`` block into (tried, total, rate).

    Returns the most recent values found in ``text``. ``total`` and ``rate`` are
    ``None`` when not present yet (hashcat prints them only once warmed up).
    """
    tried = 0
    total: int | None = None
    rate: float | None = None
    for m in _PROGRESS_RE.finditer(text):
        tried = int(m.group(1))
        total = int(m.group(2))
    speeds = _SPEED_RE.findall(text)
    if speeds:
        rate = float(speeds[-1].replace(",", ""))
    return tried, total, rate
