"""aircrack-ng backend helpers: build argv and parse output.

aircrack-ng is the always-present fallback on Kali. It cracks directly from the
``.pcap``/``.cap`` handshake, keyed by BSSID:

- wordlist: ``aircrack-ng -w <wordlist> -b <bssid> <pcap>``
- mask / brute: there is no native mask mode, so we stream candidates from
  ``crunch`` over a pipe — ``crunch ... | aircrack-ng -w - -b <bssid> <pcap>`` —
  which honours the operator's "never write candidates to disk" constraint.

Pure helpers only (argv + parsing); the plugin owns the subprocess + pipe.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wlan_dumper.core.crack import CrackJob

# "KEY FOUND! [ correct horse ]" — passphrase may contain spaces, so capture
# everything between the brackets and strip the single padding space aircrack
# adds on each side.
_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s(.*?)\s\]")
# "[00:00:04] 1234/  56789 keys tested (1234.56 k/s)" — capture the FIRST
# number of the tested/total pair, not the total.
_PROGRESS_RE = re.compile(r"([\d,]+)\s*/\s*[\d,]+\s+keys tested.*?\(([\d.]+)\s*k/s\)")


def build_argv(job: CrackJob) -> list[str]:
    """aircrack-ng wordlist argv for ``job``. Raises on bad config."""
    if not job.wordlist:
        raise ValueError("aircrack-ng wordlist mode requires a wordlist")
    return ["aircrack-ng", "-w", job.wordlist, "-b", job.bssid, job.hash_path]


def build_stream_cmd(job: CrackJob) -> tuple[list[str], list[str]]:
    """Return (producer_argv, consumer_argv) for a streamed mask crack.

    The producer is ``crunch`` emitting candidates to stdout; the consumer is
    ``aircrack-ng -w -`` reading them from stdin. Nothing touches disk.

    crunch needs explicit min/max lengths and a charset. We derive a fixed
    length and a charset from the mask's single repeated token (the common
    ISP-router case, e.g. ``?d?d?d?d?d?d?d?d`` -> 8 digits). Mixed-token masks
    are rejected — use the hashcat backend for those.
    """
    if not job.mask:
        raise ValueError("mask mode requires a mask")
    length, charset = _mask_to_crunch(job.mask)
    producer = ["crunch", str(length), str(length), charset]
    consumer = ["aircrack-ng", "-w", "-", "-b", job.bssid, job.hash_path]
    return producer, consumer


_CRUNCH_CHARSETS = {
    "d": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


def _mask_to_crunch(mask: str) -> tuple[int, str]:
    """Convert a single-token repeated mask to (length, crunch charset)."""
    tokens = re.findall(r"\?(.)", mask)
    if not tokens or len(set(tokens)) != 1:
        raise ValueError(
            f"aircrack streaming needs a single repeated mask token, got {mask!r}; "
            "use the hashcat backend for mixed masks"
        )
    charset = _CRUNCH_CHARSETS.get(tokens[0])
    if charset is None:
        raise ValueError(f"unsupported crunch charset for token '?{tokens[0]}'")
    return len(tokens), charset


def parse_key_found(text: str) -> str | None:
    """Return the passphrase from an aircrack-ng 'KEY FOUND!' line, else None."""
    m = _KEY_FOUND_RE.search(text)
    return m.group(1) if m else None


def parse_progress(text: str) -> tuple[int, float | None]:
    """Parse aircrack-ng progress into (keys_tested, rate_per_sec).

    aircrack prints rate in k/s; we return candidates/sec. Returns the latest
    values in ``text``; rate is ``None`` if not yet printed.
    """
    tried = 0
    rate: float | None = None
    for m in _PROGRESS_RE.finditer(text):
        tried = int(m.group(1).replace(",", ""))
        rate = float(m.group(2)) * 1000.0
    return tried, rate
