"""Thin wrapper around the external ``hcxpcapngtool`` binary.

``hcxpcapngtool`` is part of the hcxtools package (Kali: ``apt install
hcxtools``). It converts a libpcap-format handshake capture into the
``.22000`` text format that modern hashcat consumes. The tool is optional —
when missing, callers should keep the raw ``.pcap`` and warn the operator.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def _which(name: str) -> str | None:  # pragma: no cover — patched in tests
    return shutil.which(name)


def _run(argv: list[str], **_kw: Any) -> Any:  # pragma: no cover — patched in tests
    return subprocess.run(argv, check=False, capture_output=True, text=True)


def convert_to_22000(pcap: Path) -> Path | None:
    """Run ``hcxpcapngtool`` on ``pcap`` and return the .22000 output path.

    Returns ``None`` when the tool is not installed, returns a non-zero exit
    code, or for any reason fails to produce the output file.
    """
    if _which("hcxpcapngtool") is None:
        return None

    out = pcap.with_suffix(".22000")
    res = _run(["hcxpcapngtool", "-o", str(out), str(pcap)])
    if getattr(res, "returncode", 1) != 0:
        return None
    if not out.exists() or out.stat().st_size == 0:
        return None
    return out
