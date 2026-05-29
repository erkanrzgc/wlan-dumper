#!/usr/bin/env python3
"""Top-level entry point — the file you actually run.

Usage:
    python3 run.py adapters         # list detected wireless adapters
    python3 run.py scan             # live scan + TUI (needs sudo)
    python3 run.py --help

This is just a 3-line shim that puts ``src/`` on PYTHONPATH and calls the
real CLI in ``src/wlan_dumper/cli.py``. After ``pip install -e .`` you
can also use the installed ``wlan-dumper`` command directly — both paths
end up at the same code.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from wlan_dumper.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
