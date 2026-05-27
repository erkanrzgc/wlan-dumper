#!/usr/bin/env bash
# One-shot launcher for the live scan.
#
# Usage:
#   ./cyberm4fia.sh adapters      # list adapters (no root needed, no NM detach)
#   ./cyberm4fia.sh scan          # full live scan: re-execs under sudo,
#                                 # lets the app pick an interface,
#                                 # restores NetworkManager on exit.
#
# Override the interface with:
#   IFACE=wlan1 ./cyberm4fia.sh scan
#   ./cyberm4fia.sh --iface wlan1 scan
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CMD="${1:-scan}"

# adapters / --help don't need root or NM detach — run cheap path.
case "$CMD" in
  adapters|--help|-h|"")
    exec python3 "$HERE/run.py" "$@"
    ;;
esac

# Anything else (scan, future plugins) wants monitor mode.
if [[ $EUID -ne 0 ]]; then
    echo "[cyberm4fia] monitor mode needs root — re-executing under sudo..." >&2
    exec sudo --preserve-env=HOME,PYTHONPATH,IFACE "$0" "$@"
fi

exec python3 "$HERE/run.py" "$@"
