#!/usr/bin/env bash
# One-shot launcher for the live scan.
#
# Usage:
#   ./cyberm4fia.sh adapters      # list adapters (no root needed, no NM detach)
#   ./cyberm4fia.sh scan          # full live scan: re-execs under sudo,
#                                 # detaches wlan0 from NetworkManager,
#                                 # restores NM on exit.
#
# Override the interface with:  IFACE=wlan1 ./cyberm4fia.sh scan
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
IFACE="${IFACE:-wlan0}"
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
    exec sudo --preserve-env=HOME,PYTHONPATH IFACE="$IFACE" "$0" "$@"
fi

cleanup() {
    echo "[cyberm4fia] restoring $IFACE to NetworkManager..." >&2
    nmcli device set "$IFACE" managed yes 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[cyberm4fia] detaching $IFACE from NetworkManager..." >&2
nmcli device set "$IFACE" managed no
exec python3 "$HERE/run.py" "$@"
