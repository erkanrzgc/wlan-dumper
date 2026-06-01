#!/usr/bin/env bash
# Install morrownr's out-of-tree 88x2bu driver for the RTL8822BU (0bda:b812).
#
# WHY: the in-kernel rtw88_8822bu driver is unreliable for 802.11 frame
# injection (deauth). Without injection, deauth frames don't go out, the
# client never re-handshakes, and handshake capture stalls. morrownr/8822bu
# is the community driver with working monitor mode + injection.
#
# This blacklists the in-kernel module, builds the DKMS driver, and loads it.
# Run with: sudo bash scripts/install-8822bu-driver.sh
# A reboot is recommended afterwards.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

echo "[*] Installing build prerequisites..."
apt-get update
apt-get install -y dkms git build-essential "linux-headers-$(uname -r)"

SRC=/usr/src/8822bu-git
echo "[*] Fetching morrownr/8822bu into $SRC ..."
rm -rf "$SRC"
git clone --depth 1 https://github.com/morrownr/8822bu.git "$SRC"

echo "[*] Blacklisting in-kernel rtw88_8822bu (conflicts with this driver)..."
cat >/etc/modprobe.d/blacklist-rtw88-8822bu.conf <<'EOF'
# Use the out-of-tree morrownr 8822bu driver for reliable injection.
blacklist rtw88_8822bu
blacklist rtw88_usb
EOF

echo "[*] Building + installing via the driver's own installer..."
cd "$SRC"
# The repo ships an install-driver.sh that handles DKMS registration.
if [[ -x ./install-driver.sh ]]; then
    ./install-driver.sh
else
    make clean || true
    make -j"$(nproc)"
    make install
fi

echo
echo "[+] Done. Unplug/replug the adapter or reboot, then verify with:"
echo "      iw dev                       # interface should reappear"
echo "      sudo aireplay-ng --test wlan0   # expect 'Injection is working!'"
