# cyberm4fia-wifi

> ⚠️ **Authorization warning.** This tool can perform actions that affect real wireless networks
> and real users. Using it against networks you do not own or do not have explicit, written
> permission to audit is illegal in most jurisdictions. The built-in authorization gate is a
> guard, not a license — the operator is responsible for compliance.

A Python-based 802.11 audit suite that fuses the airodump-ng (live scan / display) and
aircrack-ng (offline crack) workflows into a single plugin-extensible CLI with a Textual TUI.

| Phase | Status | Scope |
|-------|--------|-------|
| 1 | ✅ shipped | scan + display (passive, no frames transmitted) |
| 2 | planned | handshake capture / deauth / PMKID / WPS |
| 3 | planned | crack engine (aircrack-ng / hashcat) + Evil Twin |
| 4 | planned | crunch / john-style wordlist generator |

See [`docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-design.md`](docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-design.md) for the full design.

---

## Install

Tested on **Kali Linux 2024.x** (Debian-derived distros should work the same). Root is required
because monitor mode and raw 802.11 socket access need it.

### 1. System packages

```bash
sudo apt update
sudo apt install -y \
    aircrack-ng \
    iw \
    pipx \
    python3-venv
```

Optional for later phases (the tool already supports a runtime check and will warn if missing):

```bash
sudo apt install -y hashcat hcxtools reaver bully hostapd dnsmasq
```

### 2. Adapter driver (only if you use the Realtek RTL8812AU)

The Atheros AR9271 (e.g. TL-WN722N v1, zSecurity adapter) runs out of the box on Kali via the
mainline `ath9k_htc` driver. The Realtek RTL8812AU (AC1300-class, often sold on Trendyol) needs
the DKMS driver:

```bash
sudo apt install -y realtek-rtl88xxau-dkms linux-headers-$(uname -r)
```

Reboot or `sudo modprobe 88XXau` afterwards. Verify with:

```bash
lsmod | grep -E '88XXau|ath9k_htc'
```

### 3. Install cyberm4fia-wifi

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-wiFi-cracker.git
cd cyberm4fia-wiFi-cracker
pipx install --editable .[dev]
```

`pipx` creates an isolated venv and exposes the `cyberm4fia` entry point on your PATH. If you
prefer a manual venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

---

## Quickstart

```bash
# 1. Verify your adapters are detected (no root needed)
cyberm4fia adapters

# 2. First-launch authorization prompt — pick a mode and acknowledge
sudo -E cyberm4fia adapters

# 3. Start a live scan (root needed for monitor mode)
sudo -E cyberm4fia scan
```

`sudo -E` preserves the `XDG_*` env vars so the authorization config and audit log stay under
your user account, not under `/root/`.

### Keybinds

While the TUI is running:

| Key | Action |
|-----|--------|
| F1 | Help overlay (placeholder for Phase 2) |
| F2 | Cycle sort column (PWR → CH → ESSID → #Beacon) |
| F3 | Toggle filter (substring on BSSID / ESSID) |
| F4 | Lock hopper on the highlighted AP's channel / unlock to resume |
| F5 | Pause / resume refresh |
| F10 or q | Quit (restores the interface) |

Mouse: click a row in the AP table to populate the clients panel for that AP.

---

## Authorization modes

Set the first time you run any subcommand and persisted at
`$XDG_CONFIG_HOME/cyberm4fia/authz.yaml` (default: `~/.config/cyberm4fia/authz.yaml`).

| Mode | Who | Active / high-risk actions |
|------|-----|----------------------------|
| `lab` | You own everything in radio range | All allowed without per-target prompts |
| `pentest` | Signed engagement | Allowed **only** against BSSIDs in the whitelist |
| `ctf` | Educational / CTF lab | Allowed; every action logged |
| `general` | Default | Passive scan free; active actions require per-target `--target <BSSID>` |

Switch later by editing the YAML directly. Phase 1 only invokes `risk: passive` actions, so the
mode does not change behavior yet — but it locks in your choice for Phase 2+.

Audit log: `$XDG_DATA_HOME/cyberm4fia/audit.log` (default: `~/.local/share/cyberm4fia/audit.log`).
Empty after Phase 1 scans; Phase 2 active actions will append one line per call.

---

## Phase 1 — Manual RF Acceptance Checklist

Automated tests cannot exercise a real radio. Run this checklist with each adapter before
tagging Phase 1 complete on your environment.

**AR9271 (2.4 GHz only)**

- [ ] `cyberm4fia adapters` lists `wlan0  AR9271  driver=ath9k_htc  bands=2.4`
- [ ] `sudo -E cyberm4fia scan` enters monitor mode and shows `iface: wlan0mon` in the header
- [ ] Channels 1–13 visibly hop in the header (`CH:` changes about 4× per second)
- [ ] Beacons from a known SSID appear in the AP table within 5 s of launch
- [ ] Selecting that AP populates the clients panel with at least one station (a phone works)
- [ ] `F4` locks the channel; the locked AP's beacon count keeps rising while others freeze
- [ ] `F4` again unlocks; hopping resumes
- [ ] `F3` filter narrows the AP list correctly
- [ ] `q` and `Ctrl+C` both exit cleanly; `iw dev` post-exit shows no leftover `wlan0mon`

**RTL8812AU (2.4 + 5 GHz)**

- [ ] `cyberm4fia adapters` lists `wlan1  RTL8812AU  driver=88XXau  bands=2.4+5`
- [ ] `sudo -E cyberm4fia --iface wlan1 scan` enters monitor mode
- [ ] The hopper visits both 2.4 GHz (1–13) and 5 GHz (36–48, 149–165) channels
- [ ] At least one 5 GHz AP appears (if one is in range)
- [ ] Exit restores the interface

**Authorization gate**

- [ ] First run shows the legal notice exactly once, asks for mode, then for `y/N`
- [ ] `authz.yaml` is written after acknowledgment; subsequent runs do not re-prompt
- [ ] Audit log file does **not** exist or is empty after passive-only scans

---

## Troubleshooting

**"no wireless adapters detected"**
Check the radio is plugged in and the driver is loaded:
```bash
lsusb | grep -iE 'atheros|realtek'
ip link show
dmesg | tail -30
```
For RTL8812AU specifically: `sudo modprobe 88XXau` and confirm `lsmod | grep 88XXau`.

**"airmon-ng start wlan0 failed (rc=…): device busy"**
NetworkManager or `wpa_supplicant` is holding the interface. Either:
```bash
sudo systemctl stop NetworkManager wpa_supplicant
```
or run `sudo airmon-ng check kill` once before `cyberm4fia scan`. Phase 1 deliberately does
**not** kill these processes automatically; that lands as an opt-in `--kill-conflicting-procs`
flag in Phase 2.

**"channel hop failed"**
A specific channel is failing the `iw set channel` call. The hopper quarantines it after 3
failures in a row, so the loop keeps moving — but if every channel fails, you're probably not
in monitor mode. Check with `iw dev wlan0mon info` (expect `type monitor`).

**"scapy permission denied"**
You launched without `sudo`. Re-run with `sudo -E cyberm4fia scan`.

**Realtek breaks after a kernel update**
DKMS modules need to be rebuilt for the new kernel:
```bash
sudo apt install --reinstall linux-headers-$(uname -r) realtek-rtl88xxau-dkms
sudo dkms autoinstall
```

---

## Development

```bash
# Run the full test suite
pytest -q

# Lint + format check
ruff check . && ruff format --check .

# Strict type-check on the core engine
mypy src/cyberm4fia_wifi/core

# Coverage report (HTML in htmlcov/)
pytest --cov --cov-report=html
```

Project layout follows the spec exactly — see
[§13 of the design](docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-design.md) for the
authoritative tree.

---

## License

MIT. See `LICENSE` (to be added in Phase 1.1 packaging pass).
