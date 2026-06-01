<div align="center">

# wlan-dumper

**A terminal WiFi cracking toolkit — scan → deauth → capture WPA handshakes → crack.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Built with Textual](https://img.shields.io/badge/TUI-Textual-5a4fcf.svg)](https://textual.textualize.io/)
[![scapy](https://img.shields.io/badge/802.11-scapy-orange.svg)](https://scapy.net/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#requirements)
[![Tests](https://img.shields.io/badge/tests-136%20passing-brightgreen.svg)](#development)
[![Status](https://img.shields.io/badge/status-pre--alpha-yellow.svg)](#roadmap)

</div>

> ⚠️ **Legal notice.** `wlan-dumper` transmits 802.11 frames (deauthentication) and
> captures wireless traffic. Using it against networks you do not own or do not have
> explicit, written permission to test is **illegal** in most jurisdictions. You are
> solely responsible for compliance. The authors accept no liability for misuse.

---

`wlan-dumper` brings the classic `airodump-ng` → `aireplay-ng` → `aircrack-ng` workflow
into a single, keyboard-driven terminal app. Point it at a wireless adapter, watch
nearby access points and their clients populate a live table, lock onto a target, and
capture a WPA handshake — then hand it off to `hashcat`/`aircrack-ng` to crack.

It is built as a small **plugin-based** core (adapter management, channel hopping,
802.11 dissection, an event bus, and a session store) with a [Textual](https://textual.textualize.io/)
TUI on top. Each capability — scan, deauth, handshake capture — is an isolated plugin,
so the suite grows without entangling the core.

## Features

- **Live scan TUI** — access points with PWR, signal bars, channel, encryption,
  vendor (OUI), beacon/data counts, WPS and handshake flags; per-AP client lists; a
  columnar event log.
- **Dual-band** 2.4 GHz + 5 GHz channel hopping with channel lock, quarantine of
  dead channels, and regulatory-domain awareness.
- **Adapter auto-detection** — a live-refreshing picker lists wireless interfaces with
  chipset, driver, bands and injection capability; plug an adapter in mid-session and
  it appears automatically.
- **Deauthentication** — forge deauth bursts against a client or broadcast to provoke
  a reconnect.
- **WPA handshake capture** — native M1–M4 state machine for live progress, written to
  `captures/handshakes/<essid>_<bssid>_<ts>.pcap`, auto-converted to hashcat's
  `.22000` format when `hcxtools` is present.
- **MFP awareness** — detects 802.11w Management Frame Protection and warns when deauth
  is unlikely to work.
- **NetworkManager handling** — detaches the chosen interface on entry and restores it
  on exit, so monitor mode doesn't fight your desktop.

## Requirements

- **Linux** (developed and tested on Kali). A wireless adapter that supports **monitor
  mode** (and **packet injection** for deauth/handshake capture).
- **Python 3.11+** and `root` (monitor mode + raw 802.11 sockets need it).
- System tools: `aircrack-ng`, `iw`. Optional but recommended: `hcxtools` (for `.22000`
  conversion), `hashcat` (GPU cracking).

```bash
sudo apt update
sudo apt install -y aircrack-ng iw python3-venv
sudo apt install -y hcxtools hashcat        # optional, for the crack stage
```

> **Adapter drivers.** Atheros AR9271 (`ath9k_htc`) works out of the box. Realtek
> chipsets (RTL8812AU / RTL8814AU / RTL88x2BU) usually need an out-of-tree DKMS driver
> such as `realtek-rtl88xxau-dkms`.

## Installation

```bash
git clone https://github.com/erkanrzgc/wlan-dumper.git
cd wlan-dumper

# Run straight from a checkout:
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

Or install it onto your PATH with [pipx](https://pipx.pypa.io/):

```bash
pipx install --editable .
```

## Quickstart

```bash
# 1. List detected wireless adapters (no root needed):
python3 run.py adapters

# 2. Live scan + TUI — the launcher handles sudo + NetworkManager for you:
./wlan-dumper.sh scan

# Pick a specific interface:
IFACE=wlan1 ./wlan-dumper.sh scan
```

After `pip install`/`pipx`, the `wlan-dumper` command is available directly
(e.g. `sudo -E wlan-dumper scan`).

### In the scan TUI

| Key | Action |
|-----|--------|
| `↑ ↓` | Select an access point |
| `Enter` / click | Inspect the AP (details + its clients) |
| `F2` | Cycle sort column |
| `F3` | Toggle filter |
| `F4` | Lock / unlock the hopper on the selected AP's channel |
| `F5` | Pause / resume |
| `h` | Capture handshake (opens a target dialog with auto-deauth) |
| `d` | Deauth helper |
| `k` | Crack the selected AP's captured handshake (wordlist / mask, live ETA) |
| `x` | Cancel the running crack |
| `c` / `a` | Focus the Clients / Access Points table |
| `q` | Quit (restores the interface) |

Pressing `h` automatically locks the channel, fires the deauth burst (if enabled), and
listens for the 4-way handshake — you do **not** need to lock manually first. Results
land in `captures/handshakes/`.

Once an AP shows a captured handshake (the **HS** column), press `k` to crack it. The
crack dialog offers a wordlist or a mask, auto-detects the backend (`hashcat` preferred,
`aircrack-ng` fallback), and shows a live keyspace + ETA estimate before you commit. Mask
mode never writes candidates to disk — `hashcat -a 3` generates them internally, and the
`aircrack-ng` path streams `crunch | aircrack-ng -w -`. A recovered passphrase shows in
the **PW** column and is saved to `captures/cracked/`.

### Crack from the CLI

```bash
# Wordlist
wlan-dumper crack --hash captures/handshakes/Net_aabbcc_*.22000 -b AA:BB:CC:DD:EE:FF \
  --mode wordlist -w /usr/share/wordlists/rockyou.txt

# Mask / streaming brute-force (no candidates on disk)
wlan-dumper crack --hash captures/handshakes/Net_aabbcc_*.pcap -b AA:BB:CC:DD:EE:FF \
  --mode mask --mask '?d?d?d?d?d?d?d?d'
```

## Roadmap

| Stage | Status | Scope |
|-------|--------|-------|
| Scan + display | ✅ shipped | live 802.11 scan, TUI, adapter picker |
| Deauth + handshake | ✅ shipped | deauth bursts, WPA handshake capture (`.pcap` + `.22000`) |
| Crack engine | ✅ shipped | `hashcat` / `aircrack-ng` dispatch, wordlist + no-disk mask, live ETA |
| PMKID + WPS | 🚧 planned | clientless PMKID, WPS attacks |
| Wordlist generator | 🚧 planned | `crunch` / rule-based candidate generation |

## Development

```bash
pip install -e '.[dev]'

pytest -q                       # run the test suite (192 tests)
ruff check . && ruff format .   # lint + format
mypy src/wlan_dumper            # type-check the core
```

Architecture lives under `src/wlan_dumper/`:

```
core/      adapter detection · channel hopper · 802.11 sniffer · session store · event bus
plugins/   scan · deauth · handshake  (each a self-contained Plugin)
tui/       Textual app + modals
utils/     EAPOL parsing · pcap writer · hcxtools wrapper · OUI lookup · paths
```

## License

[MIT](LICENSE) © erkanrzgc

---

<div align="center">
<sub>For authorized security testing and education only.</sub>
</div>
