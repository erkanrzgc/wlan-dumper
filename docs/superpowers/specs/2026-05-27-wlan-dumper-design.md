# wlan-dumper — Design Spec

**Date:** 2026-05-27
**Status:** Approved (brainstorm complete, implementation plan pending)
**Owner:** erkanrzgc

---

## 1. Purpose

A single Python tool that combines the airodump-ng (scan / display) and aircrack-ng (crack) workflows into one cohesive, branded experience under the `wlan-dumper` namespace, with future extensions for Evil Twin and a crunch/john-style wordlist generator. The tool targets a general-purpose audience (own networks, authorized pentest engagements, and CTF/educational use), with explicit per-mode authorization guards because the active and high-risk plugins (deauth, Evil Twin) can affect real users on real networks.

## 2. Non-Goals

- Not a replacement for `aircrack-ng` suite as a library. We wrap and orchestrate the existing binaries where they are clearly best-in-class (e.g. WPA crack on CPU).
- Not a network mapper (no Nmap/active-host-discovery features).
- Not a Bluetooth, Zigbee, or SDR tool. 802.11 only.
- No Windows support in Phase 1–4. Linux-only (Kali primary target; any Debian/Arch with the right driver should also work).

## 3. User Personas & Use Modes

The tool supports a single `mode` setting, persisted in `~/.config/wlan-dumper/authz.yaml`:

| Mode | Who | Scope of allowed actions |
|------|-----|---------------------------|
| `lab` | Operator owns all networks in radio range (RF chamber, dedicated test APs) | All plugins, no per-target prompt |
| `pentest` | Operator has a signed engagement with a target BSSID whitelist | Active/high-risk plugins allowed **only** against whitelisted BSSIDs |
| `ctf` | Educational / CTF lab | Like `lab` but every active/high-risk action is appended to an audit log |
| `general` | Default | Passive scan free; active/high-risk plugins require per-BSSID acknowledgment each session |

The mode is chosen at first launch via a CLI prompt and can be changed with `wlan-dumper config mode <mode>`.

## 4. Hardware Targets

Two adapters owned by the operator must be supported first-class. The detection layer is extensible.

| Chipset | Vendor:Product | Bands | Injection | Driver |
|---------|----------------|-------|-----------|--------|
| Atheros AR9271 (e.g. TL-WN722N v1, zSecurity adapter) | `0cf3:9271` | 2.4 GHz | Yes | `ath9k_htc` |
| Realtek RTL8812AU (AC1300 class, e.g. Trendyol-sourced) | `0bda:8812` (also `0bda:881a`) | 2.4 + 5 GHz | Yes | `88XXau` (DKMS) |

Other chipsets are not blocked; the detector falls back to a generic `AdapterProfile` with conservative defaults and warns the user that injection support is unverified.

## 5. Architecture

### 5.1 High-Level Diagram

```
+--------------------------------------------------------+
|                       CLI (Click)                      |
|  wlan-dumper [scan|deauth|pmkid|wps|crack|evil|word|.]  |
+--------------------+-----------------------------------+
                     |
           +---------v---------+
           |   Core Engine     |
           |   AuthGate        |  authorization + audit log
           |   Adapter         |  USB detect, monitor mode
           |   Hopper          |  channel hopping
           |   Sniffer         |  scapy 802.11 parser
           |   Session         |  AP/client/handshake store
           |   EventBus        |  sniffer -> session -> tui
           +---------+---------+
                     |
           +---------v---------+       +---------------------+
           |     Plugins       | <---> |   Textual TUI       |
           |  scan, deauth,    |       |   AP list + detail  |
           |  pmkid, wps,      |       |   Live log panel    |
           |  crack, evil,     |       +---------------------+
           |  wordlist         |
           +-------------------+
```

### 5.2 Module Responsibilities (`src/wlan_dumper/`)

- `cli.py` — Click entrypoint. Mounts every plugin's subcommand via the plugin registry. Handles global flags (`--iface`, `--mode`, `--config`, `--verbose`).
- `core/adapter.py` — USB enumeration via `iw dev` + `udevadm info`; maintains the `ADAPTERS` capability matrix; toggles monitor mode via `airmon-ng start` and registers an `atexit` restore.
- `core/hopper.py` — Configurable channel hopping (2.4 GHz: 1–14; 5 GHz: 36–165 subject to regdomain). Per-channel dwell time, pluggable hop strategy (round-robin or weighted-by-AP-density).
- `core/sniffer.py` — Wraps `scapy.AsyncSniffer`, dissects 802.11 frames (beacon, probe req/resp, auth, assoc, EAPOL), emits events. Filters by interface and (optionally) by BSSID list.
- `core/session.py` — In-memory authoritative state: `APs`, `Clients`, `Handshakes`, `Cracked`. Optional JSON persistence to `~/.local/share/wlan-dumper/sessions/<ts>.json`.
- `core/auth.py` — `AuthorizationGate.check(plugin, target)`; reads `authz.yaml`; writes `audit.log`. Refuses high-risk plugins without the `--i-am-authorized-to-do-this "<reason>"` flag.
- `core/events.py` — Tiny pub/sub bus; events: `BeaconSeen`, `ClientSeen`, `EAPOLCapture`, `PMKIDFound`, `ChannelChanged`, `PluginStarted`, `PluginFinished`, `PluginError`.
- `tui/app.py` — Textual `App`. Subscribes to `EventBus`, renders three panels (AP table, selected-AP detail/clients, log).
- `plugins/<name>.py` — One module per plugin. Each implements the `Plugin` ABC and is auto-discovered via entry points or a static `PLUGINS` registry.
- `utils/` — small shared helpers (logging, formatting, subprocess wrappers).

### 5.3 Plugin Contract

```python
class Plugin(ABC):
    name: str
    risk: Literal["passive", "active", "high"]
    requires_injection: bool

    @abstractmethod
    def register_cli(self, group: click.Group) -> None: ...

    @abstractmethod
    def run(self, ctx: PluginContext) -> int: ...
```

`PluginContext` carries the `Session`, `EventBus`, active `AdapterProfile`, `AuthorizationGate`, and the parsed CLI namespace. Plugins must never touch the adapter directly; they go through the core.

### 5.4 Per-Plugin Risk Classification

These values are the source of truth for the authorization gate. Each plugin module declares its own `risk` attribute matching this table; the gate enforces it at runtime.

| Plugin | Risk | Requires injection | Notes |
|--------|------|-------------------|-------|
| `scan` | `passive` | no | Listen-only; no frames transmitted |
| `handshake` | `passive` | no | Listen-only; captures EAPOL frames in flight |
| `pmkid` | `active` | yes | Sends association request to elicit PMKID |
| `wps` | `active` | yes | WPS M1–M7 exchange; pixie-dust offline once captured |
| `deauth` | `high` | yes | Forges deauth frames; disconnects real clients |
| `evil_twin` | `high` | yes (+ second iface ideal) | Stands up a rogue AP; can intercept credentials |
| `crack` | `passive` | no | Local CPU/GPU work on captured hashes; no RF |
| `wordlist` | `passive` | no | Local generator; no RF, no network I/O |

## 6. Data Flow

### 6.1 Scan path (Phase 1)

```
USB adapter -> airmon-ng start -> wlan0mon
            -> scapy AsyncSniffer (sniffer.py)
            -> 802.11 frame parse
            -> Events (BeaconSeen, ClientSeen, ...)
            -> EventBus
            -> Session.update()
            -> Textual TUI reactive refresh (~250 ms)
```

### 6.2 Handshake + Crack path (Phases 2–3)

```
Session.handshakes
   -> export .pcap (tcpdump-compatible)
   -> hcxpcapngtool -o hash.22000   (hashcat format)
                    or .hccapx      (legacy)
   -> crack.py dispatcher
        -> nvidia-smi / rocm-smi detect -> hashcat (GPU)
        -> else                          -> aircrack-ng (CPU)
   -> stream progress events -> TUI
   -> Session.cracked[]
```

## 7. Authorization Gate (Detailed)

This tool can perform actions that affect real networks and real users. Misuse is illegal in most jurisdictions. The authorization gate is the technical expression of that boundary.

- First launch: a four-line legal acknowledgment + `y/N` prompt. The acknowledgment timestamp and chosen mode are stored in `~/.config/wlan-dumper/authz.yaml`.
- `authz.yaml` schema:

  ```yaml
  mode: general              # lab | pentest | ctf | general
  acknowledged_at: 2026-05-27T05:30:00Z
  whitelist_bssids:          # required when mode == pentest
    - AA:BB:CC:DD:EE:01
    - AA:BB:CC:DD:EE:02
  ```
- Plugins with `risk: high` (see §5.4) require `--i-am-authorized-to-do-this "<free-text reason>"`. The reason is recorded verbatim in the audit log.
- Audit log location: `~/.local/share/wlan-dumper/audit.log`. Line format:

  ```
  2026-05-27T05:35:12Z mode=pentest plugin=deauth target=AA:BB:CC:DD:EE:01 reason="engagement #4711 phase 2"
  ```
- All `risk: active` and `risk: high` actions are logged. `risk: passive` actions are not, to keep the log signal-to-noise high.

## 8. Adapter Detection Strategy

1. Run `iw dev` to list interfaces. For each phy, resolve to a USB device via `/sys/class/net/<iface>/device`.
2. Run `udevadm info -q property /sys/class/net/<iface>/device` to extract `ID_VENDOR_ID` and `ID_MODEL_ID`.
3. Look up `(vendor, product)` in the `ADAPTERS` matrix; on miss, emit a `WARN: unknown chipset, falling back to generic profile (injection unverified)`.
4. If multiple usable adapters exist, the CLI `--iface` flag picks one; the TUI exposes a picker on launch.
5. Monitor mode is entered with `airmon-ng start <iface>`; the resulting interface name (e.g. `wlan0mon`) is captured from stdout. An `atexit` handler runs `airmon-ng stop <iface>` and additionally kills the processes airmon-ng usually warns about (`NetworkManager`, `wpa_supplicant`) only if the user opted in via `--kill-conflicting-procs`.

## 9. TUI Layout

```
+- wlan-dumper ------------------------------------------------+
| [F1]Help [F2]Sort [F3]Filter [F4]LockCH [F5]Pause [F10]Quit      |
+------------------------------------------------------------------+
| iface: wlan0mon  driver: ath9k_htc  CH: 6 (hop)  mode: general   |
+------------------------------------------------------------------+
| APs (12)                                                         |
| BSSID              PWR CH ENC       ESSID         #Beacon  #Data |
| > AA:BB:..:01     -42  6 WPA2-PSK   MyHome           420   1532  |
|   AA:BB:..:02     -67 11 WPA2-PSK   Neighbour          8      0  |
|   AA:BB:..:03     -78  1 WPA3-SAE   OFFICE             3      0  |
+------------------------------------------------------------------+
| Selected: MyHome (AA:BB:..:01)            Clients (3)            |
|   STATION         PWR  RATE   LOST   FRAMES  PROBES              |
|   11:22:..:66    -55  54/54   0      312     -                   |
+------------------------------------------------------------------+
| [log] beacon AA:BB..01 ch6 -42 | new client 11:22..66            |
+------------------------------------------------------------------+
```

Keyboard map (Phase 1): `F1` help overlay, `F2` cycle sort column, `F3` filter prompt (substring on ESSID/BSSID), `F4` lock to currently highlighted AP's channel (stops hopping), `F5` pause sniffer, `F10` quit. Mouse selection updates the detail panel.

## 10. Error Handling

- Adapter missing or monitor mode fails: a structured error message naming the failing step, an excerpt of relevant `dmesg` if available, and exit code 2.
- Permission denied (non-root): the CLI prints the exact `sudo` rerun command and exits with code 1. The TUI never starts under these conditions.
- Channel hop failure: logged at `WARN`, that channel is skipped for the next N rotations, hopping continues.
- Plugin crash: captured by a top-level handler; rendered in the TUI error panel; written to the audit log; other plugins and the sniffer keep running.
- `SIGINT` / `Ctrl+C`: graceful shutdown — stop sniffer, restore monitor mode, optionally persist the session if the user opted in.
- No silent failures. Anything that does not propagate to the user goes to the audit log with full context.

## 11. Testing Strategy

| Layer | Approach | Target coverage |
|-------|----------|-----------------|
| `core/adapter`, `core/session`, `core/hopper`, `core/auth` | `pytest` unit tests, fake `iw dev` and `udevadm` output | 80%+ |
| `core/sniffer` | Replay pre-recorded `.pcap` fixtures through scapy | 80%+ |
| Passive plugins (`scan`) | `pytest` unit + recorded pcap fixtures | 70%+ |
| Active / subprocess plugins (`deauth`, `pmkid`, `wps`, `crack`, `evil_twin`) | Subprocess mocked, integration smoke tests that assert command construction and event emission | 50%+ |
| TUI | Textual snapshot tests for the three panels | smoke only |
| Live RF | **Not in CI.** Manual checklist in `README.md` for each phase. | n/a |

`pytest-cov` enforces the per-package thresholds in CI. Live-RF manual tests gate each release.

## 12. Phase Roadmap

| Phase | Scope | Plugins delivered |
|-------|-------|-------------------|
| **1 (MVP)** | Core engine + scan view + TUI | `scan` |
| **2** | Handshake pipeline, deauth, PMKID, WPS | `deauth`, `handshake`, `pmkid`, `wps` |
| **3** | Crack engine (aircrack-ng / hashcat dispatcher) + Evil Twin | `crack`, `evil_twin` |
| **4** | Wordlist generator + rule engine (crunch / john style) | `wordlist` |

Each phase ships independently with its own implementation plan and manual-RF acceptance checklist.

## 13. Repository Layout

```
wlan-dumper/
|-- pyproject.toml              # entry point: wlan-dumper = wlan_dumper.cli:main
|-- README.md                   # authorization warning + adapter setup
|-- src/wlan_dumper/
|   |-- __init__.py
|   |-- cli.py
|   |-- core/
|   |   |-- __init__.py
|   |   |-- adapter.py
|   |   |-- hopper.py
|   |   |-- sniffer.py
|   |   |-- session.py
|   |   |-- auth.py
|   |   `-- events.py
|   |-- tui/
|   |   `-- app.py
|   |-- plugins/
|   |   |-- __init__.py
|   |   |-- scan.py
|   |   |-- deauth.py
|   |   |-- handshake.py
|   |   |-- pmkid.py
|   |   |-- wps.py
|   |   |-- crack.py
|   |   |-- evil_twin.py
|   |   `-- wordlist.py
|   `-- utils/
|-- tests/
|   |-- unit/
|   |-- integration/
|   `-- fixtures/pcaps/
`-- docs/
    `-- superpowers/
        `-- specs/
            `-- 2026-05-27-wlan-dumper-design.md
```

## 14. Dependencies

```
runtime:
  scapy>=2.5
  textual>=0.50
  click>=8.1
  rich
  pyyaml
  psutil

external (subprocess, runtime-detected):
  airmon-ng, aircrack-ng           # required
  hashcat                          # optional (GPU)
  hcxpcapngtool                    # optional (PMKID -> 22000)
  reaver, bully                    # optional (WPS)
  hostapd, dnsmasq                 # optional (Evil Twin)

dev:
  pytest, pytest-cov, pytest-asyncio
  ruff (lint + format)
  mypy
```

## 15. Open Decisions (Resolved)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Use case scope | All — general-purpose with per-mode guards |
| 2 | Language | Python |
| 3 | airodump-ng / aircrack-ng usage | Hybrid (scapy capture + subprocess crack) |
| 4 | Primary adapters | AR9271 + RTL8812AU (extensible matrix) |
| 5 | MVP scope | Scan + display only |
| 6 | UI | Textual |
| 7 | Attack plugins | Deauth + PMKID + WPS + Evil Twin |
| 8 | Crack engine | Both, runtime-selected (GPU -> hashcat, CPU -> aircrack-ng) |
| 9 | Architecture pattern | Plugin-based monorepo (single package, one CLI) |

## 16. Risks

- **Driver instability for RTL8812AU**: `88XXau` DKMS module breaks across kernel updates. Mitigation: explicit kernel-version check on startup with a remediation hint.
- **WPA3-SAE coverage**: pure brute force is not viable; we will detect WPA3 and disable the brute attack with a clear message rather than waste cycles.
- **Live-RF test gap**: CI cannot exercise the real radio path. We accept this and require a manual checklist per phase.
- **Legal exposure for the operator**: addressed by the authorization gate and the README warning, but ultimately the operator's responsibility.

---

## Approval

- [x] Brainstorm complete (2026-05-27)
- [x] Design approved by erkanrzgc
- [ ] User has reviewed this spec file
- [ ] Implementation plan written (`writing-plans` skill — next step)
