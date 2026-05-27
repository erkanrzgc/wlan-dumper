# cyberm4fia-wifi — Phase 2a Design Spec

**Date:** 2026-05-27
**Phase:** 2a of 4 (Active actions — deauth + handshake capture)
**Status:** Approved (brainstorm complete, implementation plan pending)
**Prior art:** `2026-05-27-cyberm4fia-wifi-design.md` (overall four-phase plan)

---

## 1. Purpose

Add the first two active 802.11 plugins on top of the Phase 1 passive scan/TUI:

- **`deauth`** — forges and injects 802.11 deauthentication frames with the AP's BSSID spoofed in the source field, disconnecting the targeted client (or every client on the AP if broadcast).
- **`handshake`** — locks the radio onto the target AP's channel, watches for EAPOL key frames, tracks the WPA 4-way state machine, optionally pulls in `deauth` to provoke a reconnect, dumps the captured frames to `captures/handshakes/<essid>_<bssid>_<ts>.pcap`, and (when `hcxpcapngtool` is installed) auto-converts to the hashcat-ready `.22000` format for Phase 3.

Both plugins are triggerable from inside the existing scan TUI via a confirm modal — the operator should never have to leave the TUI for the common case — and from the CLI for automation.

PMKID, WPS, and Evil Twin are intentionally out of scope here and are scheduled for Phase 2b / Phase 3.

## 2. Non-Goals

- No PMKID, WPS, or Evil Twin in this phase (Phase 2b / Phase 3).
- No cracking (Phase 3). Phase 2a stops at producing valid `.pcap` + `.22000` artifacts.
- No 802.11w (Management Frame Protection) bypass attempts — we detect MFP and warn; we do not try to defeat it.
- No deauth flooding as a denial-of-service tool. Default burst is small (8 frames); flag is recorded in the audit log.

## 3. Workflow (TUI primary path)

```
[scan TUI running] -> pick AP with arrow keys -> press 'h'
   |
   v
[HandshakeModal opens]
   Target AP    : Cudy-Outdoor (80:af:ca:27:b0:78)
   Channel      : 6           (will lock on confirm)
   MFP status   : not detected
   Target STA   : <dropdown: pick a client | broadcast>
   Auto-deauth  : [x] yes
   Deauth count : [ 8 ]
   Timeout      : [ 60s ]
   Reason       : [ free text — required, audit-logged verbatim ]
   [ Cancel ]  [ Start ]
   |
   v
[hopper.lock(6); EAPOL filter armed in sniffer]
   |
   v   (if auto-deauth: 8 frames -> target STA, spoofing AP MAC)
[Live Events panel streams the burst]
   [deauth] -> 11:22:33:44:55:66 (1/8) src=80:af:ca:27:b0:78
   ...
   [deauth] -> 11:22:33:44:55:66 (8/8) src=80:af:ca:27:b0:78
   |
   v   (client reconnects; we sniff the 4-way)
[Live Events panel streams the handshake]
   [eapol ] M1/4 <- AP   (80:af:ca:27:b0:78)
   [eapol ] M2/4 -> AP   (11:22:33:44:55:66)
   [eapol ] M3/4 <- AP
   [eapol ] M4/4 -> AP   complete
   |
   v
[handshake plugin calls hcxpcapngtool to validate + convert]
[Live Events]
   [handshake] saved captures/handshakes/Cudy-Outdoor_80afca27b078_20260527-142315.pcap
   [handshake] saved captures/handshakes/Cudy-Outdoor_80afca27b078_20260527-142315.22000
   |
   v
[notification toast: "Handshake captured — ready for Phase 3 crack"]
[hopper unlocks, EAPOL filter disarms]
```

Equivalent CLI (automation):

```
./cyberm4fia.sh handshake \
    --target AA:BB:CC:DD:EE:01 \
    --client 11:22:33:44:55:66 \
    --count 8 --timeout 60 \
    --reason "engagement 4711 — my router lab test"
```

Standalone `deauth` (without capture):

```
./cyberm4fia.sh deauth \
    --target AA:BB:CC:DD:EE:01 \
    --client 11:22:33:44:55:66 --count 8 \
    --reason "..."
```

## 4. Architecture

### 4.1 Plugin Composition

```
HandshakePlugin.execute
   |
   |-- arms sniffer EAPOL filter (subscribes to EAPOLCapture)
   |-- hopper.lock(channel)
   |-- if auto_deauth: DeauthPlugin.execute(burst=N)
   |       |-- AuthorizationGate.check(plugin="deauth", risk=HIGH, ...)
   |       |-- scapy sendp() x N -> emits DeauthSent events
   |-- state machine consumes EAPOLCapture events
   |       state[(bssid, sta)] = set of message indices {1, 2, 3, 4}
   |       all frames appended to <captures>/handshakes/<...>.pcap
   |-- when {1,2} or {1,2,3,4} present: invoke hcxpcapngtool
   |       valid -> emit HandshakeComplete, finish
   |       invalid -> keep listening until timeout
   |-- finally: hopper.unlock, unsubscribe, restore filter
```

`HandshakePlugin` owns the orchestration. `DeauthPlugin` is reusable in isolation
(CLI `deauth` subcommand) and as a child of `HandshakePlugin` when
`auto_deauth=True`. They never share state — composition is explicit through the
`PluginContext`.

### 4.2 New Events (`core/events.py`)

```python
@dataclass(frozen=True, slots=True)
class DeauthSent(Event):
    target_bssid: str
    target_station: str | None   # None = broadcast
    sequence: int                # 1-based position inside the burst
    total: int                   # burst size

@dataclass(frozen=True, slots=True)
class EAPOLCapture(Event):       # declared in Phase 1 with placeholder fields,
                                 # now emitted with the real contract
    bssid: str
    station: str
    message_index: int | None    # 1..4, or None if undecodable
    raw: bytes                   # full frame bytes for the pcap writer
# NOTE: replaces the Phase-1 placeholder field `pcap_offset: int`. The
#       class is still not emitted in Phase 1, so the field change is a
#       safe evolution rather than a breaking rename.

@dataclass(frozen=True, slots=True)
class HandshakeComplete(Event):
    bssid: str
    station: str
    pcap_path: str
    hashcat_path: str | None     # None when hcxpcapngtool is missing or rejected
    valid_by_hcxtool: bool       # False -> we kept the pcap but tool said no
```

`PluginStarted` / `PluginFinished` / `PluginError` remain the contract for plugin
lifecycle and don't change.

### 4.3 Session Extensions (`core/session.py`)

`APRecord` gains:

- `handshake_count: int = 0` — incremented on each `HandshakeComplete` for this BSSID.
- `mfp_status: str = "unknown"` — one of `unknown / none / capable / required`, sourced from the RSN Capabilities field in the beacon.

`Session.handle_event` learns to consume `HandshakeComplete` and (already consumes channel/beacon/client events).

### 4.4 Sniffer Extensions (`core/sniffer.py`)

`dissect_packet` gains an EAPOL branch:

```python
if pkt.haslayer(EAPOL):
    bssid, station = _extract_eapol_pair(pkt)
    mi = message_index(pkt)
    out.append(EAPOLCapture(
        timestamp=ts, bssid=bssid, station=station,
        message_index=mi, raw=bytes(pkt),
    ))
```

Beacon dissection learns the MFP bit (RSN Capabilities byte 0, bits 6-7) and
publishes it as a new attribute of `BeaconSeen`:

```python
mfp_status: str = "unknown"   # "none" | "capable" | "required" | "unknown"
```

Session promotes this onto `APRecord.mfp_status` with the same stickiness rule
we use for WPS (a single beacon that fails to parse must not erase a known
status).

### 4.5 New Utility Modules

- **`utils/eapol.py`** — `message_index(pkt: Any) -> int | None` parses the EAPOL Key Information field (IEEE 802.11-2016, §12.7.6) and returns 1, 2, 3, or 4. Pure function, fixture-tested.
- **`utils/pcap_writer.py`** — append-mode pcap helper using `scapy.utils.PcapWriter` with `append=True, sync=True` so a crash mid-capture doesn't lose frames.
- **`utils/hcxtools.py`** — `convert_to_22000(pcap_path: Path) -> Path | None` shells out to `hcxpcapngtool -o <out.22000> <pcap>`; returns the new path on success, `None` if the tool is missing (with a one-time WARN log) or rejected the pcap.

### 4.6 TUI Changes (`tui/app.py`, new `tui/modals.py`)

Bindings appended to `ScanApp.BINDINGS`:

```python
Binding("d", "deauth_prompt", "Deauth"),
Binding("h", "handshake_prompt", "Handshake"),
```

`tui/modals.py` defines `HandshakeModal(ModalScreen[HandshakeRequest])`:

- Header: `Capture handshake for <ESSID>`.
- Fields, in order: Target STA (Select widget populated from the AP's known clients plus a `broadcast` option), Auto-deauth (Switch), Deauth count (Input, numeric, default 8), Timeout (Input, default 60), Reason (Input, multiline=False, required).
- MFP status row above the fields: green check if `none`, yellow warn if `capable`, red block + "Override?" checkbox if `required` (the override checkbox must be explicitly checked to enable the **Start** button).
- Buttons: **Cancel** (Esc) returns `None`. **Start** (Enter when valid) returns a populated `HandshakeRequest` dataclass.

`action_handshake_prompt` opens the modal, awaits the result, calls `HandshakePlugin.execute(...)` with the gathered parameters. Plugin runs on a worker thread; `Live Events` log already reactively renders the new event types because we just need to add their `__str__`-equivalent formatters in `_log_event`.

`AP Details` panel adds two rows:

- **MFP** — colour-coded (`none` dim, `capable` yellow, `required` red).
- **Handshakes** — `ap.handshake_count` (bold green if > 0).

### 4.7 CLI Changes (`cli.py`, new plugin subcommands)

Each new plugin registers its own Click subcommand (`deauth`, `handshake`)
through the existing `register_cli` hook. Global options (`--iface`, `--mode`)
remain at the root. Per-subcommand options:

```
deauth     --target / -t   BSSID (required)
           --client / -c   STA MAC or "broadcast" (required)
           --count / -n    int, default 8
           --reason / -r   string (required; alias of --i-am-authorized-to-do-this)

handshake  --target / -t   BSSID (required)
           --client / -c   STA MAC or "broadcast" (optional; default broadcast)
           --no-deauth     boolean flag, disables auto-deauth
           --count / -n    int, default 8
           --timeout       int seconds, default 60
           --reason / -r   string (required)
```

`--reason` is the friendly alias; `--i-am-authorized-to-do-this` from the spec
remains accepted for backwards compatibility with anything that uses the full
form.

## 5. Authorization

Per the spec's risk matrix (Phase 1 design §5.4), updated for these plugins:

| Plugin | Risk | Active-action target required | Reason required | Audit-logged |
|--------|------|-------------------------------|-----------------|--------------|
| `deauth` | `high` | yes (`general`/`pentest` modes) | yes (always, all modes) | yes |
| `handshake` (`auto_deauth=False`) | `active` | yes (`general`/`pentest` modes) | yes if `general`/`pentest` | yes |
| `handshake` (`auto_deauth=True`) | `high` (effective, via child deauth) | yes | yes | yes |

`HandshakePlugin.execute` re-runs `AuthorizationGate.check` with risk=high
when `auto_deauth=True` — the child plugin's gate call alone would also catch
it, but checking up front prevents wasted radio time. Both calls produce the
same audit-log signature so we don't double-count.

Audit log line gains two extra fields when relevant:

```
2026-05-27T14:23:10Z mode=lab plugin=handshake target=AA:BB:CC:DD:EE:01 \
    reason="my own router, lab test" auto_deauth=yes count=8
```

## 6. File Format

```
captures/handshakes/<safe-essid>_<bssid-no-colons>_<YYYYMMDD-HHMMSS>.pcap
captures/handshakes/<safe-essid>_<bssid-no-colons>_<YYYYMMDD-HHMMSS>.22000
```

`utils/paths.handshake_path(essid, bssid, ts)` from Phase 1 already produces
the `.pcap` name. The `.22000` path is the same with the suffix swapped.

Filename rule recap (already enforced by `paths._safe_essid`):

- ESSID: `[A-Za-z0-9_-.]` only, non-matching chars become `_`, capped at 32 chars, falls back to `hidden`.
- BSSID: lowercase hex, no separators.
- Timestamp: `YYYYMMDD-HHMMSS` UTC.

The pcap is written incrementally during capture (append mode, fsync each
frame) so an interrupted capture still leaves a valid pcap for partial
diagnosis.

## 7. Error Handling

- **MFP `required` AP without operator override** → modal blocks Start, toast: "MFP is required on this AP; deauth will be ignored. Check Override to try anyway."
- **Adapter without injection support** (`profile.injection == False`) → `deauth` plugin refuses early with `ClickException`, points the operator at the adapter list. `handshake` with `auto_deauth=False` still runs.
- **scapy `sendp` permission denied** (non-root) → clean error, suggests `./cyberm4fia.sh ...` wrapper.
- **`hcxpcapngtool` missing** → one-time WARN, `.pcap` still saved, `HandshakeComplete.hashcat_path = None`. Operator can convert later.
- **Timeout reached without `{1,2,3,4}`** → `HandshakeComplete(valid_by_hcxtool=False)` if `{1,2}` exists (partial may still be crackable), or `PluginError` if nothing captured. Either way the partial pcap is kept.
- **Plugin crash** → caught at the top-level handler (existing pattern), audit-logged, sniffer + hopper restored.

No silent failures.

## 8. Testing Strategy

| Layer | Approach | Coverage target |
|-------|----------|-----------------|
| `utils/eapol.message_index` | scapy fixtures for M1/M2/M3/M4 EAPOL frames | 100% |
| `utils/pcap_writer.append_to_pcap` | tmp_path round-trip, partial-write durability | 90%+ |
| `utils/hcxtools.convert_to_22000` | subprocess mocked (success / tool-missing / non-zero exit) | 90%+ |
| `core/sniffer` EAPOL branch | replay synthesized EAPOL packets, assert `EAPOLCapture` shape | 80%+ |
| `core/sniffer` MFP parse | beacon fixture with RSN capabilities byte set | 80%+ |
| `plugins/deauth.execute` | scapy `sendp` mocked, assert frame count + Dot11 fields + event burst | 80%+ |
| `plugins/handshake.execute` | feed synthesized `EAPOLCapture` events through worker, assert state progression + emitted `HandshakeComplete` + pcap write | 80%+ |
| `tui/modals.HandshakeModal` | Textual snapshot — empty state, validation error, MFP-required block, valid submit | smoke |
| Live RF | Manual: README checklist (capture handshake against operator's own router) | n/a |

CI thresholds remain per-package as set in Phase 1 (`pytest --cov` enforces
70 % overall, with the per-package overrides from spec §11).

## 9. Manual RF Acceptance Checklist (Phase 2a)

- [ ] `./cyberm4fia.sh handshake --target <own router> --reason "..."` produces a `.pcap` ≥ 1 KB in `captures/handshakes/`.
- [ ] The same run also writes a `.22000` if `hcxpcapngtool` is installed.
- [ ] `hcxpcapngtool` round-trip: independently re-run on the `.pcap` accepts it as a valid handshake.
- [ ] TUI: pressing `h` opens the modal; cancelling closes cleanly; submitting runs end-to-end without leaving the radio in monitor mode if the operator aborts mid-capture.
- [ ] Live Events panel shows `[deauth]` then `[eapol]` then `[handshake]` lines in order.
- [ ] AP Details panel `Handshakes` counter increments after a successful capture.
- [ ] Audit log gets one line per `deauth` and one per `handshake` invocation.
- [ ] An AP with MFP=required produces a blocked modal until Override is checked.

## 10. Risks

- **MFP coverage** — increasingly common on WPA2-Enterprise and WPA3 networks; deauth is ineffective there. Spec accepts this and surfaces the warning.
- **Random / private client MACs** — iPhones and modern Android devices randomize MACs per SSID. A "target client" picker may show MACs that change between scans. Documented in the TUI hint.
- **Driver injection quirks** — RTL88x2bu's injection is unverified in our matrix; on operator's hardware it works for monitor + scan but injection may behave differently. Plugin will surface scapy's send errors as `PluginError` rather than swallowing them.
- **hcxpcapngtool absent on minimal Kali installs** — handled gracefully; phase 3 crack can still consume the raw `.pcap` via aircrack-ng's own parser.

## 11. Open Decisions (Resolved during brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Phase 2 sub-scope | 2a = deauth + handshake; 2b = PMKID + WPS (separate spec) |
| 2 | Auto-deauth behaviour in handshake mode | User-selectable in the confirm modal; default on |
| 3 | Output format | `.pcap` + auto-convert to `.22000` via `hcxpcapngtool` |
| 4 | Modal fields | Full — reason + auto-deauth + count + timeout + target picker + broadcast toggle + MFP check |
| 5 | Handshake validation | Hybrid — native M1–M4 state machine for live TUI progress + `hcxpcapngtool` for final validation |
| 6 | CLI primacy | TUI primary; CLI subcommands kept for automation; same plugin code path |

## 12. Files Affected

```
src/cyberm4fia_wifi/
   core/events.py            modified  (+DeauthSent, +HandshakeComplete, +mfp on BeaconSeen)
   core/sniffer.py           modified  (+EAPOL branch, +MFP parse)
   core/session.py           modified  (+handshake_count, +mfp_status, +HandshakeComplete handler)
   plugins/__init__.py       modified  (REGISTRY += DeauthPlugin, HandshakePlugin)
   plugins/deauth.py         new
   plugins/handshake.py      new
   tui/app.py                modified  (+d/h bindings, +action handlers, +log formatters)
   tui/modals.py             new       (HandshakeModal + HandshakeRequest dataclass)
   utils/eapol.py            new
   utils/pcap_writer.py      new
   utils/hcxtools.py         new

tests/unit/core/
   test_deauth.py            new
   test_handshake.py         new
   test_eapol.py             new
   test_pcap_writer.py       new
   test_hcxtools.py          new
   test_handshake_modal.py   new
   test_sniffer.py           modified  (+EAPOL + MFP fixtures)
   test_session.py           modified  (+handshake counter + mfp persistence)

docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-phase2a-design.md  (this file)
README.md                    modified  (+Phase 2a quickstart + acceptance checklist)
captures/handshakes/         exists from Phase 1; runtime artifacts go here
```

---

## Approval

- [x] Brainstorm complete (2026-05-27)
- [x] Design approved by erkanrzgc
- [ ] User has reviewed this spec file
- [ ] Implementation plan written (`writing-plans` skill — next step)
