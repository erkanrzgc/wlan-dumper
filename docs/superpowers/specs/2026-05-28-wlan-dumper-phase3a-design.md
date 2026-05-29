# wlan-dumper — Phase 3a Design Spec

**Date:** 2026-05-28
**Phase:** 3a of 4 (Crack engine — turn a captured handshake into a passphrase)
**Status:** Approved (brainstorm complete, implementation plan pending)
**Prior art:** Phase 1 (scan), Phase 2a (deauth + handshake capture)

---

## 1. Purpose

Phase 2a captures WPA handshakes to `captures/handshakes/<essid>_<bssid>_<ts>.pcap`
(+ `.22000` when `hcxtools` is present). Phase 3a closes the loop: take that
artifact and **recover the passphrase** by trying candidate passwords against it.

Two candidate sources, both runnable without writing the candidate space to disk:

1. **Wordlist mode** — feed an existing password list (e.g. `rockyou.txt`) to the
   cracker. Optionally apply hashcat rules to expand each word into likely
   mutations on the fly.
2. **Mask / streaming brute-force mode** — generate candidates from a character
   pattern and stream them straight into the cracker, never storing them. This is
   the operator's key requirement: *generate a candidate, try it, discard it* —
   no 35 TB of pre-generated passwords on disk.

Evil Twin is **out of scope** here (deferred to Phase 3b). This phase is only the
offline crack stage.

## 2. Honest Constraints (design rationale)

- Disk is **not** the real wall for brute force — **time** is. WPA2 uses PBKDF2,
  which is deliberately slow: ~1–2 M candidates/s on a strong GPU (hashcat),
  orders of magnitude less on CPU (aircrack-ng).
- Full printable charset (95 chars) at length 8 ≈ 6.6 × 10¹⁵ combinations →
  ~100+ years even on GPU. Streaming solves the disk problem but not the time
  problem.
- Therefore the design steers the operator toward **realistic** attacks:
  popular wordlists, rule-based mutation, and **constrained** masks (digits-only,
  known prefixes, phone/date patterns). A **keyspace + ETA estimator** is shown
  before any run so the operator never unknowingly starts a 200-year job.

## 3. Backend Dispatch

`utils/crack_engine.py` auto-detects available backends at runtime:

| Condition | Backend | Input |
|-----------|---------|-------|
| `hashcat` present (GPU or CPU OpenCL) | **hashcat** `-m 22000` | `.22000` |
| else `aircrack-ng` present | **aircrack-ng** | `.pcap` / `.cap` |
| neither | clean error: "install aircrack-ng or hashcat" |

- `detect_backends()` → `{hashcat: bool, aircrack: bool, gpu: bool}` via
  `shutil.which` + a best-effort `hashcat -I` / `nvidia-smi` probe.
- Operator may force a backend with `--engine hashcat|aircrack`.
- If the chosen input format is missing (e.g. hashcat wants `.22000` but only a
  `.pcap` exists), convert via `hcxpcapngtool` (already wrapped in Phase 2a); if
  that's unavailable, fall back to aircrack-ng with a notice.

## 4. Crack Modes

### 4.1 Wordlist mode
- **hashcat:** `hashcat -m 22000 -a 0 <hash.22000> <wordlist> [-r <rules>]`
- **aircrack-ng:** `aircrack-ng -w <wordlist> -b <bssid> <pcap>`
- **Rules (hashcat only, optional):** `-r <rulefile>` mutates each word
  (capitalize, leet, append digits…) in-engine — no expanded list on disk.
  Curated default rule paths are auto-discovered (e.g.
  `/usr/share/hashcat/rules/best64.rule`).

### 4.2 Mask / streaming brute-force mode (no disk)
- **hashcat:** `hashcat -m 22000 -a 3 <hash.22000> <mask>` — hashcat generates
  the keyspace internally on the GPU; nothing is written to disk.
- **aircrack-ng:** `crunch <min> <max> <charset> [-t <pattern>] | aircrack-ng -w - -b <bssid> <pcap>`
  — `crunch` streams candidates to stdout, `aircrack-ng -w -` consumes them from
  stdin; nothing is stored. If `crunch` is absent, an internal Python generator
  (`itertools.product` over the charset) provides the same stdin stream as a
  fallback.

### 4.3 Mask presets
Operators rarely want to hand-write hashcat masks. The crack modal/CLI offers a
small curated list of the most common WPA passphrase shapes; each maps to a
hashcat mask and an equivalent crunch charset/pattern:

| Preset | hashcat mask | keyspace |
|--------|--------------|----------|
| 8 digits (phone/date) | `?d?d?d?d?d?d?d?d` | 10⁸ |
| 10 digits | `?d?d?d?d?d?d?d?d?d?d` | 10¹⁰ |
| 8 lower alpha | `?l?l?l?l?l?l?l?l` | 26⁸ |
| 8 lower+digit | `-1 ?l?d ?1?1?1?1?1?1?1?1` (custom charset 1) | 36⁸ |
| Custom | operator-supplied mask | computed |

> Note: hashcat's built-in `?h` is hex (0-9a-f), **not** lower+digit — the
> lower+digit preset must define a custom charset via `-1 ?l?d`. The crunch
> equivalent uses the charset string `abcdefghijklmnopqrstuvwxyz0123456789`.

## 5. Keyspace + ETA Estimator

`utils/crack_engine.estimate(mask_or_wordlist, rate)`:
- **Mask:** product of per-position charset sizes → total candidates.
- **Wordlist:** line count (× rule count if rules applied).
- ETA = total / detected_rate. Detected rate comes from a tiny benchmark or a
  conservative default per backend (hashcat: 1.0 M/s; aircrack: 2 k/s) until the
  live run reports a real rate.
- Rendered in the modal/CLI before start: e.g. `1.0e8 candidates · ~83s @ 1.2M/s`
  or `6.6e15 candidates · ~210 years ⚠`. A red warning shows when ETA exceeds a
  threshold (e.g. > 24 h).

## 6. Execution Model (background worker + live progress)

- `CrackPlugin.execute()` launches the backend as a subprocess on a worker
  thread; the TUI never blocks and the scan keeps running.
- The subprocess's stdout is parsed line-by-line into progress events:
  - **aircrack-ng:** parse `[hh:mm:ss] N/M keys tested (R k/s)` → tried, total, rate.
  - **hashcat:** run with `--status --status-timer 2 --machine-readable` (or
    `--status-json`) and parse the periodic status lines → progress, rate, ETA.
- Cancellation: a TUI key (`x`) or `Ctrl+C` in CLI sends SIGTERM then SIGKILL to
  the subprocess (and the `crunch` producer, if piped).

## 7. New Events (`core/events.py`)

```python
@dataclass(frozen=True, slots=True)
class CrackProgress(Event):
    bssid: str
    tried: int
    total: int | None        # None when keyspace is unbounded/unknown
    rate: float              # candidates/sec
    eta_seconds: int | None

@dataclass(frozen=True, slots=True)
class CrackComplete(Event):
    bssid: str
    password: str | None     # None = exhausted, not found
    backend: str             # "hashcat" | "aircrack-ng"
```

## 8. Session Extension (`core/session.py`)

`APRecord` gains `cracked_password: str | None = None`. `CrackComplete` with a
non-None password sets it (sticky). `handle_event` + `attach` learn the event.

## 9. Output / Persistence

On a successful crack:
- File: `captures/cracked/<safe-essid>_<bssid>.txt`, content `ESSID:BSSID:password`
  (one line; `utils/paths.cracked_path()` already provides the directory).
- `CrackComplete` → `APRecord.cracked_password`.
- AP table: new **PW** column — green `✓` when cracked, dim `·` otherwise.
- AP Details: a `Cracked: <password>` row (green).
- Log: `CRACKED  <bssid>  password=<password>`.

## 10. New Utility Modules

- **`utils/wordlist.py`**
  - `discover_wordlists() -> list[Path]` — scans known locations
    (`/usr/share/wordlists/rockyou.txt`, `/usr/share/wordlists/*.txt`, also a
    gzipped `rockyou.txt.gz`) and returns existing ones for the picker.
  - `validate_wordlist(path) -> None` — raises a clear error if missing/unreadable.
  - `discover_rules() -> list[Path]` — finds hashcat rule files
    (`/usr/share/hashcat/rules/*.rule`).
- **`utils/crack_engine.py`**
  - `detect_backends()`, `estimate(...)`, `build_command(...)` (returns argv +
    whether a `crunch` producer pipe is needed), and `run_crack(...)` (spawns the
    subprocess(es), parses output, emits `CrackProgress`/`CrackComplete`). All
    subprocess calls go through a patchable indirection for tests.
  - `MASK_PRESETS` — the curated preset table from §4.3.

## 11. CLI

```bash
# Wordlist
wlan-dumper crack --pcap captures/handshakes/X.pcap --wordlist /usr/share/wordlists/rockyou.txt
wlan-dumper crack --hashfile X.22000 --engine hashcat -w rockyou.txt -r best64

# Mask / streaming brute-force (no disk)
wlan-dumper crack --pcap X.pcap --mask '?d?d?d?d?d?d?d?d'
wlan-dumper crack --pcap X.pcap --preset 8-digits
```

`--bssid` selects the target when a capture holds more than one. Exactly one of
`--wordlist` / `--mask` / `--preset` is required.

## 12. TUI Changes (`tui/app.py`, `tui/modals.py`)

- **`c`** binding → `CrackModal`, enabled only when the selected AP has
  `handshake_count > 0` (otherwise a "no handshake captured for this AP" notice).
  Modal fields: mode (Wordlist / Mask), wordlist picker (with discovered
  suggestions) **or** mask preset + custom mask, engine (auto/hashcat/aircrack),
  optional rules, and a live **keyspace + ETA** line. Start / Cancel.
- **`x`** binding → cancel the running crack.
- AP table: new **PW** column after **HS**.
- AP Details: `Cracked:` row.
- Log formatters for `CrackProgress` (`CRACK  <bssid>  45%  1.2M  3450k/s  ETA 8m`)
  and `CrackComplete` (`CRACKED  <bssid>  password=…` or `CRACK  <bssid>  not found`).

## 13. Error Handling

- No backend installed → clean error naming both tools.
- Wordlist missing/unreadable → clear error (modal blocks Start; CLI exits 1).
- hashcat selected but no `.22000` and no `hcxtools` → fall back to aircrack-ng
  with a notice, or error if aircrack also missing.
- Exhausted without a hit → `CrackComplete(password=None)`; surfaced as
  "not found" (not an error).
- Subprocess crash → `PluginError`, surfaced in the TUI; producer pipe cleaned up.
- Cancel → SIGTERM then SIGKILL to backend and any `crunch` producer.
- Estimator shows a warning (does not block) when ETA is absurd.

## 14. Testing Strategy

| Layer | Approach | Coverage |
|-------|----------|----------|
| `utils/wordlist` discovery/validate | tmp_path fake filesystem | 90%+ |
| `utils/crack_engine.detect_backends` | mock `shutil.which` + probe | 90%+ |
| `estimate()` | mask/wordlist → known counts + ETA math | 100% |
| `build_command()` | hashcat vs aircrack vs crunch-pipe argv | 90%+ |
| aircrack stdout parser | fixture lines → `CrackProgress` | 90%+ |
| hashcat status parser | fixture machine-readable lines → `CrackProgress` | 90%+ |
| `run_crack()` | mocked subprocess streaming lines → events | 80%+ |
| `plugins/crack.execute` | synthetic backend → `CrackComplete` + file write | 80%+ |
| Session `cracked_password` | `CrackComplete` → `APRecord` | 100% |
| `CrackModal` | Textual snapshot: wordlist vs mask, ETA line, no-handshake block | smoke |
| Live | manual README checklist: crack own handshake with rockyou + an 8-digit mask | n/a |

## 15. Files Affected

```
core/events.py            modified  (+CrackProgress, +CrackComplete)
core/session.py           modified  (+cracked_password, handler, attach)
plugins/crack.py          new
plugins/__init__.py       modified  (REGISTRY += CrackPlugin)
tui/app.py                modified  (+c/x bindings, +PW column, +Cracked row, +log formatters)
tui/modals.py             modified  (+CrackModal)
utils/wordlist.py         new
utils/crack_engine.py     new
tests/unit/core/...       new test modules + session/events updates
README.md                 modified  (+crack quickstart + acceptance checklist)
captures/cracked/         exists from Phase 1; runtime artifacts go here
```

## 16. Open Decisions (resolved during brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Backends | Both, runtime auto-detect (GPU→hashcat, else aircrack-ng) |
| 2 | Trigger | TUI `c` key + `wlan-dumper crack` CLI |
| 3 | Wordlist selection | Path input + auto-discovery of popular lists |
| 4 | Execution | Background worker, live progress, cancellable |
| 5 | Result | File + TUI (PW column, Details row) + session field |
| 6 | Brute force | Mask/streaming, **no disk** (hashcat `-a 3` / `crunch \| aircrack -w -`) |
| 7 | Smart filtering | Popular wordlists + mask presets + optional hashcat rules |
| 8 | Safety | Keyspace + ETA estimate shown before start; warn on absurd ETA |

## Approval

- [x] Brainstorm complete (2026-05-28)
- [x] Design approved by erkanrzgc (incl. no-disk streaming brute force + heavy filtering)
- [ ] User has reviewed this spec file
- [ ] Implementation plan written (`writing-plans` skill — next step)
