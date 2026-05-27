# cyberm4fia-wifi

> ⚠️ **Authorization warning.** This tool can perform actions that affect real wireless networks
> and real users. Using it against networks you do not own or do not have explicit, written
> permission to audit is illegal in most jurisdictions. The built-in authorization gate is a
> guard, not a license — the operator is responsible for compliance.

A Python-based 802.11 audit suite that fuses the airodump-ng (live scan / display) and
aircrack-ng (offline crack) workflows into a single plugin-extensible CLI with a Textual TUI.

**Phase 1 (current):** scan + display only — passive, no frames transmitted.
**Future phases:** handshake capture / deauth / PMKID / WPS (Phase 2), crack engine + Evil
Twin (Phase 3), crunch/john-style wordlist generator (Phase 4).

See [`docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-design.md`](docs/superpowers/specs/2026-05-27-cyberm4fia-wifi-design.md) for the full design.

---

## Status

Phase 1 implementation is in progress. This README will grow into the operator handbook as
modules land.
