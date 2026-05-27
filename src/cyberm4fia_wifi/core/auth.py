"""Authorization gate, mode persistence, and audit log.

Every CLI invocation passes through ``AuthorizationGate.ensure_acknowledged``
before anything else. On first launch the operator picks a mode and accepts a
short legal acknowledgment; the choice is persisted to ``$XDG_CONFIG_HOME/
cyberm4fia/authz.yaml`` (default ``~/.config/cyberm4fia/authz.yaml``).

Plugins then call ``gate.check(plugin, risk, target, reason)`` before they act.
The gate enforces:

- ``risk: passive``  — always allowed; not logged.
- ``risk: active``   — allowed when ``mode == lab``; in ``pentest`` mode the
                        ``target`` BSSID must be in the whitelist; in
                        ``general`` mode a non-None ``target`` is required;
                        every successful check is appended to the audit log.
- ``risk: high``     — requires ``reason`` to be a non-empty string
                        (passed via ``--i-am-authorized-to-do-this``); the
                        reason is logged verbatim.

In Phase 1 the gate is wired up but only the scan plugin (``risk: passive``)
calls it. The full risk matrix lives in the design spec, §5.4.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import IO

import yaml


class Mode(StrEnum):
    LAB = "lab"
    PENTEST = "pentest"
    CTF = "ctf"
    GENERAL = "general"


class PluginRisk(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    HIGH = "high"


class AuthzError(Exception):
    """Raised when an action is not authorized under the current configuration."""


_LEGAL_NOTICE = """\
cyberm4fia-wifi performs 802.11 audit actions that affect real networks and
real users. Use it only against networks you own or have explicit, written
permission to audit. You are responsible for legal compliance in your
jurisdiction. The mode you choose determines which actions are allowed and
which are recorded in the audit log.

Modes:
  lab      — you own everything in radio range (RF chamber, test APs)
  pentest  — signed engagement; only whitelisted BSSIDs accept active actions
  ctf      — educational lab; every active action is logged
  general  — default; passive scan free, active actions need per-target opt-in
"""


@dataclass
class AuthzConfig:
    mode: Mode
    acknowledged_at: str
    whitelist_bssids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> AuthzConfig | None:
        if not path.exists():
            return None
        raw = yaml.safe_load(path.read_text()) or {}
        try:
            mode = Mode(raw["mode"])
        except (KeyError, ValueError) as exc:
            raise AuthzError(f"invalid mode in {path}: {raw.get('mode')!r}") from exc
        return cls(
            mode=mode,
            acknowledged_at=str(raw.get("acknowledged_at", "")),
            whitelist_bssids=list(raw.get("whitelist_bssids") or []),
        )

    def dump(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "mode": self.mode.value,
            "acknowledged_at": self.acknowledged_at,
            "whitelist_bssids": self.whitelist_bssids,
        }
        path.write_text(yaml.safe_dump(payload, sort_keys=False))


class AuthorizationGate:
    def __init__(self, config_path: Path, audit_path: Path) -> None:
        self.config_path = config_path
        self.audit_path = audit_path
        self._config: AuthzConfig | None = None

    # ---- construction -------------------------------------------------------

    @classmethod
    def from_xdg(cls) -> AuthorizationGate:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        data_home = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
        return cls(
            config_path=config_home / "cyberm4fia" / "authz.yaml",
            audit_path=data_home / "cyberm4fia" / "audit.log",
        )

    # ---- config -------------------------------------------------------------

    def set_config(self, cfg: AuthzConfig) -> None:
        self._config = cfg

    @property
    def config(self) -> AuthzConfig:
        if self._config is None:
            loaded = AuthzConfig.load(self.config_path)
            if loaded is None:
                raise AuthzError("authorization config missing; run ensure_acknowledged() first")
            self._config = loaded
        return self._config

    def ensure_acknowledged(self, stdin: IO[str], stdout: IO[str]) -> None:
        """Run the first-launch prompt if no config exists yet."""
        existing = AuthzConfig.load(self.config_path)
        if existing is not None:
            self._config = existing
            return

        stdout.write(_LEGAL_NOTICE)
        stdout.write("\nChoose mode [lab|pentest|ctf|general]: ")
        stdout.flush()
        raw_mode = stdin.readline().strip().lower()
        try:
            mode = Mode(raw_mode)
        except ValueError as exc:
            raise AuthzError(f"unknown mode: {raw_mode!r}") from exc

        stdout.write(
            "I acknowledge the legal notice above and confirm I am authorized "
            "to use this tool against the targets I will specify [y/N]: "
        )
        stdout.flush()
        answer = stdin.readline().strip().lower()
        if answer != "y":
            raise AuthzError("acknowledgment refused; aborting")

        cfg = AuthzConfig(
            mode=mode,
            acknowledged_at=dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        cfg.dump(self.config_path)
        self._config = cfg

    # ---- enforcement --------------------------------------------------------

    def check(
        self,
        *,
        plugin: str,
        risk: PluginRisk,
        target: str | None,
        reason: str | None,
    ) -> None:
        cfg = self.config

        if risk is PluginRisk.PASSIVE:
            return  # always allowed; not logged

        if risk is PluginRisk.HIGH and not reason:
            raise AuthzError(
                f"plugin {plugin!r} has risk=high; "
                'pass --i-am-authorized-to-do-this "<reason>" to proceed'
            )

        if cfg.mode is Mode.PENTEST:
            if target is None:
                raise AuthzError(f"plugin {plugin!r} requires a --target BSSID in pentest mode")
            if target not in cfg.whitelist_bssids:
                raise AuthzError(
                    f"target {target} is not in the pentest whitelist ({cfg.whitelist_bssids})"
                )
        elif cfg.mode is Mode.GENERAL:
            if target is None:
                raise AuthzError(
                    f"plugin {plugin!r} (risk={risk.value}) requires an explicit "
                    "--target BSSID in general mode"
                )
        # lab and ctf modes do not require a target for active actions

        self._audit(plugin=plugin, mode=cfg.mode, target=target, reason=reason)

    def _audit(
        self,
        *,
        plugin: str,
        mode: Mode,
        target: str | None,
        reason: str | None,
    ) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        parts = [
            ts,
            f"mode={mode.value}",
            f"plugin={plugin}",
            f"target={target if target is not None else '-'}",
        ]
        if reason:
            parts.append(f'reason="{reason}"')
        with self.audit_path.open("a", encoding="utf-8") as fp:
            fp.write(" ".join(parts) + "\n")
