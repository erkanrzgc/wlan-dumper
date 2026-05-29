"""One-time legal acknowledgment + append-only audit log.

This module used to host a multi-mode authorization gate. It was removed in
favour of a simpler model: the operator is an ethical security professional,
accepts legal responsibility once, and is then trusted to run any plugin
without per-action prompts. The audit log is kept — it's a record for the
operator's own benefit (after-the-fact accountability), not a runtime gate.

Public surface:

- ``AuthorizationGate.from_xdg()`` — construct from ``$XDG_CONFIG_HOME`` and
  ``$XDG_DATA_HOME`` (defaults: ``~/.config/cyberm4fia/authz.yaml`` and
  ``~/.local/share/cyberm4fia/audit.log``).
- ``gate.ensure_acknowledged(stdin, stdout)`` — first-launch only. Shows the
  legal notice and persists a timestamp. Subsequent launches are silent.
- ``gate.check(plugin, target=None, risk=None, reason=None)`` — no-op except
  for the audit log. ``risk=PluginRisk.PASSIVE`` is not logged (too noisy).
  All other risk levels append one line. Never raises.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO

import yaml


class PluginRisk(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    HIGH = "high"


class AuthzError(Exception):
    """Raised only when the first-launch legal acknowledgment is refused."""


_LEGAL_NOTICE = """\
cyberm4fia-dumper transmits 802.11 frames (deauth) and captures traffic
that affects real networks and real users. You are responsible for legal
compliance in your jurisdiction. By proceeding you confirm you are
authorized to operate against the networks you will target.
"""


@dataclass
class AuthzConfig:
    """Persisted state. Holds the legal-acknowledgment timestamp only."""

    acknowledged_at: str

    @classmethod
    def load(cls, path: Path) -> AuthzConfig | None:
        if not path.exists():
            return None
        raw = yaml.safe_load(path.read_text()) or {}
        ts = raw.get("acknowledged_at")
        if not ts:
            return None
        return cls(acknowledged_at=str(ts))

    def dump(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump({"acknowledged_at": self.acknowledged_at}))


class AuthorizationGate:
    """One-time legal ack + audit log writer."""

    def __init__(self, config_path: Path, audit_path: Path) -> None:
        self.config_path = config_path
        self.audit_path = audit_path
        self._config: AuthzConfig | None = None

    @classmethod
    def from_xdg(cls) -> AuthorizationGate:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        data_home = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
        return cls(
            config_path=config_home / "cyberm4fia" / "authz.yaml",
            audit_path=data_home / "cyberm4fia" / "audit.log",
        )

    # ---- config ------------------------------------------------------------

    def set_config(self, cfg: AuthzConfig) -> None:
        """Test helper — preload the acknowledgment without touching disk."""
        self._config = cfg

    @property
    def config(self) -> AuthzConfig | None:
        if self._config is None:
            self._config = AuthzConfig.load(self.config_path)
        return self._config

    def ensure_acknowledged(self, stdin: IO[str], stdout: IO[str]) -> None:
        """Show the legal notice once. Silent on subsequent runs."""
        if self.config is not None:
            return

        stdout.write(_LEGAL_NOTICE)
        stdout.write("\nProceed? [y/N]: ")
        stdout.flush()
        answer = stdin.readline().strip().lower()
        if answer != "y":
            raise AuthzError("legal acknowledgment refused; aborting")

        cfg = AuthzConfig(
            acknowledged_at=dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        cfg.dump(self.config_path)
        self._config = cfg

    # ---- audit log ---------------------------------------------------------

    def check(
        self,
        *,
        plugin: str,
        risk: PluginRisk = PluginRisk.PASSIVE,
        target: str | None = None,
        reason: str | None = None,
    ) -> None:
        """No-op for passive risk; audit-log every active/high action.

        Never raises. ``reason`` is recorded verbatim when supplied; callers
        that don't have one are fine — the log line just omits it.
        """
        if risk is PluginRisk.PASSIVE:
            return
        self._audit(plugin=plugin, risk=risk, target=target, reason=reason)

    def _audit(
        self,
        *,
        plugin: str,
        risk: PluginRisk,
        target: str | None,
        reason: str | None,
    ) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        parts = [
            ts,
            f"risk={risk.value}",
            f"plugin={plugin}",
            f"target={target if target is not None else '-'}",
        ]
        if reason:
            parts.append(f'reason="{reason}"')
        with self.audit_path.open("a", encoding="utf-8") as fp:
            fp.write(" ".join(parts) + "\n")
