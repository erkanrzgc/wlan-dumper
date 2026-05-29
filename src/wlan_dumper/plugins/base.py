"""Plugin contract and runtime context.

Every plugin lives in its own module under ``wlan_dumper.plugins`` and
implements the ``Plugin`` ABC. Plugins are registered in the static
``REGISTRY`` list in ``plugins/__init__.py`` for Phase 1; entry-point
discovery lands in Phase 2 when there are multiple plugins.

The runtime context (``PluginContext``) carries everything a plugin needs to
do its job — the authoritative session, event bus, the chosen adapter, the
authorization gate, and the parsed CLI namespace. Plugins must not touch the
adapter directly; they go through the context so the core can enforce the
authorization rules and ensure cleanup happens.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import click

from wlan_dumper.core.adapter import DetectedAdapter
from wlan_dumper.core.auth import AuthorizationGate, PluginRisk
from wlan_dumper.core.events import EventBus
from wlan_dumper.core.session import Session


@dataclass
class PluginContext:
    session: Session
    bus: EventBus
    adapter: DetectedAdapter
    gate: AuthorizationGate
    cli_args: dict[str, Any]


class Plugin(ABC):
    name: str = ""
    risk: PluginRisk = PluginRisk.PASSIVE
    requires_injection: bool = False

    @abstractmethod
    def register_cli(self, group: click.Group) -> None:
        """Attach this plugin's subcommand(s) to the top-level CLI group."""

    @abstractmethod
    def run(self, ctx: PluginContext) -> int:
        """Execute the plugin. Return a Unix-style exit code (0 = success)."""
