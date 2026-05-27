"""Plugin package.

Phase 1 exposes a static REGISTRY. Phase 2 will switch to entry-point
discovery so external packages can ship plugins.
"""

from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.scan import REGISTRY, ScanPlugin

__all__ = ["Plugin", "PluginContext", "REGISTRY", "ScanPlugin"]
