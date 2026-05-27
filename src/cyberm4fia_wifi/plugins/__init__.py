"""Plugin package.

Phase 1 exposes a static REGISTRY. Phase 2 will switch to entry-point
discovery so external packages can ship plugins.
"""

from cyberm4fia_wifi.plugins.base import Plugin, PluginContext
from cyberm4fia_wifi.plugins.deauth import DeauthPlugin
from cyberm4fia_wifi.plugins.handshake import HandshakePlugin
from cyberm4fia_wifi.plugins.scan import REGISTRY as _SCAN_REGISTRY, ScanPlugin

REGISTRY: list[Plugin] = list(_SCAN_REGISTRY) + [DeauthPlugin(), HandshakePlugin()]

__all__ = [
    "DeauthPlugin",
    "HandshakePlugin",
    "Plugin",
    "PluginContext",
    "REGISTRY",
    "ScanPlugin",
]
