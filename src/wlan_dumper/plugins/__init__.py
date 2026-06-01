"""Plugin package.

Phase 1 exposes a static REGISTRY. Phase 2 will switch to entry-point
discovery so external packages can ship plugins.
"""

from wlan_dumper.plugins.base import Plugin, PluginContext
from wlan_dumper.plugins.crack import CrackPlugin
from wlan_dumper.plugins.deauth import DeauthPlugin
from wlan_dumper.plugins.handshake import HandshakePlugin
from wlan_dumper.plugins.scan import REGISTRY as _SCAN_REGISTRY
from wlan_dumper.plugins.scan import ScanPlugin

REGISTRY: list[Plugin] = [*_SCAN_REGISTRY, DeauthPlugin(), HandshakePlugin(), CrackPlugin()]

__all__ = [
    "REGISTRY",
    "CrackPlugin",
    "DeauthPlugin",
    "HandshakePlugin",
    "Plugin",
    "PluginContext",
    "ScanPlugin",
]
