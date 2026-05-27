"""Tiny in-tree OUI → vendor lookup.

A full IEEE OUI database is ~5 MB and updates monthly. For Phase 1 we only
need vendor labels in the AP details panel, so we ship a curated subset of
~80 prefixes covering the brands most commonly seen on home and corporate
WiFi: ISP routers, the big consumer brands, and the SoC vendors that get
randomized into client MACs.

A miss returns ``None`` and the caller falls back to showing the raw OUI.
"""

from __future__ import annotations

# Keys are lowercase, no separators (first 24 bits of the MAC).
_OUI: dict[str, str] = {
    # Router / AP vendors (ISP + consumer)
    "80afca": "Cudy",
    "82afca": "Cudy",
    "f81a67": "TP-Link",
    "f4f26d": "TP-Link",
    "909a4a": "TP-Link",
    "245a4c": "TP-Link",
    "74da38": "Tenda",
    "c0a0bb": "D-Link",
    "0024b2": "Netgear",
    "847b57": "Netgear",
    "00037f": "Atheros",
    "001b2f": "Netgear",
    "001de1": "Cisco-Linksys",
    "00112f": "Asus",
    "0026b8": "Asus",
    "501c43": "Asus",
    "086361": "Huawei",
    "104f58": "Huawei",
    "1c66aa": "Samsung",
    "001bdc": "Vodafone",
    "6038e0": "Vodafone",
    "c0d962": "TurkTelekom",
    "885d90": "TurkTelekom",
    "002275": "AirTies",
    "0024d3": "AirTies",
    "b482fe": "AskeyComputer",
    "00264a": "ZyXEL",
    "0024a5": "Buffalo",
    "00037f1": "Atheros",
    "00908f": "Audio-Tech",
    "001fb3": "Mikrotik",
    "4c5e0c": "Mikrotik",
    "e48d8c": "Mikrotik",
    "dca632": "Ubiquiti",
    "245a4c": "TP-Link",
    "98ded0": "TP-Link",
    "74832c": "RuckusWireless",
    # Client device vendors (phones / laptops — useful when STA shows up)
    "f04f7c": "Apple",
    "a4c361": "Apple",
    "f0989d": "Apple",
    "ace7b9": "Apple",
    "8c8590": "Apple",
    "405bd8": "Apple",
    "001ec2": "Apple",
    "c83a35": "Tenda",
    "4cbb58": "Xiaomi",
    "286c07": "Xiaomi",
    "8c53c3": "Xiaomi",
    "94fbb2": "Xiaomi",
    "8c1d96": "Sony",
    "f4f5d8": "Google",
    "947bbe": "Samsung",
    "002566": "Samsung",
    "9cd917": "Samsung",
    "ec1f72": "Samsung",
    "00ec0a": "Samsung",
    # SoC / chipset vendors used in randomized client MACs
    "001a11": "Google",
    "001302": "Intel",
    "8c705a": "Intel",
    "001b21": "Intel",
    "0050f2": "Microsoft",
    "00037f": "Atheros",
    "00226b": "Cisco-Linksys",
    "001cdf": "Belkin",
    "0090a9": "Western-Digital",
}


def oui_for(bssid: str) -> str | None:
    """Return the vendor name for a BSSID, or None for an unknown OUI.

    Recognises both colon-separated (``AA:BB:CC:DD:EE:FF``) and bare hex
    (``aabbccddeeff``) forms; case-insensitive.
    """
    if not bssid:
        return None
    cleaned = bssid.replace(":", "").replace("-", "").lower()
    if len(cleaned) < 6:
        return None
    return _OUI.get(cleaned[:6])


def is_locally_administered(bssid: str) -> bool:
    """True if the BSSID has the locally-administered bit set.

    Set on randomized client MACs (iPhone private addresses, Android
    randomization, etc.); a true here is a strong hint the OUI lookup is
    meaningless because the address was generated locally.
    """
    if not bssid or ":" not in bssid and len(bssid) < 2:
        return False
    first = bssid.replace(":", "")[:2]
    try:
        return bool(int(first, 16) & 0x02)
    except ValueError:
        return False
