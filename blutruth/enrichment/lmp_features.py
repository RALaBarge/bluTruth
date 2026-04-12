"""
blutruth.enrichment.lmp_features — LMP feature bitmap decoder

Decodes the 8-byte (64-bit) LMP Features bitmask from HCI Read Remote
Features Complete events into human-readable capability lists.

Also decodes Extended Features pages 1 and 2.

Reference: Bluetooth Core Spec 5.4, Vol 2, Part C, Section 3.3

Usage:
    from blutruth.enrichment.lmp_features import decode_lmp_features
    features = decode_lmp_features(0x875bffdbfe8fffff)
    # ["3-slot packets", "5-slot packets", "encryption", "slot offset", ...]

    ext = decode_lmp_extended(page=1, value=0x0000000f)
    # ["SSP (host)", "LE supported (host)", "simultaneous LE+BR/EDR (host)", ...]
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Page 0: standard LMP features (Vol 2, Part C, Section 3.3, Table 3.2)
# bit position → (short_name, description)
_LMP_PAGE0: Dict[int, Tuple[str, str]] = {
    0:  ("3-slot packets",          "ACL 3-slot packets (DM3/DH3)"),
    1:  ("5-slot packets",          "ACL 5-slot packets (DM5/DH5)"),
    2:  ("encryption",              "Link-level encryption supported"),
    3:  ("slot offset",             "Slot offset info in FHS"),
    4:  ("timing accuracy",         "Timing accuracy flag"),
    5:  ("role switch",             "Master/slave role switch"),
    6:  ("hold mode",               "Hold mode for power saving"),
    7:  ("sniff mode",              "Sniff mode for power saving"),
    # byte 1
    9:  ("power ctrl req",          "Power control requests"),
    10: ("CQDDR",                   "Channel quality driven data rate"),
    11: ("SCO link",                "SCO voice link (64 kbps CVSD)"),
    12: ("HV2 packets",             "HV2 SCO packet type"),
    13: ("HV3 packets",             "HV3 SCO packet type"),
    14: ("μ-law log",               "μ-law SCO coding"),
    15: ("A-law log",               "A-law SCO coding"),
    # byte 2
    16: ("CVSD",                    "CVSD voice codec (narrowband)"),
    17: ("paging param negotiation","Paging parameter negotiation"),
    18: ("power control",           "Power control"),
    19: ("transparent SCO",         "Transparent SCO data"),
    20: ("flow ctrl lag bit 0",     "Flow control lag (bit 0)"),
    21: ("flow ctrl lag bit 1",     "Flow control lag (bit 1)"),
    22: ("flow ctrl lag bit 2",     "Flow control lag (bit 2)"),
    23: ("broadcast encryption",    "Broadcast encryption supported"),
    # byte 3
    25: ("EDR ACL 2 Mbps",         "Enhanced Data Rate ACL 2 Mbps"),
    26: ("EDR ACL 3 Mbps",         "Enhanced Data Rate ACL 3 Mbps"),
    27: ("enhanced inquiry scan",   "Enhanced inquiry scan"),
    28: ("interlaced inquiry scan", "Interlaced inquiry scan"),
    29: ("interlaced page scan",    "Interlaced page scan"),
    30: ("RSSI with inquiry",       "RSSI available in inquiry results"),
    31: ("eSCO link",               "Extended SCO (eSCO) link"),
    # byte 4
    32: ("EV4 packets",             "EV4 eSCO packet type"),
    33: ("EV5 packets",             "EV5 eSCO packet type"),
    35: ("AFH capable slave",       "Adaptive Frequency Hopping (slave)"),
    36: ("AFH classification slave","AFH classification (slave)"),
    37: ("BR/EDR not supported",    "Device is LE-only (no BR/EDR)"),
    38: ("LE supported (ctrl)",     "LE supported (controller)"),
    39: ("3-slot EDR ACL",          "3-slot EDR ACL packets"),
    # byte 5
    40: ("5-slot EDR ACL",          "5-slot EDR ACL packets"),
    41: ("sniff subrating",         "Sniff subrating"),
    42: ("pause encryption",        "Pause encryption"),
    43: ("AFH capable master",      "Adaptive Frequency Hopping (master)"),
    44: ("AFH classification master","AFH classification (master)"),
    45: ("EDR eSCO 2 Mbps",        "EDR eSCO 2 Mbps"),
    46: ("EDR eSCO 3 Mbps",        "EDR eSCO 3 Mbps"),
    47: ("3-slot EDR eSCO",         "3-slot EDR eSCO packets"),
    # byte 6
    48: ("extended inquiry resp",   "Extended inquiry response"),
    49: ("simultaneous LE+BR/EDR",  "Simultaneous LE and BR/EDR (ctrl)"),
    51: ("secure simple pairing",   "Secure Simple Pairing (SSP)"),
    52: ("encapsulated PDU",        "Encapsulated PDU"),
    53: ("erroneous data reporting","Erroneous data reporting"),
    54: ("non-flushable PBF",       "Non-flushable packet boundary flag"),
    # byte 7
    56: ("link supervision TO evt", "Link supervision timeout changed event"),
    57: ("inquiry TX power level",  "Inquiry TX power level"),
    58: ("enhanced power control",  "Enhanced power control"),
    63: ("extended features",       "Extended features (pages 1+)"),
}

# Page 1: extended LMP features
_LMP_PAGE1: Dict[int, Tuple[str, str]] = {
    0: ("SSP (host)",               "Secure Simple Pairing (host support)"),
    1: ("LE supported (host)",      "LE supported (host)"),
    2: ("simultaneous LE+BR/EDR (host)", "Simultaneous LE and BR/EDR (host)"),
    3: ("secure connections (host)","Secure Connections (host support)"),
}

# Page 2: extended LMP features
_LMP_PAGE2: Dict[int, Tuple[str, str]] = {
    0: ("CSB master",               "Connectionless Slave Broadcast (master)"),
    1: ("CSB slave",                "Connectionless Slave Broadcast (slave)"),
    2: ("sync train",               "Synchronization train"),
    3: ("sync scan",                "Synchronization scan"),
    4: ("inquiry resp notif",       "HCI Inquiry Response Notification event"),
    5: ("generalized interlaced",   "Generalized interlaced scan"),
    6: ("coarse clock adj",         "Coarse clock adjustment"),
    8: ("secure connections (ctrl)","Secure Connections (controller)"),
    9: ("ping",                     "Ping"),
    10: ("slot availability mask",  "Slot availability mask"),
    11: ("train nudging",           "Train nudging"),
}

_PAGES = {0: _LMP_PAGE0, 1: _LMP_PAGE1, 2: _LMP_PAGE2}


def decode_lmp_features(value: int, page: int = 0) -> List[str]:
    """Decode an LMP feature bitmask into a list of short feature names.

    Args:
        value: The feature bitmask (up to 64 bits).
        page: Feature page number (0, 1, or 2).

    Returns:
        List of short feature name strings for set bits.
    """
    table = _PAGES.get(page, {})
    result = []
    for bit, (name, _desc) in sorted(table.items()):
        if value & (1 << bit):
            result.append(name)
    return result


def decode_lmp_features_detailed(value: int, page: int = 0) -> List[Dict[str, str]]:
    """Decode with full descriptions for each feature.

    Returns:
        List of dicts with 'bit', 'name', 'description' keys.
    """
    table = _PAGES.get(page, {})
    result = []
    for bit, (name, desc) in sorted(table.items()):
        if value & (1 << bit):
            result.append({"bit": bit, "name": name, "description": desc})
    return result


def summarize_capabilities(page0: int) -> Dict[str, bool]:
    """Summarize key capabilities from page 0 as a dict of booleans.

    Useful for quick checks like 'does this device support LE?'
    """
    return {
        "encryption":       bool(page0 & (1 << 2)),
        "sco":              bool(page0 & (1 << 11)),
        "esco":             bool(page0 & (1 << 31)),
        "edr_2mbps":        bool(page0 & (1 << 25)),
        "edr_3mbps":        bool(page0 & (1 << 26)),
        "le_supported":     bool(page0 & (1 << 38)),
        "ssp":              bool(page0 & (1 << 51)),
        "afh":              bool(page0 & (1 << 35)),
        "sniff":            bool(page0 & (1 << 7)),
        "role_switch":      bool(page0 & (1 << 5)),
        "extended_features": bool(page0 & (1 << 63)),
    }
