"""
blutruth.enrichment.smp_features — SMP (Security Manager Protocol) decoder

Decodes SMP pairing feature exchange fields from BLE Security Manager
Protocol packets captured in HCI traffic.

Reference: Bluetooth Core Spec 5.4, Vol 3, Part H

Usage:
    from blutruth.enrichment.smp_features import (
        decode_io_capability, decode_auth_req, decode_key_dist
    )
    io = decode_io_capability(0x03)     # "NoInputNoOutput"
    auth = decode_auth_req(0x0D)        # ["bonding", "MITM", "SC"]
    keys = decode_key_dist(0x07)        # ["EncKey", "IdKey", "Sign"]
"""
from __future__ import annotations

from typing import Dict, List, Optional

# SMP IO Capabilities (Vol 3, Part H, Section 3.5.1)
_IO_CAPABILITIES: Dict[int, str] = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

# SMP OOB Data Flag (Vol 3, Part H, Section 3.5.2)
_OOB_DATA: Dict[int, str] = {
    0x00: "OOB not available",
    0x01: "OOB available",
}

# SMP AuthReq bit flags (Vol 3, Part H, Section 3.5.1)
_AUTH_REQ_BITS: Dict[int, str] = {
    0: "bonding",       # bit 0-1: bonding flags (00=no bonding, 01=bonding)
    2: "MITM",          # bit 2: Man-in-the-middle protection required
    3: "SC",            # bit 3: Secure Connections
    4: "keypress",      # bit 4: Keypress notifications
    5: "CT2",           # bit 5: Cross-Transport Key Derivation
}

# SMP Key Distribution (Vol 3, Part H, Section 3.6.1)
_KEY_DIST_BITS: Dict[int, str] = {
    0: "EncKey",        # bit 0: LTK + EDIV + Rand (encryption key)
    1: "IdKey",         # bit 1: IRK + BD_ADDR (identity key)
    2: "Sign",          # bit 2: CSRK (signing key)
    3: "LinkKey",       # bit 3: BR/EDR link key derivation
}

# SMP pairing methods based on IO capabilities
# (initiator_io, responder_io) → method
_PAIRING_METHOD: Dict[tuple, str] = {
    (0x00, 0x00): "JustWorks",
    (0x00, 0x01): "JustWorks",
    (0x00, 0x02): "PasskeyEntry (responder enters)",
    (0x00, 0x03): "JustWorks",
    (0x00, 0x04): "PasskeyEntry (responder enters)",
    (0x01, 0x00): "JustWorks",
    (0x01, 0x01): "NumericComparison",      # if SC, else JustWorks
    (0x01, 0x02): "PasskeyEntry (responder enters)",
    (0x01, 0x03): "JustWorks",
    (0x01, 0x04): "NumericComparison",      # if SC, else PasskeyEntry
    (0x02, 0x00): "PasskeyEntry (initiator enters)",
    (0x02, 0x01): "PasskeyEntry (initiator enters)",
    (0x02, 0x02): "PasskeyEntry (both enter)",
    (0x02, 0x03): "JustWorks",
    (0x02, 0x04): "PasskeyEntry (initiator enters)",
    (0x03, 0x00): "JustWorks",
    (0x03, 0x01): "JustWorks",
    (0x03, 0x02): "JustWorks",
    (0x03, 0x03): "JustWorks",
    (0x03, 0x04): "JustWorks",
    (0x04, 0x00): "PasskeyEntry (initiator enters)",
    (0x04, 0x01): "NumericComparison",      # if SC, else PasskeyEntry
    (0x04, 0x02): "PasskeyEntry (both enter)",
    (0x04, 0x03): "JustWorks",
    (0x04, 0x04): "NumericComparison",      # if SC, else PasskeyEntry
}


def decode_io_capability(value: int) -> str:
    """Decode SMP IO Capability byte."""
    return _IO_CAPABILITIES.get(value, f"Reserved (0x{value:02x})")


def decode_oob_data(value: int) -> str:
    """Decode SMP OOB Data Flag byte."""
    return _OOB_DATA.get(value, f"Reserved (0x{value:02x})")


def decode_auth_req(value: int) -> List[str]:
    """Decode SMP AuthReq byte into list of flag names."""
    flags = []
    # Bonding is bits 0-1
    bonding = value & 0x03
    if bonding == 0x01:
        flags.append("bonding")
    elif bonding == 0x00:
        flags.append("no-bonding")
    # Remaining flags
    for bit, name in _AUTH_REQ_BITS.items():
        if bit < 2:
            continue
        if value & (1 << bit):
            flags.append(name)
    return flags


def decode_key_dist(value: int) -> List[str]:
    """Decode SMP Key Distribution byte into list of key type names."""
    return [name for bit, name in sorted(_KEY_DIST_BITS.items()) if value & (1 << bit)]


def predict_pairing_method(
    initiator_io: int, responder_io: int, secure_connections: bool = False
) -> str:
    """Predict the pairing method from IO capabilities.

    Args:
        initiator_io: Initiator's IO capability (0x00-0x04).
        responder_io: Responder's IO capability (0x00-0x04).
        secure_connections: Whether Secure Connections (LE SC) is in use.

    Returns:
        Human-readable pairing method name.
    """
    method = _PAIRING_METHOD.get((initiator_io, responder_io), "Unknown")
    # NumericComparison only applies with SC; without SC it's JustWorks or PasskeyEntry
    if "NumericComparison" in method and not secure_connections:
        if initiator_io == 0x01 and responder_io == 0x01:
            return "JustWorks"
        return "PasskeyEntry"
    return method


def assess_security(
    io_cap: int, auth_req: int, secure_connections: bool = False
) -> Dict[str, any]:
    """Assess the security level of an SMP pairing configuration.

    Returns a dict with security assessment fields.
    """
    auth_flags = decode_auth_req(auth_req)
    mitm = "MITM" in auth_flags
    sc = secure_connections or "SC" in auth_flags
    bonding = "bonding" in auth_flags
    io_name = decode_io_capability(io_cap)

    # JustWorks with NoInputNoOutput is the weakest
    just_works = io_name == "NoInputNoOutput" or (not mitm)

    if sc and mitm and not just_works:
        level = "high"
        assessment = "Secure Connections with MITM protection"
    elif sc and just_works:
        level = "medium"
        assessment = "Secure Connections but no MITM protection (JustWorks)"
    elif mitm and not just_works:
        level = "medium"
        assessment = "Legacy pairing with MITM protection"
    else:
        level = "low"
        assessment = "JustWorks — no MITM protection, vulnerable to passive eavesdropping"

    return {
        "level": level,
        "assessment": assessment,
        "io_capability": io_name,
        "mitm_protection": mitm,
        "secure_connections": sc,
        "bonding": bonding,
        "auth_flags": auth_flags,
    }
