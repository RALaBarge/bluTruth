"""
blutruth.enrichment.usb_ids — USB VID:PID to known Bluetooth adapter info

Maps USB Vendor ID:Product ID pairs to adapter information including
chipset, known issues, and recommended workarounds.

Focused on BT adapters commonly encountered in diagnostics. Not a general
USB ID database — only covers Bluetooth-relevant hardware.

Usage:
    from blutruth.enrichment.usb_ids import lookup_adapter, known_issues
    info = lookup_adapter(0x8087, 0x0029)
    # {"vendor": "Intel", "name": "AX200/AX201", "chipset": "Intel AX200", ...}

    issues = known_issues(0x0a12, 0x0001)
    # [{"issue": "CSR clone detected", "severity": "ERROR", ...}]
"""
from __future__ import annotations

from typing import Dict, List, Optional

# (vendor_id, product_id) → adapter info
# Sources: linux-firmware, kernel driver docs, community reports
_ADAPTERS: Dict[tuple, Dict[str, str]] = {
    # ---- Intel ----
    (0x8087, 0x0025): {
        "vendor": "Intel",
        "name": "Wireless 9260/9560",
        "chipset": "Intel 9260",
        "driver": "btusb (btintel)",
        "bt_version": "5.1",
        "notes": "Combo WiFi+BT. Firmware in linux-firmware.",
    },
    (0x8087, 0x0026): {
        "vendor": "Intel",
        "name": "AX201",
        "chipset": "Intel AX201",
        "driver": "btusb (btintel)",
        "bt_version": "5.2",
        "notes": "Combo WiFi+BT. LE Audio capable with fw update.",
    },
    (0x8087, 0x0029): {
        "vendor": "Intel",
        "name": "AX200",
        "chipset": "Intel AX200",
        "driver": "btusb (btintel)",
        "bt_version": "5.0",
        "notes": "Combo WiFi+BT. Very common in laptops 2019+.",
    },
    (0x8087, 0x0032): {
        "vendor": "Intel",
        "name": "AX210/AX211",
        "chipset": "Intel AX210",
        "driver": "btusb (btintel)",
        "bt_version": "5.3",
        "notes": "Wi-Fi 6E + BT 5.3. LE Audio capable.",
    },
    (0x8087, 0x0033): {
        "vendor": "Intel",
        "name": "BE200",
        "chipset": "Intel BE200",
        "driver": "btusb (btintel)",
        "bt_version": "5.4",
        "notes": "Wi-Fi 7 + BT 5.4.",
    },
    (0x8087, 0x07dc): {
        "vendor": "Intel",
        "name": "Wireless 8265",
        "chipset": "Intel 8265",
        "driver": "btusb (btintel)",
        "bt_version": "4.2",
        "notes": "Combo WiFi+BT. Common in laptops 2017-2019.",
    },
    (0x8087, 0x0a2b): {
        "vendor": "Intel",
        "name": "Wireless 7265",
        "chipset": "Intel 7265",
        "driver": "btusb (btintel)",
        "bt_version": "4.2",
        "notes": "Combo WiFi+BT.",
    },
    # ---- Realtek ----
    (0x0bda, 0xb00a): {
        "vendor": "Realtek",
        "name": "RTL8852AE",
        "chipset": "Realtek 8852AE",
        "driver": "btusb (btrtl)",
        "bt_version": "5.2",
        "notes": "Combo WiFi 6 + BT 5.2.",
    },
    (0x0bda, 0xb852): {
        "vendor": "Realtek",
        "name": "RTL8852BE",
        "chipset": "Realtek 8852BE",
        "driver": "btusb (btrtl)",
        "bt_version": "5.2",
        "notes": "Budget WiFi 6 + BT combo.",
    },
    (0x0bda, 0xb00c): {
        "vendor": "Realtek",
        "name": "RTL8852CE",
        "chipset": "Realtek 8852CE",
        "driver": "btusb (btrtl)",
        "bt_version": "5.3",
        "notes": "WiFi 6E + BT 5.3 combo.",
    },
    (0x0bda, 0x8771): {
        "vendor": "Realtek",
        "name": "RTL8761BUV",
        "chipset": "Realtek 8761B",
        "driver": "btusb (btrtl)",
        "bt_version": "5.0",
        "notes": "Common USB dongle chip. Needs firmware from linux-firmware.",
    },
    (0x0bda, 0xc123): {
        "vendor": "Realtek",
        "name": "RTL8821CU",
        "chipset": "Realtek 8821CU",
        "driver": "btusb (btrtl)",
        "bt_version": "4.2",
        "notes": "Budget USB combo adapter.",
    },
    # ---- Qualcomm / Atheros ----
    (0x0cf3, 0x3004): {
        "vendor": "Qualcomm Atheros",
        "name": "QCA61x4",
        "chipset": "QCA6174",
        "driver": "btusb (btath3k/btqca)",
        "bt_version": "4.2",
        "notes": "Common in Dell/HP laptops.",
    },
    (0x0cf3, 0xe300): {
        "vendor": "Qualcomm Atheros",
        "name": "QCA6174A",
        "chipset": "QCA6174A",
        "driver": "btusb (btqca)",
        "bt_version": "4.2",
        "notes": "Widespread combo chip.",
    },
    # ---- Broadcom ----
    (0x0a5c, 0x6412): {
        "vendor": "Broadcom",
        "name": "BCM20702A0",
        "chipset": "BCM20702",
        "driver": "btusb (btbcm)",
        "bt_version": "4.0",
        "notes": "Very common standalone USB adapter chip.",
    },
    (0x0a5c, 0x21e8): {
        "vendor": "Broadcom",
        "name": "BCM20702A0 (Lenovo)",
        "chipset": "BCM20702",
        "driver": "btusb (btbcm)",
        "bt_version": "4.0",
        "notes": "Lenovo ThinkPad variant.",
    },
    # ---- MediaTek ----
    (0x0e8d, 0x7961): {
        "vendor": "MediaTek",
        "name": "MT7921",
        "chipset": "MediaTek MT7921",
        "driver": "btusb (btmtk)",
        "bt_version": "5.2",
        "notes": "WiFi 6 + BT 5.2 combo. Common in 2022+ budget laptops.",
    },
    (0x0e8d, 0x7922): {
        "vendor": "MediaTek",
        "name": "MT7922",
        "chipset": "MediaTek MT7922",
        "driver": "btusb (btmtk)",
        "bt_version": "5.3",
        "notes": "WiFi 6E + BT 5.3 combo.",
    },
    # ---- CSR (Cambridge Silicon Radio) ----
    (0x0a12, 0x0001): {
        "vendor": "CSR",
        "name": "CSR8510",
        "chipset": "CSR8510 A10",
        "driver": "btusb",
        "bt_version": "4.0",
        "notes": "Extremely common cheap USB dongle. Many clones exist.",
    },
    # ---- TP-Link branded ----
    (0x2357, 0x0604): {
        "vendor": "TP-Link",
        "name": "UB500",
        "chipset": "Realtek 8761B",
        "driver": "btusb (btrtl)",
        "bt_version": "5.0",
        "notes": "Popular standalone BT 5.0 USB dongle.",
    },
    # ---- ASUS branded ----
    (0x0b05, 0x190e): {
        "vendor": "ASUS",
        "name": "USB-BT500",
        "chipset": "Realtek 8761B",
        "driver": "btusb (btrtl)",
        "bt_version": "5.0",
        "notes": "Popular standalone BT 5.0 USB dongle.",
    },
}

# Known issues by (vendor_id, product_id) or vendor_id alone
_KNOWN_ISSUES: List[Dict] = [
    {
        "match": {"vid": 0x0a12, "pid": 0x0001},
        "issue": "CSR8510 clone detection",
        "severity": "WARN",
        "description": (
            "VID:PID 0A12:0001 is shared by genuine CSR8510 and hundreds of "
            "counterfeit/clone chips. Clones often have broken firmware that "
            "causes: phantom disconnects, failed SCO, limited EDR throughput. "
            "Check bcdDevice in lsusb -v — genuine CSR8510 is bcdDevice 88.00."
        ),
        "action": "Run: lsusb -v -d 0a12:0001 | grep bcdDevice. If not 88.00, likely a clone.",
    },
    {
        "match": {"vid": 0x0a12, "pid": 0x0001},
        "issue": "CSR8510 BT 4.0 only — no LE Privacy, no SC",
        "severity": "INFO",
        "description": (
            "CSR8510 is BT 4.0 only. Does not support LE Privacy (RPA), "
            "Secure Connections, or Extended Advertising. Many modern BLE "
            "devices require these features."
        ),
        "action": "Upgrade to a BT 5.0+ adapter for full BLE compatibility.",
    },
    {
        "match": {"vid": 0x0bda},
        "issue": "Realtek firmware dependency",
        "severity": "INFO",
        "description": (
            "Realtek BT adapters require firmware blobs from linux-firmware. "
            "Missing firmware causes the adapter to enumerate but fail to "
            "initialize — btusb loads but btmgmt shows no adapter."
        ),
        "action": "Install linux-firmware package and check dmesg for firmware load errors.",
    },
    {
        "match": {"vid": 0x8087},
        "issue": "Intel firmware dependency",
        "severity": "INFO",
        "description": (
            "Intel BT adapters require firmware from linux-firmware (ibt-* files). "
            "Missing firmware results in 'Intel Read Version failed' in dmesg."
        ),
        "action": "Install linux-firmware. Check: dmesg | grep -i 'bluetooth.*firmware'",
    },
    {
        "match": {"vid": 0x0e8d},
        "issue": "MediaTek early driver issues",
        "severity": "INFO",
        "description": (
            "MediaTek BT support was added in kernel 5.17+. Earlier kernels "
            "may not recognize the device or have incomplete support. "
            "SCO (HFP voice) may require kernel 6.1+."
        ),
        "action": "Use kernel 6.1+ for full MediaTek BT support. Check: uname -r",
    },
]


def lookup_adapter(vid: int, pid: int) -> Optional[Dict[str, str]]:
    """Look up a USB BT adapter by vendor:product ID.

    Args:
        vid: USB Vendor ID.
        pid: USB Product ID.

    Returns:
        Dict with adapter info, or None if not recognized.
    """
    return _ADAPTERS.get((vid, pid))


def known_issues(vid: int, pid: int) -> List[Dict]:
    """Get known issues for a USB adapter.

    Matches on exact VID:PID or vendor-wide issues.

    Returns:
        List of issue dicts with 'issue', 'severity', 'description', 'action'.
    """
    results = []
    for entry in _KNOWN_ISSUES:
        match = entry["match"]
        if match.get("pid") is not None:
            if vid == match["vid"] and pid == match["pid"]:
                results.append({k: v for k, v in entry.items() if k != "match"})
        elif vid == match["vid"]:
            results.append({k: v for k, v in entry.items() if k != "match"})
    return results


def adapter_summary(vid: int, pid: int) -> Optional[str]:
    """One-line summary for log enrichment."""
    info = lookup_adapter(vid, pid)
    if not info:
        return None
    return f"{info['vendor']} {info['name']} ({info['chipset']}, BT {info['bt_version']})"
