"""
blutruth.enrichment.gatt_uuids — GATT UUID→name mapping

Maps 16-bit Bluetooth SIG assigned UUIDs to human-readable service,
characteristic, and descriptor names.

Reference: Bluetooth SIG Assigned Numbers
  https://www.bluetooth.com/specifications/assigned-numbers/

Usage:
    from blutruth.enrichment.gatt_uuids import (
        service_name, characteristic_name, descriptor_name, uuid_name
    )
    service_name("180f")           # "Battery Service"
    characteristic_name("2a19")    # "Battery Level"
    uuid_name("180f")              # ("service", "Battery Service")
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

# ============================================================================
# GATT Services (0x1800 - 0x18FF + vendor ranges)
# ============================================================================
_SERVICES: Dict[str, str] = {
    # Generic Access Profile
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    # Health & Fitness
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "1806": "Reference Time Update",
    "1807": "Next DST Change",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180e": "Phone Alert Status",
    "180f": "Battery Service",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181a": "Environmental Sensing",
    "181b": "Body Composition",
    "181c": "User Data",
    "181d": "Weight Scale",
    "181e": "Bond Management",
    "181f": "Continuous Glucose Monitoring",
    "1820": "Internet Protocol Support",
    "1821": "Indoor Positioning",
    "1822": "Pulse Oximeter",
    "1823": "HTTP Proxy",
    "1824": "Transport Discovery",
    "1825": "Object Transfer",
    "1826": "Fitness Machine",
    "1827": "Mesh Provisioning",
    "1828": "Mesh Proxy",
    "1829": "Reconnection Configuration",
    # Audio (LE Audio / BAP / CAS)
    "1843": "Audio Input Control",
    "1844": "Volume Control",
    "1845": "Volume Offset Control",
    "1846": "Coordinated Set Identification",
    "1848": "Media Control",
    "1849": "Generic Media Control",
    "184a": "Constant Tone Extension",
    "184b": "Telephone Bearer",
    "184c": "Generic Telephone Bearer",
    "184d": "Microphone Control",
    "184e": "Audio Stream Control",
    "184f": "Broadcast Audio Scan",
    "1850": "Published Audio Capabilities",
    "1851": "Basic Audio Announcement",
    "1852": "Broadcast Audio Announcement",
    "1853": "Common Audio",
    "1854": "Hearing Access",
    "1855": "TMAS",  # Telephony and Media Audio
    "1856": "Public Broadcast Announcement",
    # Vendor-specific (common ones)
    "febe": "Bose",
    "fe2c": "Google Fast Pair",
    "fd6f": "Apple Exposure Notification",
    "fea0": "Google",
    "fe9f": "Google",
    "fed4": "Apple Notification Center",
    "fd43": "Apple",
    "fd44": "Apple",
    "fc7e": "Apple AirPods",
    "fee7": "Tencent",
    "fd5a": "Samsung",
    "fef3": "Google (Eddystone)",
    "feaa": "Google (Eddystone)",
    "fd08": "Bose",
    "fe07": "Xiaomi",
    "fd2d": "Xiaomi",
    "fee0": "Anhui Huami (Amazfit)",
    "fecd": "Fitbit",
    "fece": "Fitbit",
    "fddf": "Harman (JBL/AKG/Harman Kardon)",
    "fdb8": "LG Electronics",
    "fd82": "Sony",
}

# ============================================================================
# GATT Characteristics (0x2A00 - 0x2BFF)
# ============================================================================
_CHARACTERISTICS: Dict[str, str] = {
    # GAP
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a02": "Peripheral Privacy Flag",
    "2a03": "Reconnection Address",
    "2a04": "Peripheral Preferred Connection Parameters",
    # GATT
    "2a05": "Service Changed",
    "2a06": "Alert Level",
    # Device Information
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a2a": "IEEE 11073-20601 Regulatory Certification",
    "2a50": "PnP ID",
    # Battery
    "2a19": "Battery Level",
    "2a1a": "Battery Power State",
    "2a1b": "Battery Level State",
    # Heart Rate
    "2a37": "Heart Rate Measurement",
    "2a38": "Body Sensor Location",
    "2a39": "Heart Rate Control Point",
    # Blood Pressure
    "2a35": "Blood Pressure Measurement",
    "2a36": "Intermediate Cuff Pressure",
    "2a49": "Blood Pressure Feature",
    # Glucose
    "2a18": "Glucose Measurement",
    "2a34": "Glucose Measurement Context",
    "2a51": "Glucose Feature",
    "2a52": "Record Access Control Point",
    # Health Thermometer
    "2a1c": "Temperature Measurement",
    "2a1d": "Temperature Type",
    "2a1e": "Intermediate Temperature",
    "2a21": "Measurement Interval",
    # Tx Power
    "2a07": "Tx Power Level",
    # Current Time
    "2a2b": "Current Time",
    "2a0f": "Local Time Information",
    "2a14": "Reference Time Information",
    # HID
    "2a4a": "HID Information",
    "2a4b": "Report Map",
    "2a4c": "HID Control Point",
    "2a4d": "Report",
    "2a4e": "Protocol Mode",
    # Scan Parameters
    "2a4f": "Scan Interval Window",
    "2a31": "Scan Refresh",
    # Running Speed / Cycling
    "2a53": "RSC Measurement",
    "2a54": "RSC Feature",
    "2a5b": "CSC Measurement",
    "2a5c": "CSC Feature",
    "2a5d": "Sensor Location",
    # Cycling Power
    "2a63": "Cycling Power Measurement",
    "2a64": "Cycling Power Vector",
    "2a65": "Cycling Power Feature",
    "2a66": "Cycling Power Control Point",
    # Location
    "2a67": "Location and Speed",
    "2a68": "Navigation",
    "2a6a": "LN Feature",
    "2a6b": "LN Control Point",
    # Environmental Sensing
    "2a6c": "Elevation",
    "2a6d": "Pressure",
    "2a6e": "Temperature",
    "2a6f": "Humidity",
    "2a70": "True Wind Speed",
    "2a71": "True Wind Direction",
    "2a72": "Apparent Wind Speed",
    "2a73": "Apparent Wind Direction",
    "2a76": "UV Index",
    "2a77": "Irradiance",
    "2a78": "Rainfall",
    "2a79": "Wind Chill",
    # Weight Scale
    "2a9d": "Weight Measurement",
    "2a9e": "Weight Scale Feature",
    # Fitness Machine
    "2acc": "Fitness Machine Feature",
    "2acd": "Treadmill Data",
    "2ace": "Cross Trainer Data",
    "2acf": "Step Climber Data",
    "2ad0": "Stair Climber Data",
    "2ad1": "Rower Data",
    "2ad2": "Indoor Bike Data",
    "2ad3": "Training Status",
    # Audio
    "2bc3": "Media Player Name",
    "2bc4": "Media Player Icon Object ID",
    "2bc5": "Media Player Icon URL",
    "2bc7": "Track Title",
    "2bca": "Track Position",
    "2bcc": "Media State",
    # Connection parameters
    "2a08": "Date Time",
    "2a09": "Day of Week",
    "2a0a": "Day Date Time",
    "2a0c": "Exact Time 256",
}

# ============================================================================
# GATT Descriptors (0x2900 - 0x29FF)
# ============================================================================
_DESCRIPTORS: Dict[str, str] = {
    "2900": "Characteristic Extended Properties",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration",
    "2903": "Server Characteristic Configuration",
    "2904": "Characteristic Presentation Format",
    "2905": "Characteristic Aggregate Format",
    "2906": "Valid Range",
    "2907": "External Report Reference",
    "2908": "Report Reference",
    "290b": "Environmental Sensing Configuration",
    "290c": "Environmental Sensing Measurement",
    "290d": "Environmental Sensing Trigger Setting",
}


def _uuid_to_short(uuid: str) -> Optional[str]:
    """Extract 16-bit short UUID from full 128-bit if standard BT base."""
    if not uuid:
        return None
    uuid = uuid.lower().strip()
    if len(uuid) == 4:
        return uuid
    if uuid.endswith("-0000-1000-8000-00805f9b34fb") and uuid.startswith("0000"):
        return uuid[4:8]
    return None


def service_name(uuid: str) -> Optional[str]:
    """Look up a GATT service UUID → human-readable name."""
    short = _uuid_to_short(uuid) or uuid.lower()
    return _SERVICES.get(short)


def characteristic_name(uuid: str) -> Optional[str]:
    """Look up a GATT characteristic UUID → human-readable name."""
    short = _uuid_to_short(uuid) or uuid.lower()
    return _CHARACTERISTICS.get(short)


def descriptor_name(uuid: str) -> Optional[str]:
    """Look up a GATT descriptor UUID → human-readable name."""
    short = _uuid_to_short(uuid) or uuid.lower()
    return _DESCRIPTORS.get(short)


def uuid_name(uuid: str) -> Optional[Tuple[str, str]]:
    """Look up any UUID and return (type, name) or None.

    Returns:
        Tuple of (type, name) where type is "service", "characteristic",
        or "descriptor". None if UUID is not recognized.
    """
    short = _uuid_to_short(uuid) or uuid.lower()
    if short in _SERVICES:
        return ("service", _SERVICES[short])
    if short in _CHARACTERISTICS:
        return ("characteristic", _CHARACTERISTICS[short])
    if short in _DESCRIPTORS:
        return ("descriptor", _DESCRIPTORS[short])
    return None


def is_vendor_uuid(uuid: str) -> bool:
    """Check if a UUID is a vendor-specific (non-SIG) UUID."""
    short = _uuid_to_short(uuid)
    if short:
        # Vendor range: 0xFD00-0xFFFF for 16-bit
        try:
            val = int(short, 16)
            return val >= 0xFD00
        except ValueError:
            pass
    # 128-bit UUID not on BT base → vendor
    uuid = uuid.lower().strip()
    if len(uuid) == 36 and not uuid.endswith("-0000-1000-8000-00805f9b34fb"):
        return True
    return False
