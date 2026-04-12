"""
blutruth.collectors.gatt — GATT service discovery collector

When a BLE device connects and resolves services (ServicesResolved=true),
this collector introspects all org.bluez.GattService1 / GattCharacteristic1
/ GattDescriptor1 objects under the device path and emits structured events
for each discovered service, characteristic, and descriptor.

Uses dbus-next to:
1. Watch for PropertiesChanged on Device1.ServicesResolved
2. Call ObjectManager.GetManagedObjects() to enumerate GATT tree
3. Optionally read characteristic values for well-known UUIDs (Battery, Device Info, etc.)

This is separate from DbusCollector — that captures raw D-Bus signals,
while this does active introspection of the GATT hierarchy.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from typing import Any, Dict, List, Optional, Set

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event

_DEV_PATH_RE = re.compile(r"/org/bluez/(hci\d+)/dev_([0-9A-Fa-f_]{17})")

# Well-known GATT service UUIDs (16-bit shorthand → name)
# Subset of Bluetooth SIG assigned numbers — enough to label the common ones.
# Full enrichment table will be added separately.
_KNOWN_SERVICES: Dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Information",
    "180f": "Battery Service",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "1806": "Reference Time Update",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180d": "Heart Rate",
    "180e": "Phone Alert Status",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181a": "Environmental Sensing",
    "181c": "User Data",
    "1820": "Internet Protocol Support",
    "1844": "Volume Control",
    "184e": "Audio Stream Control",
    "febe": "Bose",
    "fe2c": "Google Fast Pair",
    "fd6f": "Apple Exposure Notification",
}

# Well-known characteristic UUIDs
_KNOWN_CHARS: Dict[str, str] = {
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a19": "Battery Level",
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a50": "PnP ID",
}

# Characteristics safe to read (string/byte values, no side effects)
_SAFE_READ_CHARS: Set[str] = {
    "2a00", "2a01", "2a19", "2a24", "2a25", "2a26", "2a27", "2a28", "2a29",
}


def _path_to_addr(path: str) -> tuple:
    m = _DEV_PATH_RE.search(path or "")
    if m:
        addr = m.group(2).replace("_", ":").upper()
        return m.group(1), addr
    return None, None


def _uuid_short(uuid: str) -> Optional[str]:
    """Extract 16-bit short UUID from full 128-bit BlueZ UUID if it's a standard one."""
    if not uuid:
        return None
    uuid = uuid.lower()
    # Already short (4 hex digits)
    if len(uuid) == 4:
        return uuid
    # Standard BT base UUID: 0000xxxx-0000-1000-8000-00805f9b34fb
    if uuid.endswith("-0000-1000-8000-00805f9b34fb") and uuid.startswith("0000"):
        return uuid[4:8]
    return None


def _service_name(uuid: str) -> str:
    short = _uuid_short(uuid)
    if short and short in _KNOWN_SERVICES:
        return _KNOWN_SERVICES[short]
    return f"Unknown ({uuid[:8]}...)" if len(uuid) > 8 else f"Unknown ({uuid})"


def _char_name(uuid: str) -> str:
    short = _uuid_short(uuid)
    if short and short in _KNOWN_CHARS:
        return _KNOWN_CHARS[short]
    return f"0x{short}" if short else uuid[:8]


def _safe_serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (list, tuple)):
        return [_safe_serialize(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    if hasattr(obj, "value"):
        return _safe_serialize(obj.value)
    return str(obj)


class GattCollector(Collector):
    """Discovers GATT services, characteristics, and descriptors on connected BLE devices."""

    name = "gatt"
    description = "GATT service discovery via D-Bus introspection"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._dbus_bus = None
        self._task: Optional[asyncio.Task] = None
        # Track devices we've already discovered to avoid duplicate scans
        self._discovered: Set[str] = set()

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["DBUS"],
            "depends_on": ["dbus"],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        try:
            from dbus_next.aio import MessageBus
            from dbus_next.constants import BusType
        except ImportError:
            await self.bus.publish(Event.new(
                source="DBUS",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary="gatt: dbus-next not installed — pip install dbus-next",
                raw_json={"error": "import failed"},
                source_version=self.source_version_tag,
            ))
            return

        self._task = asyncio.create_task(self._run(MessageBus, BusType))

    async def _run(self, MessageBus, BusType) -> None:
        from dbus_next import Message, MessageType

        try:
            self._dbus_bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        except Exception as e:
            await self.bus.publish(Event.new(
                source="DBUS",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary=f"gatt: D-Bus connect failed: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True

        # Watch for ServicesResolved changes
        rule = (
            "type='signal',"
            "sender='org.bluez',"
            "interface='org.freedesktop.DBus.Properties',"
            "member='PropertiesChanged',"
            "arg0='org.bluez.Device1'"
        )
        try:
            await self._dbus_bus.call(Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[rule],
            ))
        except Exception as e:
            await self.bus.publish(Event.new(
                source="DBUS",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary=f"gatt: AddMatch failed: {e}",
                raw_json={"rule": rule, "error": str(e)},
                source_version=self.source_version_tag,
            ))

        await self.bus.publish(Event.new(
            source="DBUS",
            event_type="COLLECTOR_START",
            summary="GATT service discovery collector started",
            raw_json={"match_rule": rule},
            source_version=self.source_version_tag,
        ))

        # Also scan any already-connected devices on startup
        asyncio.create_task(self._scan_existing_devices())

        # Message handler
        def on_message(msg):
            if msg.message_type != MessageType.SIGNAL:
                return
            if (msg.member == "PropertiesChanged"
                    and msg.body
                    and msg.body[0] == "org.bluez.Device1"):
                changed = msg.body[1] if len(msg.body) > 1 else {}
                sr = changed.get("ServicesResolved")
                if sr is not None:
                    val = sr.value if hasattr(sr, "value") else sr
                    if val:
                        asyncio.create_task(self._discover_device(msg.path))

        self._dbus_bus.add_message_handler(on_message)

        try:
            while self._running:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass

    async def _scan_existing_devices(self) -> None:
        """On startup, discover GATT on any already-connected device with resolved services."""
        from dbus_next import Message

        try:
            reply = await self._dbus_bus.call(Message(
                destination="org.bluez",
                path="/",
                interface="org.freedesktop.DBus.ObjectManager",
                member="GetManagedObjects",
            ))
        except Exception:
            return

        if not reply or not reply.body:
            return

        objects = reply.body[0]
        for path, ifaces in objects.items():
            dev_iface = ifaces.get("org.bluez.Device1")
            if not dev_iface:
                continue
            sr = dev_iface.get("ServicesResolved")
            if sr is not None:
                val = sr.value if hasattr(sr, "value") else sr
                if val:
                    asyncio.create_task(self._discover_device(path))

    async def _discover_device(self, device_path: str) -> None:
        """Enumerate GATT services/characteristics/descriptors for a device."""
        adapter, device_addr = _path_to_addr(device_path)
        if not device_addr:
            return

        # Deduplicate — don't re-scan the same device in the same session
        if device_addr in self._discovered:
            return
        self._discovered.add(device_addr)

        from dbus_next import Message

        # Get all managed objects and filter to children of this device path
        try:
            reply = await self._dbus_bus.call(Message(
                destination="org.bluez",
                path="/",
                interface="org.freedesktop.DBus.ObjectManager",
                member="GetManagedObjects",
            ))
        except Exception as e:
            await self.bus.publish(Event.new(
                source="DBUS",
                severity="WARN",
                event_type="GATT_ERROR",
                summary=f"GATT discovery failed for {device_addr}: {e}",
                raw_json={"device_addr": device_addr, "error": str(e)},
                adapter=adapter,
                device_addr=device_addr,
                source_version=self.source_version_tag,
            ))
            return

        if not reply or not reply.body:
            return

        objects = reply.body[0]
        prefix = device_path + "/"

        # Collect the GATT tree
        services: List[Dict[str, Any]] = []
        chars: List[Dict[str, Any]] = []
        descriptors: List[Dict[str, Any]] = []

        for obj_path, ifaces in objects.items():
            if not obj_path.startswith(prefix):
                continue

            if "org.bluez.GattService1" in ifaces:
                props = ifaces["org.bluez.GattService1"]
                uuid = _safe_serialize(props.get("UUID", ""))
                primary = _safe_serialize(props.get("Primary", True))
                services.append({
                    "path": obj_path,
                    "uuid": uuid,
                    "name": _service_name(uuid),
                    "primary": primary,
                })

            if "org.bluez.GattCharacteristic1" in ifaces:
                props = ifaces["org.bluez.GattCharacteristic1"]
                uuid = _safe_serialize(props.get("UUID", ""))
                flags = _safe_serialize(props.get("Flags", []))
                svc_path = _safe_serialize(props.get("Service", ""))
                chars.append({
                    "path": obj_path,
                    "uuid": uuid,
                    "name": _char_name(uuid),
                    "flags": flags,
                    "service": svc_path,
                })

            if "org.bluez.GattDescriptor1" in ifaces:
                props = ifaces["org.bluez.GattDescriptor1"]
                uuid = _safe_serialize(props.get("UUID", ""))
                char_path = _safe_serialize(props.get("Characteristic", ""))
                descriptors.append({
                    "path": obj_path,
                    "uuid": uuid,
                    "characteristic": char_path,
                })

        # Get device name if available
        device_name = None
        dev_iface = objects.get(device_path, {}).get("org.bluez.Device1", {})
        if dev_iface:
            device_name = _safe_serialize(dev_iface.get("Name"))

        # Emit summary event for the full GATT tree
        svc_names = [s["name"] for s in services]
        summary_text = (
            f"GATT discovery: {device_addr}"
            f"{(' (' + device_name + ')') if device_name else ''}"
            f" — {len(services)} services, {len(chars)} chars, {len(descriptors)} descriptors"
            f" [{', '.join(svc_names[:5])}"
            f"{'...' if len(svc_names) > 5 else ''}]"
        )

        await self.bus.publish(Event.new(
            source="DBUS",
            severity="INFO",
            stage="HANDSHAKE",
            event_type="GATT_DISCOVERY",
            adapter=adapter,
            device_addr=device_addr,
            device_name=device_name,
            summary=summary_text[:300],
            raw_json={
                "services": services,
                "characteristics": chars,
                "descriptors": descriptors,
                "service_count": len(services),
                "characteristic_count": len(chars),
                "descriptor_count": len(descriptors),
            },
            source_version=self.source_version_tag,
        ))

        # Emit individual service events for correlation
        for svc in services:
            await self.bus.publish(Event.new(
                source="DBUS",
                severity="INFO",
                stage="HANDSHAKE",
                event_type="GATT_SERVICE",
                adapter=adapter,
                device_addr=device_addr,
                device_name=device_name,
                summary=f"GATT service: {svc['name']} (UUID {svc['uuid']}) primary={svc['primary']}",
                raw_json=svc,
                source_version=self.source_version_tag,
            ))

        # Try reading safe characteristics (battery level, device info strings)
        read_enabled = self.config.get(
            "collectors", "gatt", "read_characteristics", default=True
        )
        if read_enabled:
            await self._read_safe_characteristics(
                chars, adapter, device_addr, device_name
            )

    async def _read_safe_characteristics(
        self,
        chars: List[Dict[str, Any]],
        adapter: Optional[str],
        device_addr: Optional[str],
        device_name: Optional[str],
    ) -> None:
        """Read well-known characteristic values that are safe to access."""
        from dbus_next import Message

        for char in chars:
            short = _uuid_short(char["uuid"])
            if not short or short not in _SAFE_READ_CHARS:
                continue
            if "read" not in [f.lower() for f in (char.get("flags") or [])]:
                continue

            obj_path = char["path"]
            try:
                reply = await self._dbus_bus.call(Message(
                    destination="org.bluez",
                    path=obj_path,
                    interface="org.bluez.GattCharacteristic1",
                    member="ReadValue",
                    signature="a{sv}",
                    body=[{}],
                ))
                if reply and reply.body:
                    raw_bytes = bytes(reply.body[0])
                    # Try UTF-8 decode for string characteristics
                    try:
                        value = raw_bytes.decode("utf-8").rstrip("\x00")
                    except UnicodeDecodeError:
                        value = raw_bytes.hex()

                    await self.bus.publish(Event.new(
                        source="DBUS",
                        severity="INFO",
                        stage="HANDSHAKE",
                        event_type="GATT_READ",
                        adapter=adapter,
                        device_addr=device_addr,
                        device_name=device_name,
                        summary=f"GATT read {_char_name(char['uuid'])}: {value[:100]}",
                        raw_json={
                            "uuid": char["uuid"],
                            "name": _char_name(char["uuid"]),
                            "value": value,
                            "raw_hex": raw_bytes.hex(),
                            "path": obj_path,
                        },
                        source_version=self.source_version_tag,
                    ))
            except Exception:
                # Characteristic may not be readable right now — skip silently
                continue

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._dbus_bus:
            with contextlib.suppress(Exception):
                self._dbus_bus.disconnect()
            self._dbus_bus = None
        self._discovered.clear()
