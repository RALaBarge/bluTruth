"""
blutruth.collectors.dbus_monitor — D-Bus BlueZ signal collector

Monitors all signals from org.bluez on the system bus:
- PropertiesChanged on all /org/bluez/* paths
- InterfacesAdded / InterfacesRemoved (device appear/disappear)
- Method calls and returns (when observable)

Uses dbus-next (pure Python, no C extensions, async-native).

FUTURE: Structured parsing for common interfaces (Adapter1, Device1,
        MediaTransport1) to extract device_addr, stage, etc. from
        the signal body rather than just capturing raw data.
FUTURE (Rust port): zbus crate with the same match rules.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, Dict, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event

# Device address extraction from D-Bus object paths
# /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF → AA:BB:CC:DD:EE:FF
import re
_DEV_PATH_RE = re.compile(r"/org/bluez/(hci\d+)/dev_([0-9A-Fa-f_]{17})")


def _path_to_addr(path: str) -> tuple:
    """Extract (adapter, device_addr) from a BlueZ object path."""
    m = _DEV_PATH_RE.search(path or "")
    if m:
        addr = m.group(2).replace("_", ":").upper()
        return m.group(1), addr
    # Adapter-only path
    adapter_m = re.search(r"/org/bluez/(hci\d+)", path or "")
    if adapter_m:
        return adapter_m.group(1), None
    return None, None


# A2DP codec byte → human-readable name (from BlueZ MediaTransport1.Codec)
_A2DP_CODECS: Dict[int, str] = {
    0x00: "SBC",
    0x01: "MP3",
    0x02: "AAC",
    0x03: "ATRAC",
    0xFF: "Vendor (aptX/LDAC/LC3/aptX-HD)",
}


def _decode_a2dp_codec(val: Any) -> Optional[str]:
    """Return codec name for a MediaTransport1.Codec byte value."""
    try:
        code = int(val)
        return _A2DP_CODECS.get(code, f"Unknown (0x{code:02X})")
    except (TypeError, ValueError):
        return None


def _classify_property_change(interface: str, changed: dict) -> tuple:
    """Return (severity, stage) based on which property changed."""
    iface = interface or ""

    if "Device1" in iface:
        if "Connected" in changed:
            val = changed["Connected"]
            # Connected: true → INFO, false → WARN (potential disconnect)
            if hasattr(val, "value"):
                val = val.value
            return ("INFO" if val else "WARN", "CONNECTION")
        if "ServicesResolved" in changed:
            return ("INFO", "HANDSHAKE")
        if "Paired" in changed:
            return ("INFO", "HANDSHAKE")
        if "RSSI" in changed:
            return ("DEBUG", "DISCOVERY")
        if "Trusted" in changed or "Blocked" in changed:
            return ("INFO", "CONNECTION")
        return ("INFO", None)

    if "Adapter1" in iface:
        if "Powered" in changed:
            return ("WARN", None)
        if "Discovering" in changed:
            return ("INFO", "DISCOVERY")
        return ("INFO", None)

    if "MediaTransport1" in iface:
        if "State" in changed:
            return ("INFO", "AUDIO")
        if "Codec" in changed:
            return ("INFO", "AUDIO")
        return ("INFO", "AUDIO")

    if "MediaPlayer1" in iface:
        return ("DEBUG", "AUDIO")

    return ("INFO", None)


def _format_changed_props(changed: dict) -> str:
    """Human-readable summary of changed properties."""
    parts = []
    for k, v in changed.items():
        # dbus-next wraps values in Variant objects
        val = v.value if hasattr(v, "value") else v
        parts.append(f"{k}: {val}")
    return ", ".join(parts[:5])  # cap at 5 to keep summary short


class DbusCollector(Collector):
    name = "dbus"
    description = "BlueZ D-Bus signal monitor"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._dbus_bus = None
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["DBUS"],
            "depends_on": [],
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
                summary="dbus-next not installed — pip install dbus-next",
                raw_json={"error": "import failed", "hint": "pip install dbus-next"},
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
                summary=f"Failed to connect to system D-Bus: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))
            return

        # Subscribe to all BlueZ signals
        match_rules = [
            "type='signal',sender='org.bluez'",
            "type='signal',interface='org.freedesktop.DBus.ObjectManager',"
            "arg0namespace='org.bluez'",
        ]

        for rule in match_rules:
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
                    summary=f"Failed to add match rule: {e}",
                    raw_json={"rule": rule, "error": str(e)},
                    source_version=self.source_version_tag,
                ))

        self._running = True

        await self.bus.publish(Event.new(
            source="DBUS",
            event_type="COLLECTOR_START",
            summary="D-Bus BlueZ collector started",
            raw_json={"match_rules": match_rules},
            source_version=self.source_version_tag,
        ))

        # Message handler
        def on_message(msg):
            if msg.message_type != MessageType.SIGNAL:
                return
            # Fire-and-forget publish
            asyncio.create_task(self._handle_signal(msg))

        self._dbus_bus.add_message_handler(on_message)

        # Keep running until cancelled
        try:
            while self._running:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass

    async def _handle_signal(self, msg) -> None:
        """Parse a D-Bus signal into a canonical event and publish."""
        path = msg.path or ""
        interface = msg.interface or ""
        member = msg.member or ""

        adapter, device_addr = _path_to_addr(path)

        # Determine event type and build summary
        if member == "PropertiesChanged" and msg.body:
            changed_iface = msg.body[0] if msg.body else ""
            changed_props = msg.body[1] if len(msg.body) > 1 else {}
            # Convert Variant objects to plain values for JSON serialization
            changed_plain = {}
            for k, v in changed_props.items():
                changed_plain[k] = v.value if hasattr(v, "value") else v

            severity, stage = _classify_property_change(changed_iface, changed_props)
            summary = f"{changed_iface}.PropertiesChanged: {_format_changed_props(changed_props)}"
            event_type = "DBUS_PROP"
            raw_json = {
                "path": path,
                "interface": changed_iface,
                "changed": _safe_serialize(changed_plain),
                "invalidated": list(msg.body[2]) if len(msg.body) > 2 else [],
            }
            # Decode A2DP codec byte for MediaTransport1
            if "MediaTransport1" in changed_iface and "Codec" in changed_plain:
                codec_name = _decode_a2dp_codec(changed_plain["Codec"])
                if codec_name:
                    raw_json["codec_name"] = codec_name
                    summary += f" [{codec_name}]"

        elif member == "InterfacesAdded" and msg.body:
            obj_path = msg.body[0] if msg.body else ""
            ifaces = msg.body[1] if len(msg.body) > 1 else {}
            iface_names = list(ifaces.keys()) if isinstance(ifaces, dict) else []
            severity = "INFO"
            stage = "CONNECTION" if "org.bluez.Device1" in iface_names else None
            summary = f"InterfacesAdded: {obj_path} [{', '.join(iface_names[:3])}]"
            event_type = "DBUS_SIG"
            raw_json = {
                "path": obj_path,
                "interfaces": iface_names,
            }
            # Extract device addr from the new object path
            _, new_addr = _path_to_addr(obj_path)
            if new_addr:
                device_addr = new_addr

        elif member == "InterfacesRemoved" and msg.body:
            obj_path = msg.body[0] if msg.body else ""
            ifaces = msg.body[1] if len(msg.body) > 1 else []
            iface_names = list(ifaces) if isinstance(ifaces, (list, tuple)) else []
            severity = "WARN"
            stage = "TEARDOWN" if "org.bluez.Device1" in iface_names else None
            summary = f"InterfacesRemoved: {obj_path} [{', '.join(iface_names[:3])}]"
            event_type = "DBUS_SIG"
            raw_json = {
                "path": obj_path,
                "interfaces": iface_names,
            }
            _, removed_addr = _path_to_addr(obj_path)
            if removed_addr:
                device_addr = removed_addr

        else:
            # Generic signal
            severity = "DEBUG"
            stage = None
            summary = f"{interface}.{member} on {path}"
            event_type = "DBUS_SIG"
            raw_json = {
                "path": path,
                "interface": interface,
                "member": member,
                "body": _safe_serialize(msg.body),
            }

        await self.bus.publish(Event.new(
            source="DBUS",
            severity=severity,
            stage=stage,
            event_type=event_type,
            adapter=adapter,
            device_addr=device_addr,
            summary=summary[:300],
            raw_json=raw_json,
            source_version=self.source_version_tag,
            parser_version=f"dbus-parser-{self.version}",
        ))

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


def _safe_serialize(obj: Any) -> Any:
    """Recursively convert D-Bus types to JSON-safe Python types."""
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
    if hasattr(obj, "value"):  # dbus-next Variant
        return _safe_serialize(obj.value)
    return str(obj)
