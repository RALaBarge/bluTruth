"""
blutruth.collectors.battery — GATT Battery Service monitor

Polls org.bluez.Battery1.Percentage via D-Bus for each currently-connected
Classic BT / BLE device. Battery1 is BlueZ's proxy for the standard GATT
Battery Service (UUID 0x180F). Only devices that implement this GATT service
will have a Battery1 interface — most modern headphones, keyboards, mice, and
phones support it, but some devices don't.

Direct D-Bus approach (not bluetoothctl subprocess):
  org.bluez / /org/bluez/hciN/dev_AA_BB_CC_DD_EE_FF
  Interface: org.bluez.Battery1
  Property:  Percentage (byte, 0–100)

Two collection modes:
  1. Polled: polls Battery1.Percentage every poll_interval_s (default 60s)
     for all devices in _connected_devices. Good for devices that don't push updates.
  2. Reactive: watches PropertiesChanged on org.bluez.Battery1 and emits
     immediately when the device sends a battery update notification.

Both modes share the same connected-device tracking logic as L2pingCollector:
subscribes to the event bus and watches DBUS_PROP Connected property changes.

Devices that don't support Battery1 are silently skipped (no WARN spam) unless
debug logging is enabled.

Config:
  collectors:
    battery:
      enabled: true
      poll_interval_s: 60    # seconds between polls
      low_battery_warn: 20   # emit WARN when battery falls below this %
      low_battery_error: 10  # emit ERROR when battery falls below this %
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, Dict, Optional, Set

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


class BatteryCollector(Collector):
    name = "battery"
    description = "GATT Battery Service monitor via org.bluez.Battery1"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None
        self._watcher_task: Optional[asyncio.Task] = None
        self._battery_watcher_task: Optional[asyncio.Task] = None
        self._connected_devices: Set[str] = set()
        self._queue: Optional[asyncio.Queue] = None
        # Cache last known values to suppress repeated identical events
        self._last_pct: Dict[str, int] = {}

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["BATTERY"],
            "depends_on": ["dbus"],
        }

    def enabled(self) -> bool:
        return bool(self.config.get("collectors", "battery", "enabled", default=True))

    async def start(self) -> None:
        if not self.enabled():
            return

        # Check that dbus-next is available
        try:
            import dbus_next  # noqa: F401
        except ImportError:
            await self.bus.publish(Event.new(
                source="SYSFS",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="battery collector requires dbus-next: pip install dbus-next",
                raw_json={"error": "dbus-next not installed"},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._queue = await self.bus.subscribe(max_queue=2000)
        self._watcher_task = asyncio.create_task(self._watch_connections())
        self._battery_watcher_task = asyncio.create_task(self._watch_battery_props())
        self._task = asyncio.create_task(self._poll_loop())

        await self.bus.publish(Event.new(
            source="SYSFS",
            event_type="COLLECTOR_START",
            summary="Battery level collector started",
            raw_json={
                "poll_interval_s": self._cfg("poll_interval_s", 60),
                "low_battery_warn": self._cfg("low_battery_warn", 20),
                "low_battery_error": self._cfg("low_battery_error", 10),
            },
            source_version=self.source_version_tag,
        ))

    async def stop(self) -> None:
        self._running = False
        for task in (self._task, self._watcher_task, self._battery_watcher_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._task = None
        self._watcher_task = None
        self._battery_watcher_task = None
        if self._queue:
            await self.bus.unsubscribe(self._queue)
            self._queue = None

    def _cfg(self, key: str, default: Any) -> Any:
        return self.config.get("collectors", "battery", key, default=default)

    async def _watch_connections(self) -> None:
        """Track connected devices by watching D-Bus Connected property changes."""
        assert self._queue
        while self._running:
            try:
                ev = await asyncio.wait_for(self._queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            if ev.source != "DBUS" or ev.event_type != "DBUS_PROP":
                continue
            if not ev.device_addr:
                continue

            raw = ev.raw_json or {}
            changed = raw.get("changed", {})
            if "Connected" not in changed:
                continue

            connected_val = changed["Connected"]
            if isinstance(connected_val, dict):
                connected_val = connected_val.get("to", connected_val)

            if connected_val is True or connected_val == 1 or connected_val == "true":
                self._connected_devices.add(ev.device_addr)
            else:
                self._connected_devices.discard(ev.device_addr)
                self._last_pct.pop(ev.device_addr, None)

    async def _watch_battery_props(self) -> None:
        """
        Subscribe to PropertiesChanged on org.bluez.Battery1 for reactive updates.

        This runs alongside the poll loop. Devices that push notifications (most
        modern BLE devices) will update here without waiting for the poll interval.
        Uses dbus-next to watch for PropertiesChanged signals.
        """
        try:
            from dbus_next.aio import MessageBus as AioMessageBus
            from dbus_next import BusType
        except ImportError:
            return

        try:
            dbus = await AioMessageBus(bus_type=BusType.SYSTEM).connect()
        except Exception:
            return

        # Subscribe to PropertiesChanged signals on any org.bluez path
        try:
            await dbus.call_method(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "AddMatch",
                "s",
                (
                    "type='signal',"
                    "interface='org.freedesktop.DBus.Properties',"
                    "member='PropertiesChanged',"
                    "path_namespace='/org/bluez'"
                ),
            )
        except Exception:
            dbus.disconnect()
            return

        def _on_message(msg) -> None:
            if not self._running:
                return
            try:
                if (msg.member != "PropertiesChanged"
                        or not msg.path
                        or "/dev_" not in msg.path):
                    return
                interface = msg.body[0] if msg.body else ""
                if interface != "org.bluez.Battery1":
                    return
                changed = msg.body[1] if len(msg.body) > 1 else {}
                pct_val = changed.get("Percentage")
                if pct_val is None:
                    return
                # Unwrap dbus-next Variant
                pct = int(pct_val.value if hasattr(pct_val, "value") else pct_val)

                # Extract device addr from path
                import re as _re
                m = _re.search(r"dev_([0-9A-Fa-f_]{17})", msg.path)
                if not m:
                    return
                addr = m.group(1).replace("_", ":").upper()

                asyncio.create_task(self._emit_battery(addr, pct, reactive=True))
            except Exception:
                pass

        dbus.add_message_handler(_on_message)

        try:
            while self._running:
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        finally:
            dbus.disconnect()

    async def _poll_loop(self) -> None:
        """Periodically query Battery1.Percentage for each connected device."""
        interval = float(self._cfg("poll_interval_s", 60))

        # Initial delay — wait for D-Bus collector to populate connected devices
        await asyncio.sleep(8.0)

        while self._running:
            devices = set(self._connected_devices)  # snapshot
            for addr in devices:
                if not self._running:
                    break
                await self._poll_device(addr)
                await asyncio.sleep(0.3)

            await asyncio.sleep(interval)

    async def _poll_device(self, addr: str) -> None:
        """Query Battery1.Percentage for a single device via D-Bus."""
        try:
            from dbus_next.aio import MessageBus as AioMessageBus
            from dbus_next import BusType, Variant
        except ImportError:
            return

        obj_path = "/org/bluez/hci0/dev_" + addr.replace(":", "_")

        try:
            dbus = await AioMessageBus(bus_type=BusType.SYSTEM).connect()
            result = await asyncio.wait_for(
                dbus.call_method(
                    "org.bluez",
                    obj_path,
                    "org.freedesktop.DBus.Properties",
                    "Get",
                    "ss",
                    ("org.bluez.Battery1", "Percentage"),
                ),
                timeout=3.0,
            )
            dbus.disconnect()
        except asyncio.TimeoutError:
            return
        except Exception:
            # Device may not support Battery1 — silently skip
            return

        try:
            # result.body is [Variant('y', value)]
            pct_variant = result.body[0] if result.body else None
            if pct_variant is None:
                return
            pct = int(pct_variant.value if hasattr(pct_variant, "value") else pct_variant)
        except Exception:
            return

        await self._emit_battery(addr, pct, reactive=False)

    async def _emit_battery(self, addr: str, pct: int, reactive: bool) -> None:
        """Emit a BATTERY_LEVEL event. Suppresses if value unchanged since last emit."""
        last = self._last_pct.get(addr)
        if last == pct and not reactive:
            # Suppress unchanged polled values; pass-through reactive notifications
            return

        self._last_pct[addr] = pct

        warn_threshold  = int(self._cfg("low_battery_warn",  20))
        error_threshold = int(self._cfg("low_battery_error", 10))

        if pct <= error_threshold:
            sev = "ERROR"
        elif pct <= warn_threshold:
            sev = "WARN"
        else:
            sev = "INFO"

        source = "reactive" if reactive else "poll"
        await self.bus.publish(Event.new(
            source="SYSFS",
            severity=sev,
            event_type="BATTERY_LEVEL",
            device_addr=addr,
            summary=f"Battery {addr}: {pct}%{' (low)' if sev != 'INFO' else ''}",
            raw_json={
                "addr":      addr,
                "percent":   pct,
                "source":    source,
                "threshold_warn":  warn_threshold,
                "threshold_error": error_threshold,
            },
            source_version=self.source_version_tag,
            parser_version=f"battery-{self.version}",
        ))
