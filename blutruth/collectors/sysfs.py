"""
blutruth.collectors.sysfs — Sysfs adapter + rfkill + USB power state collector

Polls /sys/class/bluetooth/hci* and /sys/class/rfkill/ for adapter-level
state that isn't surfaced through HCI frames or D-Bus signals. Useful for
catching power state changes, rfkill block events, and USB disconnect/reconnect
before bluetoothd even reacts.

Also follows hciN/device → USB device sysfs node and monitors USB runtime_status
and power budget. This is the layer that catches "USB hub not powering up
properly" — adapter disappears + USB runtime_status=error/suspended.

No root required. No external tools. Pure Python + pathlib.

Stack position (what this watches):
  /sys/class/bluetooth/hci0/
    address         BD_ADDR of the adapter
    type            Primary / Secondary (Classic / LE)
    bus             USB / UART / ...
    features        LMP feature bitmask
    states          Current HCI state (disconnected/scanning/connected)
    name            Friendly adapter name

  /sys/class/rfkill/rfkillN/   (where type == "bluetooth")
    soft            0 = not blocked, 1 = software blocked
    hard            0 = not blocked, 1 = hardware blocked

  /sys/bus/usb/devices/X/   (resolved via hciN/device symlink)
    manufacturer        USB manufacturer string
    product             USB product string
    idVendor/idProduct  USB VID:PID
    bMaxPower           Power budget from USB descriptor (mA)
    power/runtime_status  active | suspended | error | unsupported
    power/control         auto | on

FUTURE: Parse /sys/kernel/debug/bluetooth/hci*/features for richer capabilities.
FUTURE: Parse /sys/kernel/debug/bluetooth/hci*/conn_info for connection details.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# Sysfs paths
_BT_CLASS  = Path("/sys/class/bluetooth")
_RFKILL    = Path("/sys/class/rfkill")

# Properties to read per adapter
_ADAPTER_PROPS = ["address", "type", "bus", "name", "states", "manufacturer"]

# Properties to read per rfkill node
_RFKILL_PROPS  = ["soft", "hard", "name"]

# USB power sysfs files to read (relative to USB device root)
_USB_POWER_FILES = [
    "manufacturer",
    "product",
    "idVendor",
    "idProduct",
    "bMaxPower",
    "power/runtime_status",
    "power/control",
]

# USB runtime_status values and their severity
_USB_STATUS_SEVERITY = {
    "active":      "INFO",
    "suspended":   "WARN",
    "error":       "ERROR",
    "unsupported": "DEBUG",
}


def _read(path: Path) -> Optional[str]:
    """Read a sysfs file, return stripped string or None."""
    try:
        return path.read_text().strip()
    except Exception:
        return None


def _adapter_snapshot(hci_path: Path) -> Dict[str, Optional[str]]:
    """Read all interesting properties from an hciN sysfs directory."""
    snap: Dict[str, Optional[str]] = {"adapter": hci_path.name}
    for prop in _ADAPTER_PROPS:
        snap[prop] = _read(hci_path / prop)
    return snap


def _rfkill_snapshot() -> List[Dict[str, Optional[str]]]:
    """Read all Bluetooth rfkill nodes."""
    nodes = []
    if not _RFKILL.exists():
        return nodes
    for node in sorted(_RFKILL.iterdir()):
        if _read(node / "type") != "bluetooth":
            continue
        entry: Dict[str, Optional[str]] = {"node": node.name}
        for prop in _RFKILL_PROPS:
            entry[prop] = _read(node / prop)
        nodes.append(entry)
    return nodes


def _rfkill_blocked(nodes: List[Dict]) -> bool:
    """Return True if any rfkill node is soft or hard blocked."""
    for n in nodes:
        if n.get("soft") == "1" or n.get("hard") == "1":
            return True
    return False


def _find_usb_device(hci_path: Path) -> Optional[Path]:
    """
    Follow hciN/device symlink up the sysfs tree to find the USB device node.

    The symlink resolves to a USB interface (e.g. 1-1.3:1.0). Walk up until
    we find a directory that has idVendor — that's the USB device proper.
    Returns None for non-USB adapters (UART, SDIO, etc.) or if not found.
    """
    device_link = hci_path / "device"
    if not device_link.exists():
        return None
    try:
        p = device_link.resolve()
        for _ in range(6):  # max depth to walk up
            if (p / "idVendor").exists():
                return p
            p = p.parent
    except Exception:
        pass
    return None


def _usb_snapshot(usb_path: Path) -> Dict[str, Optional[str]]:
    """Read USB power-related sysfs files for one USB device."""
    snap: Dict[str, Optional[str]] = {}
    for fname in _USB_POWER_FILES:
        key = fname.replace("/", "_")
        snap[key] = _read(usb_path / fname)
    return snap


class SysfsCollector(Collector):
    name = "sysfs"
    description = "Adapter state + rfkill via /sys/class/bluetooth"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None
        self._prev_adapters: Dict[str, Dict] = {}
        self._prev_rfkill: List[Dict] = []
        self._prev_usb: Dict[str, Dict] = {}  # hci name → usb snapshot

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [
                "Access to /sys/kernel/debug/bluetooth/ for deeper adapter state",
            ],
            "provides": ["SYSFS"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        if not _BT_CLASS.exists():
            await self.bus.publish(Event.new(
                source="SYSFS",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="/sys/class/bluetooth not found — Bluetooth subsystem not loaded?",
                raw_json={"path": str(_BT_CLASS)},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._task = asyncio.create_task(self._poll_loop())

        await self.bus.publish(Event.new(
            source="SYSFS",
            event_type="COLLECTOR_START",
            summary="Sysfs collector started — polling adapter state and rfkill",
            raw_json={"bt_class": str(_BT_CLASS), "rfkill": str(_RFKILL)},
            source_version=self.source_version_tag,
        ))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _poll_loop(self) -> None:
        poll_s = float(self.config.get("collectors", "sysfs", "poll_s", default=2.0))

        # Emit initial snapshot on first poll
        first = True

        while self._running:
            await asyncio.sleep(0 if first else poll_s)
            first = False

            await asyncio.gather(
                self._poll_adapters(),
                self._poll_rfkill(),
                self._poll_usb_power(),
                return_exceptions=True,
            )

    async def _poll_adapters(self) -> None:
        """Compare current adapter sysfs state to previous; emit on change."""
        if not _BT_CLASS.exists():
            return

        current: Dict[str, Dict] = {}
        for hci_path in sorted(_BT_CLASS.iterdir()):
            if not hci_path.name.startswith("hci"):
                continue
            snap = _adapter_snapshot(hci_path)
            current[hci_path.name] = snap

        # Detect new adapters
        for name, snap in current.items():
            if name not in self._prev_adapters:
                await self.bus.publish(Event.new(
                    source="SYSFS",
                    severity="INFO",
                    stage="CONNECTION",
                    event_type="ADAPTER_ADDED",
                    adapter=name,
                    device_addr=snap.get("address"),
                    summary=f"Adapter appeared: {name} [{snap.get('address', '?')}]",
                    raw_json={"snapshot": snap, "change": "added"},
                    source_version=self.source_version_tag,
                    parser_version=f"sysfs-parser-{self.version}",
                ))

        # Detect removed adapters
        for name in list(self._prev_adapters):
            if name not in current:
                prev = self._prev_adapters[name]
                await self.bus.publish(Event.new(
                    source="SYSFS",
                    severity="WARN",
                    stage="TEARDOWN",
                    event_type="ADAPTER_REMOVED",
                    adapter=name,
                    device_addr=prev.get("address"),
                    summary=f"Adapter disappeared: {name} [{prev.get('address', '?')}]",
                    raw_json={"snapshot": prev, "change": "removed"},
                    source_version=self.source_version_tag,
                    parser_version=f"sysfs-parser-{self.version}",
                ))

        # Detect changed properties
        for name, snap in current.items():
            prev = self._prev_adapters.get(name, {})
            changed = {k: (prev.get(k), snap[k]) for k in snap if snap[k] != prev.get(k) and k != "adapter"}
            if changed and prev:  # only emit if we had a previous snapshot (skip initial)
                # Determine severity from what changed
                sev = "WARN" if "states" in changed else "INFO"
                changes_fmt = ", ".join(f"{k}: {old!r}→{new!r}" for k, (old, new) in changed.items())
                await self.bus.publish(Event.new(
                    source="SYSFS",
                    severity=sev,
                    event_type="ADAPTER_STATE",
                    adapter=name,
                    device_addr=snap.get("address"),
                    summary=f"{name} state changed: {changes_fmt}",
                    raw_json={"snapshot": snap, "changed": {k: {"from": o, "to": n} for k, (o, n) in changed.items()}},
                    source_version=self.source_version_tag,
                    parser_version=f"sysfs-parser-{self.version}",
                ))

        self._prev_adapters = current

    async def _poll_rfkill(self) -> None:
        """Check rfkill state; emit on soft/hard block changes."""
        current = _rfkill_snapshot()

        # Build comparable maps
        prev_map = {n["node"]: n for n in self._prev_rfkill}
        curr_map = {n["node"]: n for n in current}

        for node_name, snap in curr_map.items():
            prev = prev_map.get(node_name, {})
            if not prev:
                # First time we see this node — emit initial state
                blocked = snap.get("soft") == "1" or snap.get("hard") == "1"
                if blocked:
                    await self.bus.publish(Event.new(
                        source="SYSFS",
                        severity="WARN",
                        event_type="RFKILL_BLOCKED",
                        summary=f"rfkill {node_name} ({snap.get('name', '?')}): BLOCKED (soft={snap.get('soft')} hard={snap.get('hard')})",
                        raw_json={"rfkill": snap},
                        source_version=self.source_version_tag,
                    ))
                continue

            # Detect changes in soft or hard block
            for key in ("soft", "hard"):
                if snap.get(key) != prev.get(key):
                    new_val = snap.get(key)
                    blocked = new_val == "1"
                    await self.bus.publish(Event.new(
                        source="SYSFS",
                        severity="WARN" if blocked else "INFO",
                        event_type="RFKILL_CHANGE",
                        summary=(
                            f"rfkill {node_name} {key}: {'BLOCKED' if blocked else 'UNBLOCKED'} "
                            f"(was {prev.get(key)!r})"
                        ),
                        raw_json={"rfkill": snap, "changed_key": key, "old": prev.get(key), "new": new_val},
                        source_version=self.source_version_tag,
                    ))

        self._prev_rfkill = current

    async def _poll_usb_power(self) -> None:
        """
        For each BT adapter, find its USB device via sysfs symlink and monitor
        runtime_status and bMaxPower. Emits events when power state changes.

        Non-USB adapters (UART, SDIO) will have no USB device — silently skipped.
        """
        if not _BT_CLASS.exists():
            return

        for hci_path in sorted(_BT_CLASS.iterdir()):
            if not hci_path.name.startswith("hci"):
                continue

            usb_path = _find_usb_device(hci_path)
            if not usb_path:
                continue  # not a USB adapter

            snap = _usb_snapshot(usb_path)
            prev = self._prev_usb.get(hci_path.name)

            if prev is None:
                # First time we see this USB device — emit an info snapshot
                vid = snap.get("idVendor", "?")
                pid = snap.get("idProduct", "?")
                mfr = snap.get("manufacturer") or snap.get("product") or "unknown"
                power_budget = snap.get("bMaxPower", "?")
                runtime = snap.get("power_runtime_status", "unknown")

                await self.bus.publish(Event.new(
                    source="SYSFS",
                    severity="INFO",
                    event_type="USB_ADAPTER_INFO",
                    adapter=hci_path.name,
                    summary=(
                        f"USB BT adapter {hci_path.name}: {mfr} "
                        f"[{vid}:{pid}] power={power_budget} status={runtime}"
                    ),
                    raw_json={
                        "adapter": hci_path.name,
                        "usb_path": str(usb_path),
                        "usb": snap,
                    },
                    source_version=self.source_version_tag,
                ))

            else:
                # Check runtime_status change
                prev_status = prev.get("power_runtime_status")
                curr_status = snap.get("power_runtime_status")

                if curr_status != prev_status and curr_status is not None:
                    severity = _USB_STATUS_SEVERITY.get(curr_status, "INFO")
                    mfr = snap.get("manufacturer") or snap.get("product") or "USB device"
                    await self.bus.publish(Event.new(
                        source="SYSFS",
                        severity=severity,
                        event_type="USB_POWER_CHANGE",
                        adapter=hci_path.name,
                        summary=(
                            f"USB adapter {hci_path.name} power: "
                            f"{prev_status!r} → {curr_status!r} ({mfr})"
                        ),
                        raw_json={
                            "adapter": hci_path.name,
                            "usb_path": str(usb_path),
                            "prev_status": prev_status,
                            "curr_status": curr_status,
                            "usb": snap,
                        },
                        source_version=self.source_version_tag,
                    ))

            self._prev_usb[hci_path.name] = snap
