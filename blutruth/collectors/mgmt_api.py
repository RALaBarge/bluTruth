"""
blutruth.collectors.mgmt_api — Bluetooth Management API collector

Monitors the kernel mgmt API layer via two complementary approaches:

1. btmgmt monitor: Runs `btmgmt --monitor` to capture management events
   (controller added/removed, power state, advertising, connections at the
   kernel level). This is the netlink socket between bluetoothd and the
   kernel bluetooth subsystem.

2. Sysfs polling: Periodically reads /sys/kernel/debug/bluetooth/hci*/
   for low-level controller state (features, manufacturer, connections,
   link keys, identity, etc.) that isn't exposed through D-Bus.

Stack position:
    bluetoothd
        ↓
    mgmt API (netlink socket to kernel)  ← THIS COLLECTOR
        ↓
    core bluetooth.ko

FUTURE: Open AF_BLUETOOTH/HCI_CHANNEL_CONTROL directly for raw mgmt frames.
FUTURE: Parse mgmt opcodes for richer event classification.
FUTURE (Rust port): btmgmt crate or raw mgmt socket via libc.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# btmgmt monitor output patterns
# Event lines look like:
#   @ Controller Information: 00:1A:7D:DA:71:13 ...
#   @ Device Connected: AA:BB:CC:DD:EE:FF ...
#   @ New Settings: 0x00002dff
_MGMT_EVENT_RE = re.compile(
    r"^@\s+"
    r"(.+?):\s*(.*)"  # event name : payload
)

# Address extraction
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

# btmgmt event classification
_MGMT_CLASSIFICATION: Dict[str, tuple] = {
    "Controller Information":      ("INFO",  None),
    "Controller Error":            ("ERROR", None),
    "Index Added":                 ("INFO",  None),
    "Index Removed":               ("WARN",  None),
    "New Settings":                ("INFO",  None),
    "Discovering":                 ("INFO",  "DISCOVERY"),
    "Device Found":                ("INFO",  "DISCOVERY"),
    "Device Connected":            ("INFO",  "CONNECTION"),
    "Device Disconnected":         ("WARN",  "TEARDOWN"),
    "Connect Failed":              ("ERROR", "CONNECTION"),
    "PIN Code Request":            ("INFO",  "HANDSHAKE"),
    "User Confirmation":           ("INFO",  "HANDSHAKE"),
    "User Passkey Request":        ("INFO",  "HANDSHAKE"),
    "Authentication Failed":       ("ERROR", "HANDSHAKE"),
    "Device Unpaired":             ("INFO",  "TEARDOWN"),
    "New Key":                     ("INFO",  "HANDSHAKE"),
    "New Long Term Key":           ("INFO",  "HANDSHAKE"),
    "New Identity Resolving Key":  ("INFO",  "HANDSHAKE"),
    "New Signature Resolving Key": ("INFO",  "HANDSHAKE"),
    "Device Blocked":              ("WARN",  "CONNECTION"),
    "Device Unblocked":            ("INFO",  "CONNECTION"),
    "New Connection Parameter":    ("DEBUG", "CONNECTION"),
    "Advertising Added":           ("INFO",  "DISCOVERY"),
    "Advertising Removed":         ("INFO",  "DISCOVERY"),
    "PHY Configuration Changed":   ("INFO",  "CONNECTION"),
    "Command Status":              ("DEBUG", None),
    "Command Complete":            ("DEBUG", None),
}

# Sysfs paths under /sys/kernel/debug/bluetooth/
_DEBUG_BT_BASE = Path("/sys/kernel/debug/bluetooth")

# Sysfs files to poll per adapter
_SYSFS_FILES = [
    "features",
    "manufacturer",
    "hci_ver",
    "hci_rev",
    "conn_info_min_age",
    "conn_info_max_age",
    "conn_latency",
    "supervision_timeout",
]

# /sys/class/bluetooth/ for non-debug info
_SYS_CLASS_BT = Path("/sys/class/bluetooth")


class MgmtApiCollector(Collector):
    name = "mgmt"
    description = "Bluetooth Management API (btmgmt + sysfs)"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._sysfs_task: Optional[asyncio.Task] = None
        self._last_sysfs_state: Dict[str, Dict[str, str]] = {}

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": True,
            "requires_debugfs": True,
            "exclusive_resource": None,
            "optional_root_benefits": [
                "btmgmt --monitor requires root for raw mgmt socket access",
                "debugfs bluetooth/ requires root for controller internals",
            ],
            "provides": ["KERNEL"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        self._running = True

        # Start btmgmt monitor
        self._monitor_task = asyncio.create_task(self._start_btmgmt())

        # Start sysfs poller
        poll_interval = self.config.get(
            "collectors", "mgmt", "sysfs_poll_s", default=5.0
        )
        self._sysfs_task = asyncio.create_task(self._sysfs_poll_loop(poll_interval))

        await self.bus.publish(Event.new(
            source="KERNEL",
            event_type="COLLECTOR_START",
            summary="Mgmt API collector started (btmgmt + sysfs)",
            raw_json={
                "btmgmt_monitor": True,
                "sysfs_poll_interval": poll_interval,
                "debugfs_available": _DEBUG_BT_BASE.exists(),
            },
            source_version=self.source_version_tag,
        ))

    async def _start_btmgmt(self) -> None:
        """Run btmgmt --monitor and parse its output."""
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "btmgmt", "--monitor",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="btmgmt not found — install bluez-utils; mgmt monitor disabled",
                raw_json={"error": "btmgmt not found in PATH"},
                source_version=self.source_version_tag,
            ))
            return

        await self._read_btmgmt_loop()

    async def _read_btmgmt_loop(self) -> None:
        """Parse btmgmt --monitor output into events."""
        assert self._proc and self._proc.stdout

        current_block: list[str] = []
        current_event_name: Optional[str] = None
        current_payload: Optional[str] = None

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="btmgmt --monitor exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            # Check for new mgmt event
            m = _MGMT_EVENT_RE.match(line)
            if m:
                # Flush previous block
                if current_event_name and current_block:
                    await self._emit_mgmt_event(
                        current_event_name, current_payload or "", current_block
                    )
                current_event_name = m.group(1).strip()
                current_payload = m.group(2).strip()
                current_block = [line]
            else:
                # Continuation line (indented details)
                current_block.append(line)

        # Flush last block
        if current_event_name and current_block:
            await self._emit_mgmt_event(
                current_event_name, current_payload or "", current_block
            )

    async def _emit_mgmt_event(
        self, event_name: str, payload: str, block: list[str]
    ) -> None:
        """Classify and publish a btmgmt event."""
        severity, stage = _MGMT_CLASSIFICATION.get(
            event_name, ("INFO", None)
        )

        # Extract device address
        device_addr = None
        for line in block:
            addr_m = _ADDR_RE.search(line)
            if addr_m:
                device_addr = addr_m.group(1).upper()
                break

        # Determine adapter from context
        adapter = None
        for line in block:
            # btmgmt often includes "hci0" or similar
            hci_m = re.search(r"(hci\d+)", line)
            if hci_m:
                adapter = hci_m.group(1)
                break

        full_text = "\n".join(block)

        await self.bus.publish(Event.new(
            source="KERNEL",
            severity=severity,
            stage=stage,
            event_type="MGMT_EVT",
            adapter=adapter,
            device_addr=device_addr,
            summary=f"mgmt: {event_name}: {payload[:150]}",
            raw_json={
                "mgmt_event": event_name,
                "payload": payload,
                "lines": block,
            },
            raw=full_text,
            source_version=self.source_version_tag,
            parser_version=f"mgmt-parser-{self.version}",
        ))

    # --- Sysfs polling ---

    async def _sysfs_poll_loop(self, interval: float) -> None:
        """Periodically read sysfs/debugfs for controller state changes."""
        # Initial snapshot
        await self._sysfs_snapshot(initial=True)

        while self._running:
            await asyncio.sleep(interval)
            try:
                await self._sysfs_snapshot(initial=False)
            except Exception as e:
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="DEBUG",
                    event_type="SYSFS_ERROR",
                    summary=f"Sysfs poll error: {e}",
                    raw_json={"error": str(e)},
                    source_version=self.source_version_tag,
                ))

    async def _sysfs_snapshot(self, initial: bool = False) -> None:
        """Read all sysfs bluetooth data and emit events for changes."""
        adapters = self._discover_adapters()

        for adapter in adapters:
            state = await self._read_adapter_sysfs(adapter)
            prev = self._last_sysfs_state.get(adapter, {})

            if initial:
                # Emit a full state dump on first poll
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="INFO",
                    event_type="SYSFS_SNAPSHOT",
                    adapter=adapter,
                    summary=f"sysfs: {adapter} initial state snapshot",
                    raw_json={"adapter": adapter, "state": state},
                    source_version=self.source_version_tag,
                ))
            else:
                # Diff and emit changes
                changes = {}
                for key, val in state.items():
                    if prev.get(key) != val:
                        changes[key] = {"old": prev.get(key), "new": val}

                # Check for new adapters
                if not prev and state:
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="INFO",
                        event_type="SYSFS_CHANGE",
                        adapter=adapter,
                        summary=f"sysfs: new adapter detected: {adapter}",
                        raw_json={"adapter": adapter, "state": state},
                        source_version=self.source_version_tag,
                    ))
                elif changes:
                    change_summary = ", ".join(
                        f"{k}: {v['old']}→{v['new']}" for k, v in list(changes.items())[:5]
                    )
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="INFO",
                        event_type="SYSFS_CHANGE",
                        adapter=adapter,
                        summary=f"sysfs: {adapter} changed: {change_summary}",
                        raw_json={"adapter": adapter, "changes": changes},
                        source_version=self.source_version_tag,
                    ))

            self._last_sysfs_state[adapter] = state

        # Detect removed adapters
        for adapter in list(self._last_sysfs_state.keys()):
            if adapter not in adapters:
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="WARN",
                    event_type="SYSFS_CHANGE",
                    adapter=adapter,
                    summary=f"sysfs: adapter removed: {adapter}",
                    raw_json={"adapter": adapter, "removed": True},
                    source_version=self.source_version_tag,
                ))
                del self._last_sysfs_state[adapter]

    def _discover_adapters(self) -> List[str]:
        """Find all bluetooth adapters via /sys/class/bluetooth/."""
        adapters = []
        if _SYS_CLASS_BT.exists():
            for entry in _SYS_CLASS_BT.iterdir():
                if entry.name.startswith("hci"):
                    adapters.append(entry.name)
        return sorted(adapters)

    async def _read_adapter_sysfs(self, adapter: str) -> Dict[str, str]:
        """Read sysfs attributes for one adapter."""
        state: Dict[str, str] = {}

        # /sys/class/bluetooth/hciN/ attributes
        class_path = _SYS_CLASS_BT / adapter
        for attr in ("address", "type", "manufacturer", "hci_version", "hci_revision"):
            fpath = class_path / attr
            if fpath.exists():
                try:
                    state[f"class_{attr}"] = fpath.read_text().strip()
                except (PermissionError, OSError):
                    pass

        # /sys/kernel/debug/bluetooth/hciN/ attributes (requires root)
        debug_path = _DEBUG_BT_BASE / adapter
        if debug_path.exists():
            for fname in _SYSFS_FILES:
                fpath = debug_path / fname
                if fpath.exists():
                    try:
                        state[f"debug_{fname}"] = fpath.read_text().strip()[:500]
                    except (PermissionError, OSError):
                        pass

            # Connection count from /sys/kernel/debug/bluetooth/hciN/conn*
            conn_path = debug_path / "conn_info"
            if conn_path.exists():
                try:
                    state["debug_conn_info"] = conn_path.read_text().strip()[:1000]
                except (PermissionError, OSError):
                    pass

        # Operational state from /sys/class/bluetooth/hciN/
        operstate = class_path / "operstate"
        if operstate.exists():
            try:
                state["operstate"] = operstate.read_text().strip()
            except (PermissionError, OSError):
                pass

        return state

    async def stop(self) -> None:
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task
            self._monitor_task = None
        if self._sysfs_task:
            self._sysfs_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sysfs_task
            self._sysfs_task = None
        if self._proc:
            with contextlib.suppress(ProcessLookupError):
                self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            self._proc = None
