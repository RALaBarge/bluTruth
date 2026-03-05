"""
blutruth.collectors.udev — Bluetooth hotplug event collector via udevadm

Monitors kernel device events for the Bluetooth subsystem:
  - BT adapter USB plug/unplug
  - BT HCI device node add/remove
  - Driver bind/unbind events

This layer sits below bluetoothd. When a USB BT dongle is yanked, udev
fires before btmon sees anything and well before D-Bus reflects the change.
Useful for catching "why did everything go silent simultaneously?"

Uses: udevadm monitor --subsystem-match=bluetooth --subsystem-match=usb

No root required. udevadm is typically available on any systemd-based distro.

FUTURE: Use libudev bindings directly (python-pyudev) for richer event metadata.
FUTURE: Filter USB events to only BT-class devices (class 0xe0, subclass 0x01).
FUTURE (Rust port): udev crate with async MonitorSocket.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from typing import Any, Dict, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# udevadm monitor output format:
#   KERNEL[12345.678901] add      /devices/pci0000:00/.../bluetooth/hci0 (bluetooth)
#   UDEV  [12345.678902] add      /devices/pci0000:00/.../bluetooth/hci0 (bluetooth)
_UDEV_LINE_RE = re.compile(
    r"^(KERNEL|UDEV)\s*\[[\d.]+\]\s+"
    r"(add|remove|change|bind|unbind|online|offline)\s+"
    r"(/\S+)\s+"
    r"\((\w+)\)"
)

# Extract hciN adapter name from device path
_HCI_RE = re.compile(r"/(hci\d+)")

# Extract USB device info from path (optional, best-effort)
_USB_RE = re.compile(r"/(usb\d+|[0-9]+-[0-9.]+)/")

# udevadm action → severity / stage mapping
_ACTION_MAP: Dict[str, tuple] = {
    "add":     ("INFO",  "CONNECTION"),
    "remove":  ("WARN",  "TEARDOWN"),
    "change":  ("INFO",  None),
    "bind":    ("INFO",  "CONNECTION"),
    "unbind":  ("WARN",  "TEARDOWN"),
    "online":  ("INFO",  None),
    "offline": ("WARN",  None),
}


class UdevCollector(Collector):
    name = "udev"
    description = "Bluetooth hotplug events via udevadm monitor"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["UDEV"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        # Only emit UDEV-side events (not duplicate KERNEL events)
        # --environment gives us property key=value lines after each event
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "udevadm", "monitor",
                "--subsystem-match=bluetooth",
                "--subsystem-match=usb",
                "--udev",                   # UDEV events only (post-rules, not raw kernel)
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            await self.bus.publish(Event.new(
                source="UDEV",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="udevadm not found — hotplug events unavailable",
                raw_json={"error": "udevadm not in PATH", "hint": "install udev or systemd-udevd"},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._task = asyncio.create_task(self._read_loop())

        await self.bus.publish(Event.new(
            source="UDEV",
            event_type="COLLECTOR_START",
            summary=f"udev collector started (udevadm monitor bluetooth+usb, PID {self._proc.pid})",
            raw_json={"pid": self._proc.pid},
            source_version=self.source_version_tag,
        ))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._proc:
            with contextlib.suppress(ProcessLookupError):
                self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            self._proc = None

    async def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout

        while self._running:
            try:
                raw = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="UDEV",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="udevadm monitor exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw.decode("utf-8", errors="replace").strip()
            if not line or line.startswith("monitor"):
                # Skip the header line "monitor will print the received events for:"
                continue

            m = _UDEV_LINE_RE.match(line)
            if not m:
                continue

            layer, action, devpath, subsystem = m.groups()

            # Extract adapter name if present
            adapter = None
            hci_m = _HCI_RE.search(devpath)
            if hci_m:
                adapter = hci_m.group(1)

            severity, stage = _ACTION_MAP.get(action, ("INFO", None))

            # More specific severity for USB remove (likely physical disconnect)
            if action == "remove" and subsystem == "usb":
                severity = "ERROR"

            await self.bus.publish(Event.new(
                source="UDEV",
                severity=severity,
                stage=stage,
                event_type=f"UDEV_{action.upper()}",
                adapter=adapter,
                summary=f"udev {action}: {devpath} ({subsystem})",
                raw_json={
                    "action":    action,
                    "devpath":   devpath,
                    "subsystem": subsystem,
                    "layer":     layer,
                },
                raw=line,
                source_version=self.source_version_tag,
                parser_version=f"udev-parser-{self.version}",
            ))
