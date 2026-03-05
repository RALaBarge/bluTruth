"""
blutruth.collectors.ubertooth — Air-level Classic Bluetooth sniffer

Captures Bluetooth BR/EDR frames from the air via an Ubertooth One hardware
dongle. This is the only layer that sees RF-level traffic before the host
controller processes it — useful for catching connection issues that don't
even make it to HCI.

What Ubertooth captures:
  - Raw BR/EDR packets (LAP, UAP, access code)
  - Piconet hopping sequence (clock synchronization)
  - AFH channel map changes
  - Timing anomalies (clock drift, missed frames)
  - Devices that never reach host (rejected at RF level)

Hardware required:
  Ubertooth One (greatscottgadgets.com/ubertoothone/)
  Software: ubertooth-tools (ubertooth-rx, ubertooth-follow, ubertooth-pan)

Setup:
  sudo apt install ubertooth
  # or build from https://github.com/greatscottgadgets/ubertooth

Current status: MOCK MODE
  No Ubertooth hardware detected. This collector emits a startup notice
  and optionally generates synthetic air-level events for UI/pipeline testing.

  Enable mock data generation:
    collectors:
      ubertooth:
        enabled: true
        mock_data: true         # emit synthetic events for testing

FUTURE: Implement real ubertooth-rx parsing when hardware is connected.
FUTURE: ubertooth-follow to lock on to a specific LAP/piconet.
FUTURE: Export to btsnoop for Wireshark analysis.
FUTURE (Rust port): libubertooth bindings via ctypes or bindgen.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from typing import Any, Dict, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


class UbertoothCollector(Collector):
    name = "ubertooth"
    description = "Air-level Classic BT sniffer (Ubertooth One) [MOCK]"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": "ubertooth_usb",
            "optional_root_benefits": [],
            "provides": ["UBERTOOTH"],
            "depends_on": [],
        }

    def enabled(self) -> bool:
        return bool(self.config.get("collectors", "ubertooth", "enabled", default=False))

    async def start(self) -> None:
        if not self.enabled():
            return

        hardware_present = shutil.which("ubertooth-rx") is not None

        if not hardware_present:
            await self.bus.publish(Event.new(
                source="UBERTOOTH",
                severity="WARN",
                event_type="COLLECTOR_MOCK",
                summary="Ubertooth: ubertooth-tools not found — running in mock mode",
                raw_json={
                    "status": "mock",
                    "reason": "ubertooth-rx not in PATH",
                    "hint": "Install ubertooth-tools and connect an Ubertooth One dongle",
                    "hardware_url": "https://greatscottgadgets.com/ubertoothone/",
                },
                source_version=self.source_version_tag,
            ))
        else:
            # Tools present but we haven't implemented real parsing yet
            await self.bus.publish(Event.new(
                source="UBERTOOTH",
                severity="WARN",
                event_type="COLLECTOR_MOCK",
                summary="Ubertooth: tools found but real parsing not yet implemented — mock mode",
                raw_json={
                    "status": "mock",
                    "reason": "real ubertooth-rx parsing not yet implemented",
                },
                source_version=self.source_version_tag,
            ))

        mock_data = bool(self.config.get("collectors", "ubertooth", "mock_data", default=False))
        if mock_data:
            self._running = True
            self._task = asyncio.create_task(self._mock_loop())
            await self.bus.publish(Event.new(
                source="UBERTOOTH",
                event_type="COLLECTOR_START",
                summary="Ubertooth mock data generator started",
                raw_json={"mode": "mock", "mock_data": True},
                source_version=self.source_version_tag,
            ))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _mock_loop(self) -> None:
        """Emit periodic synthetic air-level events for UI/pipeline testing."""
        import random
        import time

        mock_devices = [
            "AA:BB:CC:DD:EE:01",
            "AA:BB:CC:DD:EE:02",
        ]
        mock_events = [
            ("AIR_PKT",    "INFO",  "DISCOVERY",  "LAP detected: {addr} (access code sync)"),
            ("AIR_PKT",    "INFO",  "CONNECTION", "Piconet entry: {addr} on channel {ch}"),
            ("AFH_MAP",    "INFO",  "CONNECTION", "AFH channel map: {addr} — 40 channels active"),
            ("AIR_PKT",    "DEBUG", "DATA",        "ACL fragment: {addr} — 27 bytes"),
            ("CLOCK_SYNC", "INFO",  "CONNECTION", "Clock sync: {addr} drift=+{drift}ppm"),
            ("AIR_PKT",    "WARN",  "TEARDOWN",   "Piconet exit: {addr} — no response after 3 polls"),
        ]

        while self._running:
            await asyncio.sleep(random.uniform(3.0, 8.0))
            if not self._running:
                break

            ev_type, sev, stage, summary_tmpl = random.choice(mock_events)
            addr = random.choice(mock_devices)
            ch   = random.randint(0, 78)
            drift = random.randint(-5, 15)
            summary = summary_tmpl.format(addr=addr, ch=ch, drift=drift)

            await self.bus.publish(Event.new(
                source="UBERTOOTH",
                severity=sev,
                stage=stage,
                event_type=ev_type,
                device_addr=addr,
                summary=f"[MOCK] {summary}",
                raw_json={
                    "mock": True,
                    "ts_air_us": int(time.monotonic() * 1_000_000),
                    "channel": ch,
                    "device_addr": addr,
                },
                tags=["mock"],
                source_version=self.source_version_tag,
            ))
