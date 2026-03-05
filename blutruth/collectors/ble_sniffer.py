"""
blutruth.collectors.ble_sniffer — BLE air-level packet capture

Captures BLE advertising and connection packets from the air via a hardware
sniffer. Unlike the HCI collector (which only sees packets the host adapter
receives), this sees ALL BLE traffic on nearby channels regardless of whether
your adapter is involved.

Useful for:
  - Watching connection parameter negotiation from the outside
  - Catching BLE devices your adapter never responded to
  - Verifying advertising intervals and connection intervals
  - Debugging pairing failures that happen before HCI is involved

Supported hardware targets:
  - nRF Sniffer for BLE (Nordic Semiconductor nRF52840 DK or dongle)
    https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le
    Software: Wireshark + nRF Sniffer plugin (extcap pipe interface)

  - Ellisys Bluetooth Vanguard / Explorer (commercial, high-end)

  - btlejack (any nRF51822 board with btlejack firmware)
    https://github.com/virtualabs/btlejack

Current status: MOCK MODE
  No BLE sniffer hardware detected. This collector emits a startup notice
  and optionally generates synthetic BLE events for UI/pipeline testing.

  Enable mock data generation:
    collectors:
      ble_sniffer:
        enabled: true
        mock_data: true         # emit synthetic BLE events for testing

FUTURE: Implement nRF Sniffer extcap pipe parsing (Wireshark pcap format).
FUTURE: btlejack integration for follow-connection mode.
FUTURE: PCAP export for Wireshark/Wireshark-compatible tools.
FUTURE (Rust port): pcap-rs or direct extcap pipe reader.
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


class BleSnifferCollector(Collector):
    name = "ble_sniffer"
    description = "BLE air-level packet capture (nRF Sniffer / btlejack) [MOCK]"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,   # sniffer doesn't block other BLE use
            "optional_root_benefits": [],
            "provides": ["BLE_AIR"],
            "depends_on": [],
        }

    def enabled(self) -> bool:
        return bool(self.config.get("collectors", "ble_sniffer", "enabled", default=False))

    async def start(self) -> None:
        if not self.enabled():
            return

        # Check for any supported tool
        btlejack = shutil.which("btlejack")
        tool_found = btlejack is not None

        await self.bus.publish(Event.new(
            source="BLE_AIR",
            severity="WARN",
            event_type="COLLECTOR_MOCK",
            summary=(
                "BLE sniffer: running in mock mode — "
                + ("btlejack found but parsing not yet implemented"
                   if tool_found
                   else "no hardware sniffer tool found (btlejack / nRF Sniffer)")
            ),
            raw_json={
                "status": "mock",
                "btlejack_found": tool_found,
                "supported_hardware": [
                    "nRF52840 DK/dongle with nRF Sniffer for Bluetooth LE firmware",
                    "Any nRF51822 board with btlejack firmware",
                ],
                "software": {
                    "btlejack": "https://github.com/virtualabs/btlejack",
                    "nrf_sniffer": "https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le",
                },
            },
            source_version=self.source_version_tag,
        ))

        mock_data = bool(self.config.get("collectors", "ble_sniffer", "mock_data", default=False))
        if mock_data:
            self._running = True
            self._task = asyncio.create_task(self._mock_loop())
            await self.bus.publish(Event.new(
                source="BLE_AIR",
                event_type="COLLECTOR_START",
                summary="BLE sniffer mock data generator started",
                raw_json={"mode": "mock"},
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
        """Emit periodic synthetic BLE air-level events."""
        import random
        import time

        mock_devices = [
            ("AA:BB:CC:DD:EE:03", "Unknown BLE Device"),
            ("AA:BB:CC:DD:EE:04", "BLE Sensor"),
        ]

        mock_events = [
            ("ADV_IND",      "DEBUG", "DISCOVERY",  "{addr} ({name}): ADV_IND rssi={rssi}dBm interval=100ms"),
            ("ADV_NONCONN",  "DEBUG", "DISCOVERY",  "{addr} ({name}): non-connectable advertisement"),
            ("SCAN_REQ",     "DEBUG", "DISCOVERY",  "SCAN_REQ → {addr} from scanner"),
            ("SCAN_RSP",     "DEBUG", "DISCOVERY",  "SCAN_RSP ← {addr}: name={name}"),
            ("CONNECT_IND",  "INFO",  "CONNECTION", "CONNECT_IND → {addr}: interval=30ms latency=0 timeout=500ms"),
            ("LL_VERSION",   "INFO",  "HANDSHAKE",  "{addr}: LL version exchange — BT4.2, company=0x00E0"),
            ("ATT_MTU",      "INFO",  "HANDSHAKE",  "{addr}: ATT MTU exchange 23→247"),
            ("LL_TERMINATE", "WARN",  "TEARDOWN",   "{addr}: LL_TERMINATE_IND reason=0x13 (remote user)"),
            ("CONN_UPDATE",  "INFO",  "CONNECTION", "{addr}: connection parameters updated interval=60ms"),
        ]

        while self._running:
            await asyncio.sleep(random.uniform(2.0, 6.0))
            if not self._running:
                break

            ev_type, sev, stage, summary_tmpl = random.choice(mock_events)
            addr, name = random.choice(mock_devices)
            rssi = random.randint(-90, -40)
            channel = random.choice([37, 38, 39] + list(range(0, 37)))
            summary = summary_tmpl.format(addr=addr, name=name, rssi=rssi)

            await self.bus.publish(Event.new(
                source="BLE_AIR",
                severity=sev,
                stage=stage,
                event_type=ev_type,
                device_addr=addr,
                device_name=name,
                summary=f"[MOCK] {summary}",
                raw_json={
                    "mock": True,
                    "pdu_type": ev_type,
                    "device_addr": addr,
                    "device_name": name,
                    "rssi": rssi,
                    "channel": channel,
                    "ts_air_us": int(time.monotonic() * 1_000_000),
                },
                tags=["mock", "ble"],
                source_version=self.source_version_tag,
            ))
