"""
blutruth.collectors.l2ping — Active L2CAP latency monitor

Runs `l2ping -c N -t T <addr>` against each currently-connected Classic BT
device on a configurable interval. Publishes min/avg/max RTT as events.

This fills the gap between "it's connected" and "is the RF link healthy?"
Correlate RTT spikes with concurrent HCI/D-Bus/PipeWire events to answer:
  "Is this audio glitch RF degradation or software?"
  "Is the lag spike correlation with a HCI connection update event?"

l2ping requires the HCI monitor socket to be available and the remote device
to respond to L2CAP echo requests. Some devices block L2CAP echo — if so,
l2ping will time out and we emit a WARN rather than failing the collector.

Maintains a live set of connected device addresses by subscribing to the bus
and watching for DBUS_PROP Connected events. Only pings devices that are
currently connected via Classic BT (not BLE — l2ping is Classic BT only).

Config:
  collectors:
    l2ping:
      enabled: true
      poll_interval_s: 30     # seconds between RTT polls per device
      ping_count: 5           # -c N packets per poll
      ping_timeout_s: 2       # -t T per-packet timeout
      rtt_warn_ms: 50         # emit WARN if avg RTT exceeds this
      rtt_error_ms: 150       # emit ERROR if avg RTT exceeds this

FUTURE: Also try `hcitool rssi <addr>` for RSSI alongside RTT.
FUTURE (Rust port): Raw L2CAP socket for echo requests without subprocess.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
from typing import Any, Dict, Optional, Set

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# l2ping output:
#   Ping: AA:BB:CC:DD:EE:FF from 00:11:22:33:44:55 (data size 44) ...
#   44 bytes from AA:BB:CC:DD:EE:FF id 0 time 12.34ms
#   5 sent, 5 received, 0% loss
_PING_LINE_RE   = re.compile(r"(\d+) bytes from .+ time ([\d.]+)ms")
_SUMMARY_RE     = re.compile(r"(\d+) sent, (\d+) received, (\d+)% loss")
_RTT_MIN_RE     = re.compile(r"min\s+([\d.]+)\s+ms")
_RTT_MAX_RE     = re.compile(r"max\s+([\d.]+)\s+ms")


class L2pingCollector(Collector):
    name = "l2ping"
    description = "Active L2CAP RTT monitor via l2ping"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None
        self._watcher_task: Optional[asyncio.Task] = None
        self._connected_devices: Set[str] = set()
        self._queue: Optional[asyncio.Queue] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["L2PING"],
            "depends_on": ["dbus"],   # needs dbus to know which devices are connected
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        if not shutil.which("l2ping"):
            await self.bus.publish(Event.new(
                source="SYSFS",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="l2ping not found — install bluez-utils for RTT monitoring",
                raw_json={"error": "l2ping not in PATH"},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._queue = await self.bus.subscribe(max_queue=2000)
        self._watcher_task = asyncio.create_task(self._watch_connections())
        self._task = asyncio.create_task(self._poll_loop())

        await self.bus.publish(Event.new(
            source="SYSFS",
            event_type="COLLECTOR_START",
            summary="L2ping RTT collector started",
            raw_json={
                "poll_interval_s": self._cfg("poll_interval_s", 30),
                "ping_count": self._cfg("ping_count", 5),
            },
            source_version=self.source_version_tag,
        ))

    async def stop(self) -> None:
        self._running = False
        for task in (self._task, self._watcher_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._task = None
        self._watcher_task = None
        if self._queue:
            await self.bus.unsubscribe(self._queue)
            self._queue = None

    def _cfg(self, key: str, default: Any) -> Any:
        return self.config.get("collectors", "l2ping", key, default=default)

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

            # Only care about D-Bus property changes on Device1.Connected
            if ev.source != "DBUS" or ev.event_type != "DBUS_PROP":
                continue
            if not ev.device_addr:
                continue

            raw = ev.raw_json or {}
            changed = raw.get("changed", {})
            if "Connected" not in changed:
                continue

            connected_val = changed["Connected"]
            # Handle nested {"from": x, "to": y} or direct bool
            if isinstance(connected_val, dict):
                connected_val = connected_val.get("to", connected_val)

            if connected_val is True or connected_val == 1 or connected_val == "true":
                self._connected_devices.add(ev.device_addr)
            else:
                self._connected_devices.discard(ev.device_addr)

    async def _poll_loop(self) -> None:
        """Periodically ping each connected device."""
        interval = float(self._cfg("poll_interval_s", 30))

        # Initial delay — wait for D-Bus collector to populate connected devices
        await asyncio.sleep(5.0)

        while self._running:
            devices = set(self._connected_devices)  # snapshot
            for addr in devices:
                if not self._running:
                    break
                await self._ping_device(addr)
                await asyncio.sleep(0.5)  # brief gap between devices

            await asyncio.sleep(interval)

    async def _ping_device(self, addr: str) -> None:
        """Run l2ping against one device and publish RTT event."""
        count   = int(self._cfg("ping_count", 5))
        timeout = int(self._cfg("ping_timeout_s", 2))
        warn_ms = float(self._cfg("rtt_warn_ms", 50))
        err_ms  = float(self._cfg("rtt_error_ms", 150))

        try:
            proc = await asyncio.create_subprocess_exec(
                "l2ping", "-c", str(count), "-t", str(timeout), addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=count * timeout + 5.0,
            )
        except asyncio.TimeoutError:
            await self.bus.publish(Event.new(
                source="SYSFS",
                severity="WARN",
                event_type="L2PING_TIMEOUT",
                device_addr=addr,
                summary=f"l2ping timeout: {addr} — device may not support L2CAP echo",
                raw_json={"addr": addr, "error": "timeout"},
                source_version=self.source_version_tag,
            ))
            return
        except Exception as e:
            return

        output = stdout.decode("utf-8", errors="replace")
        rtts = [float(m.group(2)) for m in _PING_LINE_RE.finditer(output)]
        summary_m = _SUMMARY_RE.search(output)

        if not rtts:
            # l2ping failed — device may not respond to echo or disconnected
            if "Can't connect" in output or "No route" in output:
                self._connected_devices.discard(addr)
            await self.bus.publish(Event.new(
                source="SYSFS",
                severity="WARN",
                event_type="L2PING_FAILED",
                device_addr=addr,
                summary=f"l2ping failed: {addr} — {output.strip()[:120]}",
                raw_json={"addr": addr, "output": output.strip()[:300]},
                source_version=self.source_version_tag,
            ))
            return

        rtt_min  = min(rtts)
        rtt_max  = max(rtts)
        rtt_avg  = sum(rtts) / len(rtts)
        sent     = int(summary_m.group(1)) if summary_m else count
        received = int(summary_m.group(2)) if summary_m else len(rtts)
        loss_pct = int(summary_m.group(3)) if summary_m else 0

        sev = "INFO"
        if rtt_avg > err_ms or loss_pct >= 40:
            sev = "ERROR"
        elif rtt_avg > warn_ms or loss_pct >= 10:
            sev = "WARN"

        await self.bus.publish(Event.new(
            source="SYSFS",
            severity=sev,
            event_type="L2PING_RTT",
            device_addr=addr,
            summary=(
                f"l2ping {addr}: avg={rtt_avg:.1f}ms "
                f"min={rtt_min:.1f}ms max={rtt_max:.1f}ms "
                f"loss={loss_pct}%"
            ),
            raw_json={
                "addr": addr,
                "rtt_avg_ms":  round(rtt_avg, 2),
                "rtt_min_ms":  round(rtt_min, 2),
                "rtt_max_ms":  round(rtt_max, 2),
                "loss_pct":    loss_pct,
                "sent":        sent,
                "received":    received,
                "samples":     rtts,
            },
            source_version=self.source_version_tag,
            parser_version=f"l2ping-parser-{self.version}",
        ))
