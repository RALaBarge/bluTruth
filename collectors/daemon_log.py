"""
blutruth.collectors.daemon_log — bluetoothd log collector

Default mode: Follow logs via `journalctl -u bluetooth -f -o json`.
  Non-disruptive, production-friendly, works with existing system config.

Advanced mode: Stop system service, run `bluetoothd -n -d` under our control
  for maximum verbosity. Opt-in only, gated by config. Restores service on stop.

FUTURE: Parse bluetoothd debug output for structured fields (profile names,
        device addresses, internal state transitions, rejection reasons).
FUTURE (Rust port): Read journal directly via libsystemd-rs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Any, Dict, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# Patterns for extracting info from bluetoothd log lines
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_ADAPTER_RE = re.compile(r"(hci\d+)")

# Syslog priority → severity mapping
_PRIORITY_MAP = {
    0: "ERROR", 1: "ERROR", 2: "ERROR", 3: "ERROR",  # emerg..err
    4: "WARN",                                          # warning
    5: "INFO", 6: "INFO",                               # notice, info
    7: "DEBUG",                                          # debug
}

# Keywords that indicate specific stages
_STAGE_KEYWORDS = {
    "DISCOVERY": ["discovery", "scan", "inquiry", "advertising"],
    "CONNECTION": ["connect", "link", "acl", "accept", "reject"],
    "HANDSHAKE": ["pair", "auth", "encrypt", "smp", "key", "bond"],
    "AUDIO": ["a2dp", "avrcp", "hfp", "sco", "codec", "media", "audio", "transport"],
    "TEARDOWN": ["disconnect", "remove", "release", "drop"],
    "DATA": ["gatt", "att", "characteristic", "service", "read", "write", "notify"],
}


def _guess_stage(text: str) -> Optional[str]:
    lower = text.lower()
    for stage, keywords in _STAGE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return stage
    return None


class DaemonLogCollector(Collector):
    name = "journalctl"
    description = "bluetoothd log capture via journalctl"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._mode: str = "journal"  # "journal" or "managed"
        self._managed_service_was_active: bool = False

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [
                "Advanced mode: run bluetoothd -n -d for full debug output",
            ],
            "provides": ["DAEMON"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        advanced = self.config.get("collectors", "advanced_bluetoothd", "enabled", default=False)

        if advanced:
            await self._start_managed()
        else:
            await self._start_journal()

    async def _start_journal(self) -> None:
        """Default mode: follow journalctl."""
        self._mode = "journal"
        unit = self.config.get("collectors", "journalctl", "unit", default="bluetooth")
        fmt = self.config.get("collectors", "journalctl", "format", default="json")

        args = ["journalctl", "-u", unit, "-f", "--no-pager"]
        if fmt == "json":
            args.extend(["-o", "json"])

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            await self.bus.publish(Event.new(
                source="DAEMON",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary="journalctl not found — systemd required for default log mode",
                raw_json={"error": "journalctl not found"},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._task = asyncio.create_task(self._read_journal_loop(fmt))

        await self.bus.publish(Event.new(
            source="DAEMON",
            event_type="COLLECTOR_START",
            summary=f"Daemon log collector started (journalctl -u {unit} -o {fmt})",
            raw_json={"mode": "journal", "unit": unit, "format": fmt},
            source_version=self.source_version_tag,
        ))

    async def _start_managed(self) -> None:
        """Advanced mode: stop system service, run bluetoothd -n -d."""
        self._mode = "managed"
        bt_path = self.config.get(
            "collectors", "advanced_bluetoothd", "bluetoothd_path",
            default="/usr/lib/bluetooth/bluetoothd",
        )

        await self.bus.publish(Event.new(
            source="DAEMON",
            severity="WARN",
            event_type="COLLECTOR_WARN",
            summary="Advanced mode: stopping system bluetooth service for debug logging",
            raw_json={"mode": "managed", "bluetoothd_path": bt_path},
            source_version=self.source_version_tag,
        ))

        # Stop system service
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", "--quiet", "bluetooth",
            )
            await proc.wait()
            self._managed_service_was_active = (proc.returncode == 0)

            if self._managed_service_was_active:
                proc = await asyncio.create_subprocess_exec(
                    "systemctl", "stop", "bluetooth",
                )
                await proc.wait()
                await asyncio.sleep(1)
        except Exception as e:
            await self.bus.publish(Event.new(
                source="DAEMON",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary=f"Failed to stop bluetooth.service: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))
            return

        # Launch managed bluetoothd
        try:
            self._proc = await asyncio.create_subprocess_exec(
                bt_path, "-n", "-d",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as e:
            # Restore service on failure
            await self._restore_service()
            await self.bus.publish(Event.new(
                source="DAEMON",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary=f"Failed to launch managed bluetoothd: {e}",
                raw_json={"error": str(e), "path": bt_path},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._task = asyncio.create_task(self._read_managed_loop())

        await self.bus.publish(Event.new(
            source="DAEMON",
            event_type="COLLECTOR_START",
            summary=f"Managed bluetoothd started with debug logging (PID {self._proc.pid})",
            raw_json={"mode": "managed", "pid": self._proc.pid, "path": bt_path},
            source_version=self.source_version_tag,
        ))

    async def _read_journal_loop(self, fmt: str) -> None:
        """Read and parse journalctl output."""
        assert self._proc and self._proc.stdout

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                await asyncio.sleep(0.1)
                continue

            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            if fmt == "json":
                await self._parse_journal_json(line)
            else:
                await self._parse_plain_line(line)

    async def _parse_journal_json(self, line: str) -> None:
        """Parse a journalctl JSON line."""
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            await self._parse_plain_line(line)
            return

        msg = obj.get("MESSAGE", "")
        if isinstance(msg, list):
            # journalctl sometimes returns message as byte array
            msg = bytes(msg).decode("utf-8", errors="replace")

        priority = obj.get("PRIORITY", "6")
        try:
            severity = _PRIORITY_MAP.get(int(priority), "INFO")
        except (ValueError, TypeError):
            severity = "INFO"

        stage = _guess_stage(msg)
        device_addr = None
        adapter = None

        addr_m = _ADDR_RE.search(msg)
        if addr_m:
            device_addr = addr_m.group(1).upper()
        adapter_m = _ADAPTER_RE.search(msg)
        if adapter_m:
            adapter = adapter_m.group(1)

        await self.bus.publish(Event.new(
            source="DAEMON",
            severity=severity,
            stage=stage,
            event_type="LOG",
            adapter=adapter,
            device_addr=device_addr,
            summary=msg[:300] if msg else "bluetooth log",
            raw_json={"journal": {k: v for k, v in obj.items() if isinstance(v, (str, int, float))}},
            raw=line,
            source_version=self.source_version_tag,
            parser_version=f"daemon-parser-{self.version}",
        ))

    async def _parse_plain_line(self, line: str) -> None:
        """Parse a plain text log line (non-JSON journalctl or managed stderr)."""
        severity = "INFO"
        if "error" in line.lower():
            severity = "ERROR"
        elif "warn" in line.lower():
            severity = "WARN"
        elif "debug" in line.lower():
            severity = "DEBUG"

        stage = _guess_stage(line)
        device_addr = None
        adapter = None

        addr_m = _ADDR_RE.search(line)
        if addr_m:
            device_addr = addr_m.group(1).upper()
        adapter_m = _ADAPTER_RE.search(line)
        if adapter_m:
            adapter = adapter_m.group(1)

        await self.bus.publish(Event.new(
            source="DAEMON",
            severity=severity,
            stage=stage,
            event_type="LOG",
            adapter=adapter,
            device_addr=device_addr,
            summary=line[:300],
            raw_json={"line": line},
            raw=line,
            source_version=self.source_version_tag,
            parser_version=f"daemon-parser-{self.version}",
        ))

    async def _read_managed_loop(self) -> None:
        """Read managed bluetoothd stdout/stderr."""
        assert self._proc and self._proc.stdout

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="DAEMON",
                        severity="WARN",
                        event_type="COLLECTOR_WARN",
                        summary="Managed bluetoothd exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").strip()
            if line:
                await self._parse_plain_line(line)

    async def _restore_service(self) -> None:
        """Restore the system bluetooth service if we stopped it."""
        if self._managed_service_was_active:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "systemctl", "start", "bluetooth",
                )
                await proc.wait()
                await self.bus.publish(Event.new(
                    source="DAEMON",
                    event_type="LOG",
                    summary="System bluetooth.service restored",
                    raw_json={"action": "service_restored"},
                    source_version=self.source_version_tag,
                ))
            except Exception as e:
                await self.bus.publish(Event.new(
                    source="DAEMON",
                    severity="ERROR",
                    event_type="COLLECTOR_ERROR",
                    summary=f"Failed to restore bluetooth.service: {e}",
                    raw_json={"error": str(e)},
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
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            self._proc = None

        # Restore service if we were in managed mode
        if self._mode == "managed":
            await self._restore_service()
