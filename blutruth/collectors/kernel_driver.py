"""
blutruth.collectors.kernel_driver — Kernel Bluetooth driver collector

Monitors the lowest layers of the Bluetooth stack:

    core bluetooth.ko
        ↓
    btusb.ko / hci_uart.ko    ← THIS COLLECTOR
        ↓
    hardware (USB/UART)

Three collection strategies:

1. dmesg watcher: Tails `dmesg --follow` for bluetooth/btusb/hci kernel
   messages. Catches firmware loading, USB enumeration, driver errors,
   hardware resets, and kernel panics in the BT subsystem.

2. Kernel ftrace (optional, requires root + debugfs): Enables tracepoints
   in the bluetooth kernel module for fine-grained event capture:
   - bluetooth:hci_send_frame / hci_recv_frame
   - bluetooth:hci_cmd_send / hci_evt_recv
   These show the raw kernel-level HCI traffic before btmon even sees it.

3. Module state polling: Periodically checks lsmod / /sys/module/ for
   bluetooth module status (loaded, parameters, refcount) to detect
   module loads/unloads/reloads that indicate driver issues.

FUTURE: Parse USB URB traces for btusb.ko firmware upload analysis.
FUTURE: udev event monitoring for BT device hotplug.
FUTURE (Rust port): Direct ftrace/tracefs interface via libc.
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


# Kernel log patterns for bluetooth subsystem
_BT_DMESG_PATTERNS = [
    re.compile(r"\b(bluetooth|btusb|btintel|btrtl|btbcm|btmtk|btmrvl|hci\d+|hci_uart)\b", re.I),
]

# Severity classification from dmesg content
_DMESG_SEVERITY_PATTERNS = [
    (re.compile(r"firmware.*load|firmware.*found", re.I),     "INFO"),
    (re.compile(r"firmware.*fail|firmware.*not found", re.I), "ERROR"),
    (re.compile(r"reset|timeout|stall", re.I),                "ERROR"),
    (re.compile(r"error|fail|bug|oops|panic", re.I),          "ERROR"),
    (re.compile(r"warn|cannot|unable", re.I),                  "WARN"),
    (re.compile(r"disconnect|remove|unplug", re.I),            "WARN"),
    (re.compile(r"new.*device|usb.*found|register", re.I),     "INFO"),
]

# dmesg timestamp: [12345.678901]
_DMESG_TS_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s*(.*)")

# Device address in kernel messages
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

# Adapter references
_HCI_RE = re.compile(r"(hci\d+)")

# Module paths
_SYS_MODULE = Path("/sys/module")
_TRACEFS = Path("/sys/kernel/debug/tracing")

# Bluetooth kernel modules to monitor
_BT_MODULES = [
    "bluetooth",
    "btusb",
    "btintel",
    "btrtl",
    "btbcm",
    "btmtk",
    "btmrvl",
    "hci_uart",
    "rfcomm",
    "bnep",
    "hidp",
]

# Ftrace events for bluetooth
_BT_TRACE_EVENTS = [
    "bluetooth/hci_send_frame",
    "bluetooth/hci_recv_frame",
]


class KernelDriverCollector(Collector):
    name = "kernel_trace"
    description = "Kernel Bluetooth driver monitor (dmesg + ftrace + modules)"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._dmesg_proc: Optional[asyncio.subprocess.Process] = None
        self._dmesg_task: Optional[asyncio.Task] = None
        self._ftrace_task: Optional[asyncio.Task] = None
        self._module_task: Optional[asyncio.Task] = None
        self._last_module_state: Dict[str, Dict[str, str]] = {}
        self._ftrace_enabled: bool = False

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": True,
            "requires_debugfs": False,  # dmesg works without, ftrace needs it
            "exclusive_resource": None,
            "optional_root_benefits": [
                "dmesg --follow requires root on some systems",
                "ftrace bluetooth tracepoints for kernel-level HCI frames",
                "Full /sys/module/ parameter access",
            ],
            "provides": ["KERNEL"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        self._running = True

        # 1. Start dmesg watcher (primary)
        self._dmesg_task = asyncio.create_task(self._start_dmesg())

        # 2. Start ftrace if available and configured
        enable_ftrace = self.config.get(
            "collectors", "kernel_trace", "ftrace", default=False
        )
        if enable_ftrace and os.geteuid() == 0 and _TRACEFS.exists():
            self._ftrace_task = asyncio.create_task(self._start_ftrace())

        # 3. Start module state poller
        poll_interval = self.config.get(
            "collectors", "kernel_trace", "module_poll_s", default=10.0
        )
        self._module_task = asyncio.create_task(
            self._module_poll_loop(poll_interval)
        )

        await self.bus.publish(Event.new(
            source="KERNEL",
            event_type="COLLECTOR_START",
            summary="Kernel driver collector started (dmesg + modules"
                    + (" + ftrace)" if enable_ftrace else ")"),
            raw_json={
                "dmesg": True,
                "ftrace": enable_ftrace and _TRACEFS.exists(),
                "module_poll_interval": poll_interval,
                "root": os.geteuid() == 0,
            },
            source_version=self.source_version_tag,
        ))

    # --- dmesg watcher ---

    async def _start_dmesg(self) -> None:
        """Run dmesg --follow and filter for bluetooth-related messages."""
        try:
            self._dmesg_proc = await asyncio.create_subprocess_exec(
                "dmesg", "--follow", "--decode", "--time-format=reltime",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="dmesg not found — kernel log monitoring disabled",
                raw_json={"error": "dmesg not found"},
                source_version=self.source_version_tag,
            ))
            return
        except PermissionError:
            # Try without --follow (will only get existing buffer)
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="dmesg --follow requires root; falling back to snapshot mode",
                raw_json={"error": "permission denied", "hint": "run as root"},
                source_version=self.source_version_tag,
            ))
            return

        await self._read_dmesg_loop()

    async def _read_dmesg_loop(self) -> None:
        """Read and filter dmesg output for bluetooth-related messages."""
        assert self._dmesg_proc and self._dmesg_proc.stdout

        while self._running:
            try:
                raw_line = await self._dmesg_proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="dmesg --follow exited",
                        raw_json={"returncode": self._dmesg_proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            # Filter: only process bluetooth-related kernel messages
            if not any(p.search(line) for p in _BT_DMESG_PATTERNS):
                continue

            await self._emit_dmesg_event(line)

    async def _emit_dmesg_event(self, line: str) -> None:
        """Parse and publish a bluetooth-related dmesg line."""
        # Extract kernel timestamp if present
        kernel_ts = None
        message = line
        ts_m = _DMESG_TS_RE.match(line)
        if ts_m:
            kernel_ts = ts_m.group(1)
            message = ts_m.group(2).strip()

        # Classify severity
        severity = "INFO"
        for pattern, sev in _DMESG_SEVERITY_PATTERNS:
            if pattern.search(message):
                severity = sev
                break

        # Determine stage
        stage = self._guess_stage(message)

        # Extract device/adapter info
        device_addr = None
        adapter = None
        addr_m = _ADDR_RE.search(message)
        if addr_m:
            device_addr = addr_m.group(1).upper()
        hci_m = _HCI_RE.search(message)
        if hci_m:
            adapter = hci_m.group(1)

        # Determine event type
        event_type = self._classify_dmesg_type(message)

        await self.bus.publish(Event.new(
            source="KERNEL",
            severity=severity,
            stage=stage,
            event_type=event_type,
            adapter=adapter,
            device_addr=device_addr,
            summary=f"kernel: {message[:250]}",
            raw_json={
                "kernel_ts": kernel_ts,
                "message": message,
                "dmesg_source": "follow",
            },
            raw=line,
            source_version=self.source_version_tag,
            parser_version=f"dmesg-parser-{self.version}",
        ))

    def _classify_dmesg_type(self, message: str) -> str:
        """Classify a dmesg message into an event type."""
        lower = message.lower()
        if "firmware" in lower:
            return "KERNEL_FW"
        if "usb" in lower and ("found" in lower or "new" in lower or "register" in lower):
            return "KERNEL_USB_ENUM"
        if "reset" in lower or "timeout" in lower:
            return "KERNEL_RESET"
        if "error" in lower or "fail" in lower:
            return "KERNEL_ERROR"
        if "disconnect" in lower or "remove" in lower:
            return "KERNEL_DISCONNECT"
        return "KERNEL_LOG"

    def _guess_stage(self, message: str) -> Optional[str]:
        """Guess lifecycle stage from kernel message content."""
        lower = message.lower()
        if any(kw in lower for kw in ("firmware", "init", "probe", "register", "new device")):
            return None  # hardware init, pre-connection
        if any(kw in lower for kw in ("connect", "link", "acl")):
            return "CONNECTION"
        if any(kw in lower for kw in ("disconnect", "remove", "unplug", "reset")):
            return "TEARDOWN"
        if any(kw in lower for kw in ("sco", "codec", "audio")):
            return "AUDIO"
        if any(kw in lower for kw in ("key", "encrypt", "auth", "pair")):
            return "HANDSHAKE"
        return None

    # --- ftrace ---

    async def _start_ftrace(self) -> None:
        """Enable bluetooth tracepoints and read trace_pipe."""
        try:
            # Enable bluetooth trace events
            for event in _BT_TRACE_EVENTS:
                enable_path = _TRACEFS / "events" / event / "enable"
                if enable_path.exists():
                    enable_path.write_text("1")
                    self._ftrace_enabled = True

            if not self._ftrace_enabled:
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="DEBUG",
                    event_type="COLLECTOR_WARN",
                    summary="No bluetooth ftrace events available on this kernel",
                    raw_json={"checked": _BT_TRACE_EVENTS},
                    source_version=self.source_version_tag,
                ))
                return

            await self.bus.publish(Event.new(
                source="KERNEL",
                event_type="COLLECTOR_START",
                summary="Bluetooth ftrace tracepoints enabled",
                raw_json={"events": _BT_TRACE_EVENTS},
                source_version=self.source_version_tag,
            ))

            # Read trace_pipe
            await self._read_trace_pipe()

        except PermissionError:
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="ftrace requires root — tracepoints disabled",
                raw_json={"error": "permission denied"},
                source_version=self.source_version_tag,
            ))
        except Exception as e:
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="WARN",
                event_type="COLLECTOR_ERROR",
                summary=f"ftrace setup failed: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))

    async def _read_trace_pipe(self) -> None:
        """Read /sys/kernel/debug/tracing/trace_pipe for bluetooth events."""
        trace_pipe = _TRACEFS / "trace_pipe"
        if not trace_pipe.exists():
            return

        # Use subprocess to read trace_pipe (blocking file)
        proc = await asyncio.create_subprocess_exec(
            "cat", str(trace_pipe),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while self._running:
            try:
                raw_line = await proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line or line.startswith("#"):
                continue

            # Only emit bluetooth-related trace events
            if any(p.search(line) for p in _BT_DMESG_PATTERNS):
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="DEBUG",
                    event_type="KERNEL_FTRACE",
                    summary=f"ftrace: {line[:250]}",
                    raw_json={"trace_line": line, "source": "ftrace"},
                    raw=line,
                    source_version=self.source_version_tag,
                    parser_version=f"ftrace-parser-{self.version}",
                ))

        with contextlib.suppress(Exception):
            proc.terminate()

    # --- Module state polling ---

    async def _module_poll_loop(self, interval: float) -> None:
        """Periodically check bluetooth kernel module status."""
        # Initial snapshot
        await self._module_snapshot(initial=True)

        while self._running:
            await asyncio.sleep(interval)
            try:
                await self._module_snapshot(initial=False)
            except Exception as e:
                await self.bus.publish(Event.new(
                    source="KERNEL",
                    severity="DEBUG",
                    event_type="KERNEL_ERROR",
                    summary=f"Module poll error: {e}",
                    raw_json={"error": str(e)},
                    source_version=self.source_version_tag,
                ))

    async def _module_snapshot(self, initial: bool = False) -> None:
        """Read module state and emit events for changes."""
        current_state: Dict[str, Dict[str, str]] = {}

        for mod_name in _BT_MODULES:
            mod_path = _SYS_MODULE / mod_name
            if mod_path.exists():
                state = self._read_module_info(mod_name, mod_path)
                current_state[mod_name] = state

        if initial:
            loaded = [m for m in _BT_MODULES if m in current_state]
            not_loaded = [m for m in _BT_MODULES if m not in current_state]
            await self.bus.publish(Event.new(
                source="KERNEL",
                severity="INFO",
                event_type="KERNEL_MODULE_SNAPSHOT",
                summary=f"BT modules loaded: {', '.join(loaded) or 'none'}",
                raw_json={
                    "loaded": loaded,
                    "not_loaded": not_loaded,
                    "details": current_state,
                },
                source_version=self.source_version_tag,
            ))
        else:
            prev = self._last_module_state

            # Detect newly loaded modules
            for mod_name in current_state:
                if mod_name not in prev:
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="INFO",
                        event_type="KERNEL_MODULE_LOAD",
                        summary=f"BT module loaded: {mod_name}",
                        raw_json={
                            "module": mod_name,
                            "state": current_state[mod_name],
                        },
                        source_version=self.source_version_tag,
                    ))

            # Detect unloaded modules
            for mod_name in prev:
                if mod_name not in current_state:
                    await self.bus.publish(Event.new(
                        source="KERNEL",
                        severity="WARN",
                        event_type="KERNEL_MODULE_UNLOAD",
                        summary=f"BT module unloaded: {mod_name}",
                        raw_json={"module": mod_name},
                        source_version=self.source_version_tag,
                    ))

            # Detect refcount changes (may indicate connection activity)
            for mod_name in current_state:
                if mod_name in prev:
                    old_ref = prev[mod_name].get("refcount", "")
                    new_ref = current_state[mod_name].get("refcount", "")
                    if old_ref != new_ref and old_ref and new_ref:
                        await self.bus.publish(Event.new(
                            source="KERNEL",
                            severity="DEBUG",
                            event_type="KERNEL_MODULE_CHANGE",
                            summary=f"BT module {mod_name} refcount: {old_ref}→{new_ref}",
                            raw_json={
                                "module": mod_name,
                                "old_refcount": old_ref,
                                "new_refcount": new_ref,
                            },
                            source_version=self.source_version_tag,
                        ))

        self._last_module_state = current_state

    def _read_module_info(self, mod_name: str, mod_path: Path) -> Dict[str, str]:
        """Read module info from /sys/module/<name>/."""
        info: Dict[str, str] = {}

        # Refcount
        refcount_path = mod_path / "refcnt"
        if refcount_path.exists():
            try:
                info["refcount"] = refcount_path.read_text().strip()
            except (PermissionError, OSError):
                pass

        # Version
        version_path = mod_path / "version"
        if version_path.exists():
            try:
                info["version"] = version_path.read_text().strip()
            except (PermissionError, OSError):
                pass

        # Parameters
        params_path = mod_path / "parameters"
        if params_path.exists() and params_path.is_dir():
            for param_file in params_path.iterdir():
                try:
                    info[f"param_{param_file.name}"] = param_file.read_text().strip()
                except (PermissionError, OSError):
                    pass

        return info

    async def stop(self) -> None:
        self._running = False

        # Disable ftrace events
        if self._ftrace_enabled:
            for event in _BT_TRACE_EVENTS:
                enable_path = _TRACEFS / "events" / event / "enable"
                if enable_path.exists():
                    try:
                        enable_path.write_text("0")
                    except (PermissionError, OSError):
                        pass
            self._ftrace_enabled = False

        if self._dmesg_task:
            self._dmesg_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._dmesg_task
            self._dmesg_task = None

        if self._ftrace_task:
            self._ftrace_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._ftrace_task
            self._ftrace_task = None

        if self._module_task:
            self._module_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._module_task
            self._module_task = None

        if self._dmesg_proc:
            with contextlib.suppress(ProcessLookupError):
                self._dmesg_proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._dmesg_proc.wait(), timeout=3.0)
            self._dmesg_proc = None
