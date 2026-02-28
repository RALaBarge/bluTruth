"""
blutruth.collectors.hci — HCI event collector via btmon

Runs btmon as a subprocess and parses its output into structured events
with severity classification, lifecycle stage mapping, and device context.

The HCI monitor socket is an exclusive resource — only one consumer can
own it at a time. This collector owns it and fans out via the event bus.

FUTURE: Parse btmon binary output (btsnoop) directly for richer data.
FUTURE: Simultaneous btsnoop file writing for Wireshark export.
FUTURE (Rust port): Open HCI_MONITOR socket directly via libc, no btmon subprocess.
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


# --- HCI event classification ---

# Opcode/event → (severity, stage) mapping for common HCI traffic
_HCI_CLASSIFICATION: Dict[str, tuple] = {
    # Commands
    "Inquiry":                          ("INFO",  "DISCOVERY"),
    "Inquiry Cancel":                   ("INFO",  "DISCOVERY"),
    "Create Connection":                ("INFO",  "CONNECTION"),
    "Disconnect":                       ("INFO",  "TEARDOWN"),
    "Accept Connection Request":        ("INFO",  "CONNECTION"),
    "Reject Connection Request":        ("WARN",  "CONNECTION"),
    "Link Key Request Reply":           ("INFO",  "HANDSHAKE"),
    "Link Key Request Negative Reply":  ("WARN",  "HANDSHAKE"),
    "Authentication Requested":         ("INFO",  "HANDSHAKE"),
    "Set Connection Encryption":        ("INFO",  "HANDSHAKE"),
    "Remote Name Request":              ("INFO",  "DISCOVERY"),
    "LE Set Scan Enable":               ("INFO",  "DISCOVERY"),
    "LE Set Scan Parameters":           ("INFO",  "DISCOVERY"),
    "LE Create Connection":             ("INFO",  "CONNECTION"),
    "LE Set Advertising Enable":        ("INFO",  "DISCOVERY"),
    "LE Extended Create Connection":    ("INFO",  "CONNECTION"),
    "Setup Synchronous Connection":     ("INFO",  "AUDIO"),
    "Enhanced Setup Synchronous Connection": ("INFO", "AUDIO"),

    # Events
    "Inquiry Complete":                 ("INFO",  "DISCOVERY"),
    "Inquiry Result":                   ("INFO",  "DISCOVERY"),
    "Inquiry Result with RSSI":         ("INFO",  "DISCOVERY"),
    "Extended Inquiry Result":          ("INFO",  "DISCOVERY"),
    "Connection Complete":              ("INFO",  "CONNECTION"),
    "Connection Request":               ("INFO",  "CONNECTION"),
    "Disconnection Complete":           ("WARN",  "TEARDOWN"),
    "Authentication Complete":          ("INFO",  "HANDSHAKE"),
    "Encryption Change":                ("INFO",  "HANDSHAKE"),
    "Remote Name Request Complete":     ("INFO",  "DISCOVERY"),
    "Command Complete":                 ("DEBUG", None),
    "Command Status":                   ("DEBUG", None),
    "Role Change":                      ("INFO",  "CONNECTION"),
    "Number of Completed Packets":      ("DEBUG", "DATA"),
    "Link Key Notification":            ("INFO",  "HANDSHAKE"),
    "Link Key Request":                 ("INFO",  "HANDSHAKE"),
    "LE Connection Complete":           ("INFO",  "CONNECTION"),
    "LE Enhanced Connection Complete":  ("INFO",  "CONNECTION"),
    "LE Advertising Report":            ("DEBUG", "DISCOVERY"),
    "LE Extended Advertising Report":   ("DEBUG", "DISCOVERY"),
    "Synchronous Connection Complete":  ("INFO",  "AUDIO"),
    "Synchronous Connection Changed":   ("INFO",  "AUDIO"),

    # L2CAP signaling
    "L2CAP: Connection Request":        ("INFO",  "CONNECTION"),
    "L2CAP: Connection Response":       ("INFO",  "CONNECTION"),
    "L2CAP: Configuration Request":     ("INFO",  "HANDSHAKE"),
    "L2CAP: Configuration Response":    ("INFO",  "HANDSHAKE"),
    "L2CAP: Disconnection Request":     ("INFO",  "TEARDOWN"),

    # SMP
    "SMP: Pairing Request":             ("INFO",  "HANDSHAKE"),
    "SMP: Pairing Response":            ("INFO",  "HANDSHAKE"),
    "SMP: Pairing Confirm":             ("INFO",  "HANDSHAKE"),
    "SMP: Pairing Random":              ("INFO",  "HANDSHAKE"),
    "SMP: Pairing Failed":              ("ERROR", "HANDSHAKE"),
    "SMP: Encryption Information":      ("INFO",  "HANDSHAKE"),
    "SMP: Security Request":            ("INFO",  "HANDSHAKE"),
}

# Error-indicating patterns in btmon output
_ERROR_PATTERNS = [
    (re.compile(r"Status:\s+(0x[0-9a-f]{2})\s+\((\w.+?)\)", re.I), "ERROR"),
    (re.compile(r"Reason:\s+(0x[0-9a-f]{2})\s+\((\w.+?)\)", re.I), "WARN"),
    (re.compile(r"Error:\s+(.+)", re.I), "ERROR"),
]

# Device address extraction
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

# btmon header line: direction + event name
_HEADER_RE = re.compile(
    r"^[<>@]\s+"                       # direction marker
    r"(?:HCI\s+)?"
    r"((?:Command|Event|ACL|SCO).*?)$"  # capture the event description
)

# btmon timestamp line
_TS_RE = re.compile(r"^#\s+\d+\.\d+$")


class HciCollector(Collector):
    name = "hci"
    description = "HCI event capture via btmon"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,  # btmon works without root on most systems
            "requires_debugfs": False,
            "exclusive_resource": "hci_monitor_socket",
            "optional_root_benefits": [
                "Access to all HCI channels including vendor-specific",
            ],
            "provides": ["HCI"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        try:
            self._proc = await asyncio.create_subprocess_exec(
                "btmon", "-T",  # -T for timestamps
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            await self.bus.publish(Event.new(
                source="HCI",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary="btmon not found — install bluez-utils or bluez",
                raw_json={"error": "btmon not found in PATH"},
                source_version=self.source_version_tag,
            ))
            return

        self._running = True
        self._task = asyncio.create_task(self._read_loop())

        await self.bus.publish(Event.new(
            source="HCI",
            event_type="COLLECTOR_START",
            summary="HCI collector started (btmon)",
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
        """Read btmon stdout, accumulate multi-line events, parse and publish."""
        assert self._proc and self._proc.stdout

        current_block: list[str] = []
        current_header: Optional[str] = None

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                # btmon exited
                if self._running:
                    await self.bus.publish(Event.new(
                        source="HCI",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="btmon process exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()

            # Skip empty lines and timestamp-only lines
            if not line or _TS_RE.match(line):
                continue

            # Detect new event block (starts with direction marker)
            header_match = _HEADER_RE.match(line)
            if header_match:
                # Flush previous block
                if current_header and current_block:
                    await self._emit_event(current_header, current_block)
                current_header = header_match.group(1).strip()
                current_block = [line]
            else:
                # Continuation of current block
                current_block.append(line)

        # Flush last block
        if current_header and current_block:
            await self._emit_event(current_header, current_block)

    async def _emit_event(self, header: str, block: list[str]) -> None:
        """Parse a complete btmon event block and publish."""
        full_text = "\n".join(block)

        # Classify
        severity, stage = self._classify(header, full_text)
        event_type = self._event_type(header)

        # Extract device address
        device_addr = None
        for line in block:
            m = _ADDR_RE.search(line)
            if m:
                device_addr = m.group(1).upper()
                break

        # Check for error status codes — upgrade severity
        for pattern, err_sev in _ERROR_PATTERNS:
            m = pattern.search(full_text)
            if m:
                # Don't downgrade severity
                from blutruth.events import SEVERITY_ORDER
                if SEVERITY_ORDER.get(err_sev, 0) > SEVERITY_ORDER.get(severity, 0):
                    severity = err_sev
                break

        # Build summary
        summary = header[:200]

        await self.bus.publish(Event.new(
            source="HCI",
            severity=severity,
            stage=stage,
            event_type=event_type,
            summary=summary,
            raw_json={"header": header, "lines": block},
            raw=full_text,
            device_addr=device_addr,
            source_version=self.source_version_tag,
            parser_version=f"hci-parser-{self.version}",
        ))

    def _classify(self, header: str, text: str) -> tuple:
        """Return (severity, stage) for a btmon event."""
        for key, (sev, stg) in _HCI_CLASSIFICATION.items():
            if key in header:
                return (sev, stg)
        # Fallback
        if "Error" in text or "Failed" in text:
            return ("ERROR", None)
        return ("INFO", None)

    def _event_type(self, header: str) -> str:
        """Map btmon header to event_type tag."""
        h = header.lower()
        if "command" in h and "complete" not in h and "status" not in h:
            return "HCI_CMD"
        if "event" in h or "complete" in h or "status" in h:
            return "HCI_EVT"
        if "acl" in h:
            return "HCI_ACL"
        if "sco" in h:
            return "HCI_SCO"
        return "HCI_OTHER"
