"""
blutruth.collectors.hci — HCI event collector via btmon

Runs btmon as a subprocess and parses its output into structured events
with severity classification, lifecycle stage mapping, and device context.

The HCI monitor socket is an exclusive resource — only one consumer can
own it at a time. This collector owns it and fans out via the event bus.

btmon output format (v5.72, piped):
  = New Index: 7C:10:C9:75:8D:37 (Primary,USB,hci0)         [hci0] 0.000001
  < HCI Command: LE Set Scan Parameters (0x200b) plen 7      [hci0] 1.234567
          Type: Passive (0x00)
          ...
  > HCI Event: LE Meta Event (0x3e) plen 12                  [hci0] 1.345678
          LE Connection Complete (0x01)
          ...
  @ MGMT Event: Device Connected (0x000b) plen 37           {0x0001} [hci0]

Direction markers: < (host->controller) > (controller->host) = (system) @ (mgmt)
Some lines get btmon[PID]: prefix when piped.
NOTE: -T flag causes buffer overflow crash on btmon 5.72 when piped.

RSSI extraction: raw_json["rssi_dbm"] is populated whenever btmon reports an RSSI
value (Inquiry Result with RSSI, LE Advertising Report, Read RSSI command complete).
Active-connection RSSI (Read RSSI) below rssi_warn_dbm/-85 thresholds bumps severity.

Disconnect reason extraction: raw_json["reason_code"] + ["reason_name"] are
populated for Disconnection Complete events, feeding the history disconnect analysis.

FUTURE: Parse btmon binary output (btsnoop) directly for richer data.
FUTURE: Simultaneous btsnoop file writing for Wireshark export.
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

    # MGMT events
    "Device Connected":                 ("INFO",  "CONNECTION"),
    "Device Disconnected":              ("WARN",  "TEARDOWN"),
    "Connect Failed":                   ("ERROR", "CONNECTION"),
    "New Link Key":                     ("INFO",  "HANDSHAKE"),
    "New Long Term Key":                ("INFO",  "HANDSHAKE"),
    "Device Found":                     ("DEBUG", "DISCOVERY"),
    "Discovering":                      ("INFO",  "DISCOVERY"),
    "Device Blocked":                   ("WARN",  "CONNECTION"),
    "Device Unblocked":                 ("INFO",  "CONNECTION"),
    "New IRK":                          ("INFO",  "HANDSHAKE"),
    "New CSRK":                         ("INFO",  "HANDSHAKE"),
    "New Settings":                     ("INFO",  None),
    "Class Of Device Changed":          ("INFO",  "DISCOVERY"),

    # Index events
    "New Index":                        ("INFO",  None),
    "Open Index":                       ("INFO",  None),
    "Delete Index":                     ("WARN",  None),
    "Close Index":                      ("WARN",  None),

    "Hardware Error":                   ("ERROR", None),
    "Encryption Key Refresh Complete":  ("INFO",  "HANDSHAKE"),
    "IO Capability Request":            ("INFO",  "HANDSHAKE"),
    "IO Capability Response":           ("INFO",  "HANDSHAKE"),
    "IO Capability Request Reply":      ("INFO",  "HANDSHAKE"),
}

# Error-indicating patterns
_ERROR_PATTERNS = [
    (re.compile(r"Status:\s+(0x[0-9a-f]{2})\s+\((\w.+?)\)", re.I), "ERROR"),
    (re.compile(r"Reason:\s+(0x[0-9a-f]{2})\s+\((\w.+?)\)", re.I), "WARN"),
    (re.compile(r"Error:\s+(.+)", re.I), "ERROR"),
]

# RSSI extraction: "RSSI: -60 dBm (0xc4)" or "RSSI: -70 dBm"
_RSSI_RE = re.compile(r"RSSI:\s*(-?\d+)\s*dBm", re.I)

# Disconnect reason: "Reason: Connection Timeout (0x08)"
_REASON_RE = re.compile(r"Reason:\s+(.+?)\s*\(0x([0-9a-f]{2})\)", re.I)

# Connection handle number: "Handle: 256"
_HANDLE_RE = re.compile(r"\bHandle:\s*(\d+)")

# Encryption key size: "Key size: 16" or "key size: 7"
_KEY_SIZE_RE = re.compile(r"[Kk]ey\s+[Ss]ize:\s*(\d+)")

# IO capability type: "Capability: DisplayYesNo (0x01)"
_IO_CAP_RE = re.compile(r"^\s+Capability:\s+(.+?)\s*\(0x([0-9a-f]{2})\)", re.MULTILINE | re.I)

# Device address extraction
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

# Adapter tag: [hci0]
_ADAPTER_RE = re.compile(r"\[(hci\d+)\]")

# btmon header line — all four direction markers
# Handles optional btmon[PID]: prefix from piped output
_HEADER_RE = re.compile(
    r"^(?:btmon\[\d+\]:\s*)?"          # optional btmon[PID]: prefix
    r"([<>=@])\s+"                      # direction marker (captured)
    r"(.+?)"                            # event description (captured)
    r"\s+(?:\{0x[0-9a-f]+\}\s*)?"      # optional mgmt handle {0x0001}
    r"\[hci\d+\]"                       # [hciN] adapter tag
)

# Continuation lines: indented content belonging to current block
_CONTINUATION_RE = re.compile(r"^\s{2,}")

# btmon info lines to skip
_SKIP_RE = re.compile(
    r"^(?:btmon\[\d+\]:\s*)?=\s+Note:|"
    r"^Bluetooth monitor ver"
)


class HciCollector(Collector):
    name = "hci"
    description = "HCI event capture via btmon"
    version = "0.2.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._handle_addr: Dict[int, str] = {}

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
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
            # NOTE: Do NOT use -T flag — causes buffer overflow crash
            # in btmon 5.72 when stdout is piped.
            self._proc = await asyncio.create_subprocess_exec(
                "btmon",
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
            summary=f"HCI collector started (btmon PID {self._proc.pid})",
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
        current_direction: Optional[str] = None

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
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

            # Skip empty lines and info lines
            if not line or _SKIP_RE.match(line):
                continue

            # New event block?
            header_match = _HEADER_RE.match(line)
            if header_match:
                # Flush previous block
                if current_header and current_block:
                    await self._emit_event(current_direction, current_header, current_block)
                current_direction = header_match.group(1)
                current_header = header_match.group(2).strip()
                current_block = [line]
            elif _CONTINUATION_RE.match(line) and current_header:
                # Continuation of current block
                current_block.append(line)
            else:
                # Unrecognized — flush current block and emit standalone
                if current_header and current_block:
                    await self._emit_event(current_direction, current_header, current_block)
                    current_header = None
                    current_direction = None
                    current_block = []

        # Flush last block
        if current_header and current_block:
            await self._emit_event(current_direction, current_header, current_block)

    async def _emit_event(self, direction: Optional[str], header: str, block: list[str]) -> None:
        """Parse a complete btmon event block and publish."""
        full_text = "\n".join(block)

        severity, stage = self._classify(header, full_text)
        event_type = self._event_type(direction, header)

        # Override: Authentication Complete with error → AUTH_FAILURE
        # btmon format: "Status: Authentication Failure (0x05)" (text first, hex in parens)
        if event_type == "AUTH_COMPLETE":
            import re as _re
            _fail_re = _re.compile(r"Status:\s+(?!Success)[^\(]+\(0x(?!00)[0-9a-f]{2}\)", _re.I)
            if _fail_re.search(full_text):
                event_type = "AUTH_FAILURE"

        # Extract adapter
        adapter = None
        adapter_m = _ADAPTER_RE.search(block[0] if block else "")
        if adapter_m:
            adapter = adapter_m.group(1)

        # Extract device address from body lines (skip adapter addr in header)
        device_addr = None
        for line in block[1:]:  # skip header line
            m = _ADDR_RE.search(line)
            if m:
                device_addr = m.group(1).upper()
                break
        # Fallback: check header for non-index events
        if not device_addr and "Index" not in header:
            m = _ADDR_RE.search(block[0] if block else "")
            if m:
                device_addr = m.group(1).upper()

        # Extract connection handle (first one in block)
        handle = None
        handle_m = _HANDLE_RE.search(full_text)
        if handle_m:
            handle = int(handle_m.group(1))

        # Handle → device_addr mapping
        # Store on connection complete; look up on handle-only events; remove on disconnect
        if handle is not None:
            if "Connection Complete" in header and device_addr:
                self._handle_addr[handle] = device_addr
            elif device_addr is None:
                device_addr = self._handle_addr.get(handle)
            if "Disconnection Complete" in header:
                self._handle_addr.pop(handle, None)

        # Check for error status codes
        for pattern, err_sev in _ERROR_PATTERNS:
            m = pattern.search(full_text)
            if m:
                from blutruth.events import SEVERITY_ORDER
                if SEVERITY_ORDER.get(err_sev, 0) > SEVERITY_ORDER.get(severity, 0):
                    severity = err_sev
                break

        # Extract RSSI if present
        rssi_dbm = None
        rssi_m = _RSSI_RE.search(full_text)
        if rssi_m:
            rssi_dbm = int(rssi_m.group(1))
            # Only escalate severity for active-connection RSSI (Read RSSI command),
            # not discovery/advertising RSSI (which being low is perfectly normal).
            if "Read RSSI" in header:
                from blutruth.events import SEVERITY_ORDER
                rssi_warn = int(self.config.get("collectors", "hci", "rssi_warn_dbm", default=-75))
                rssi_error = int(self.config.get("collectors", "hci", "rssi_error_dbm", default=-85))
                if rssi_dbm <= rssi_error:
                    if SEVERITY_ORDER.get("ERROR", 0) > SEVERITY_ORDER.get(severity, 0):
                        severity = "ERROR"
                elif rssi_dbm <= rssi_warn:
                    if SEVERITY_ORDER.get("WARN", 0) > SEVERITY_ORDER.get(severity, 0):
                        severity = "WARN"

        # Extract disconnect reason if present
        reason_code = None
        reason_name = None
        reason_m = _REASON_RE.search(full_text)
        if reason_m:
            reason_name = reason_m.group(1).strip()
            # Normalize compound reason names: "LMP Response Timeout / LL Response Timeout" → "LMP Response Timeout"
            reason_name = reason_name.split(" / ")[0].strip()
            reason_code = int(reason_m.group(2), 16)

        # Extract encryption key size if present (KNOB attack indicator)
        key_size = None
        key_m = _KEY_SIZE_RE.search(full_text)
        if key_m:
            key_size = int(key_m.group(1))
            from blutruth.events import SEVERITY_ORDER
            if key_size < 7:
                # Definitely compromised — key entropy too low to be accidental
                if SEVERITY_ORDER.get("ERROR", 0) > SEVERITY_ORDER.get(severity, 0):
                    severity = "ERROR"
            elif key_size < 16:
                # Reduced key size — possible KNOB attack in progress
                if SEVERITY_ORDER.get("WARN", 0) > SEVERITY_ORDER.get(severity, 0):
                    severity = "WARN"

        # Extract IO capability type if present (SSP downgrade detection)
        io_capability = None
        io_cap_m = _IO_CAP_RE.search(full_text)
        if io_cap_m:
            io_capability = io_cap_m.group(1).strip()

        # Direction arrow for summary
        dir_label = {"<": "\u2192", ">": "\u2190", "=": "=", "@": "@"}.get(direction, "?")
        summary = f"{dir_label} {header}"[:200]

        raw_json: Dict[str, Any] = {
            "direction": direction,
            "header": header,
            "lines": block,
        }
        if handle is not None:
            raw_json["handle"] = handle
        if rssi_dbm is not None:
            raw_json["rssi_dbm"] = rssi_dbm
        if reason_code is not None:
            raw_json["reason_code"] = f"0x{reason_code:02X}"
            raw_json["reason_name"] = reason_name
        if key_size is not None:
            raw_json["key_size"] = key_size
            if key_size < 16:
                raw_json["knob_risk"] = "HIGH" if key_size < 7 else "POSSIBLE"
        if io_capability is not None:
            raw_json["io_capability"] = io_capability

        await self.bus.publish(Event.new(
            source="HCI",
            severity=severity,
            stage=stage,
            event_type=event_type,
            summary=summary,
            raw_json=raw_json,
            raw=full_text,
            adapter=adapter,
            device_addr=device_addr,
            source_version=self.source_version_tag,
            parser_version=f"hci-parser-{self.version}",
        ))

    def _classify(self, header: str, text: str) -> tuple:
        """Return (severity, stage) for a btmon event."""
        for key, (sev, stg) in _HCI_CLASSIFICATION.items():
            if key in header:
                return (sev, stg)
        if "Error" in text or "Failed" in text:
            return ("ERROR", None)
        return ("INFO", None)

    def _event_type(self, direction: Optional[str], header: str) -> str:
        """Map btmon direction + header to event_type tag.

        Specific types are checked first (for rule matching) then direction-based
        fallbacks. Caller may override AUTH_COMPLETE → AUTH_FAILURE after severity
        is determined.
        """
        h = header.lower()

        # Specific types checked before direction so MGMT events also get them
        if "disconnection complete" in h:
            return "DISCONNECT"
        if "authentication complete" in h:
            return "AUTH_COMPLETE"  # may be overridden to AUTH_FAILURE in _emit_event
        if "encryption change" in h:
            return "ENCRYPT_CHANGE"
        if "le advertising report" in h or "le extended advertising report" in h:
            return "LE_ADV_REPORT"
        if "connection complete" in h:  # checked AFTER disconnection complete
            return "CONNECT"
        if "connect failed" in h:
            return "CONNECT_FAILED"
        if "io capability" in h:
            return "IO_CAP"
        if "simple pairing complete" in h:
            return "PAIR_COMPLETE"
        if "link key notification" in h:
            return "LINK_KEY"
        if "smp: pairing failed" in h:
            return "SMP_PAIR_FAILED"
        if "smp: pairing" in h:
            return "SMP_PAIRING"
        if "hardware error" in h:
            return "HCI_HARDWARE_ERROR"

        # Direction-based fallbacks
        if direction == "=":
            return "HCI_INDEX"
        if direction == "@":
            return "HCI_MGMT"
        if "command:" in h and "complete" not in h and "status" not in h:
            return "HCI_CMD"
        if "event:" in h or "complete" in h or "status" in h:
            return "HCI_EVT"
        if "acl" in h:
            return "HCI_ACL"
        if "sco" in h:
            return "HCI_SCO"
        return "HCI_OTHER"
