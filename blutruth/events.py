"""
blutruth.events — Canonical event schema

This is the primary compatibility contract. Collectors change, parsers change,
the UI changes — the event format stays stable and versioned.

FUTURE (Rust port): This dataclass maps 1:1 to a Rust struct. The field names,
types, and JSON serialization must remain identical across both implementations.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union


SCHEMA_VERSION = 1


@dataclasses.dataclass(slots=True)
class Event:
    # --- Versioning (provenance across Python/Rust implementations) ---
    schema_version: int
    source_version: Optional[str]       # e.g., "hci-collector-0.1.0"
    parser_version: Optional[str]       # e.g., "hci-parser-0.1.0"

    # --- Identity ---
    event_id: str

    # --- Time ---
    ts_mono_us: int                     # microseconds since boot (primary sort key)
    ts_wall: str                        # ISO8601 wall clock (display/debug only)

    # --- Classification ---
    source: str                         # HCI | DBUS | DAEMON | KERNEL | SYSFS | RUNTIME
    severity: str                       # DEBUG | INFO | WARN | ERROR | SUSPICIOUS
    stage: Optional[str]                # DISCOVERY | CONNECTION | HANDSHAKE | DATA | AUDIO | TEARDOWN
    event_type: str                     # HCI_CMD | HCI_EVT | DBUS_PROP | DBUS_SIG | LOG | ...

    # --- Device context ---
    adapter: Optional[str]              # hci0
    device_addr: Optional[str]          # normalized AA:BB:CC:DD:EE:FF
    device_name: Optional[str]

    # --- Content ---
    summary: str                        # human-readable one-liner
    raw_json: Dict[str, Any]            # full structured payload
    raw: Optional[str]                  # original unparsed line/bytes

    # --- Correlation ---
    group_id: Optional[int]             # set by correlation engine
    tags: Optional[Union[List[str], Dict[str, Any]]]

    # --- User scratch space ---
    annotations: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    @staticmethod
    def _boot_us() -> int:
        """Microseconds since process monotonic epoch.
        FUTURE: read CLOCK_BOOTTIME via ctypes for true boot-anchored time."""
        return int(time.monotonic() * 1_000_000)

    @classmethod
    def new(
        cls,
        *,
        source: str,
        summary: str,
        raw_json: Dict[str, Any],
        event_type: str = "GENERIC",
        severity: str = "INFO",
        stage: Optional[str] = None,
        adapter: Optional[str] = None,
        device_addr: Optional[str] = None,
        device_name: Optional[str] = None,
        raw: Optional[str] = None,
        tags: Optional[Union[List[str], Dict[str, Any]]] = None,
        source_version: Optional[str] = None,
        parser_version: Optional[str] = None,
    ) -> Event:
        return cls(
            schema_version=SCHEMA_VERSION,
            source_version=source_version,
            parser_version=parser_version,
            event_id=uuid.uuid4().hex[:16],
            ts_mono_us=cls._boot_us(),
            ts_wall=dt.datetime.now(dt.timezone.utc).isoformat(),
            source=source,
            severity=severity,
            stage=stage,
            event_type=event_type,
            adapter=adapter,
            device_addr=device_addr,
            device_name=device_name,
            summary=summary,
            raw_json=raw_json,
            raw=raw,
            group_id=None,
            tags=tags,
            annotations=None,
        )


# --- Severity helpers ---

SEVERITY_ORDER = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "SUSPICIOUS": 4}

# --- Stage constants ---

STAGES = ("DISCOVERY", "CONNECTION", "HANDSHAKE", "DATA", "AUDIO", "TEARDOWN")

# --- Source constants ---

SOURCES = ("HCI", "DBUS", "DAEMON", "KERNEL", "SYSFS", "RUNTIME")
