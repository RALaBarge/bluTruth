"""
blutruth.collectors.pipewire — PipeWire / PulseAudio audio pipeline collector

Monitors the audio routing layer between BlueZ A2DP/HFP profiles and
applications (Spotify, Firefox, etc.). This is the gap between:

    Your App (Spotify, etc.)
        ↓
    PipeWire / PulseAudio      ← THIS COLLECTOR
        ↓
    BlueZ profile plugins (A2DP, HFP, HID...)

Two collection strategies:

1. pw-dump watcher: Runs `pw-dump --monitor --no-colors` to capture real-time
   PipeWire object changes. Detects bluetooth node creation/destruction, codec
   negotiation, buffer underruns, format changes, and routing decisions.

2. pactl subscribe (fallback): If PipeWire isn't present, falls back to
   `pactl subscribe` to capture PulseAudio events for sink/source/card changes.

This collector answers questions like:
  - "Why did my headphones switch from A2DP to HFP?"
  - "When did PipeWire re-route audio away from the bluetooth sink?"
  - "What codec did PipeWire negotiate with the device?"
  - "Are there buffer underruns causing audio glitches?"

FUTURE: Parse PipeWire profiler data for latency measurements.
FUTURE: Direct libpipewire bindings for zero-overhead monitoring.
FUTURE (Rust port): pipewire-rs crate with direct registry listener.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


# Bluetooth-related PipeWire properties to watch for
_BT_PW_PROPS = {
    "api.bluez5",
    "bluez5.codec",
    "bluez5.address",
    "bluetooth.codec",
    "media.class",
    "node.name",
    "node.description",
    "device.api",
    "device.bus",
}

# PulseAudio event patterns
# Example: Event 'change' on sink #42
_PACTL_EVENT_RE = re.compile(
    r"Event '(\w+)' on (\w+) #(\d+)"
)

# Device address in PipeWire properties or names
_ADDR_RE = re.compile(r"([0-9A-Fa-f]{2}(?:[_:][0-9A-Fa-f]{2}){5})")


def _normalize_addr(addr: str) -> str:
    """Normalize PipeWire's underscore-separated addresses to colon format."""
    return addr.replace("_", ":").upper()


def _is_bluetooth_node(obj: dict) -> bool:
    """Check if a PipeWire object is bluetooth-related."""
    info = obj.get("info", {})
    props = info.get("props", {})

    # Direct bluetooth indicators
    if props.get("device.api") == "bluez5":
        return True
    if props.get("device.bus") == "bluetooth":
        return True
    if any(k.startswith("api.bluez5") for k in props):
        return True
    if any(k.startswith("bluez5.") for k in props):
        return True
    if any(k.startswith("bluetooth.") for k in props):
        return True

    # Check node name for bluetooth patterns
    name = props.get("node.name", "") or ""
    if "bluez" in name.lower() or "bluetooth" in name.lower():
        return True

    return False


def _extract_bt_props(obj: dict) -> Dict[str, Any]:
    """Extract bluetooth-relevant properties from a PipeWire object."""
    info = obj.get("info", {})
    props = info.get("props", {})
    result = {}

    for key in _BT_PW_PROPS:
        if key in props:
            result[key] = props[key]

    # Also grab format info if present
    for key in ("audio.format", "audio.rate", "audio.channels",
                "audio.position", "format.dsp"):
        if key in props:
            result[key] = props[key]

    # Params may contain format negotiation details
    params = info.get("params", {})
    if params:
        # Only include bluetooth-relevant param sections
        for section in ("Format", "Props", "EnumFormat"):
            if section in params:
                result[f"param_{section}"] = params[section]

    return result


def _classify_pw_change(obj: dict, change_type: str) -> tuple:
    """Return (severity, stage, summary_detail) for a PipeWire change."""
    info = obj.get("info", {})
    props = info.get("props", {})
    obj_type = obj.get("type", "")

    node_name = props.get("node.name", "")
    node_desc = props.get("node.description", "")
    codec = props.get("bluez5.codec", props.get("bluetooth.codec", ""))
    media_class = props.get("media.class", "")

    display = node_desc or node_name or obj_type

    if change_type == "added":
        if "Audio/Sink" in media_class:
            return ("INFO", "AUDIO", f"BT audio sink created: {display}")
        if "Audio/Source" in media_class:
            return ("INFO", "AUDIO", f"BT audio source created: {display}")
        return ("INFO", "AUDIO", f"BT PipeWire node added: {display}")

    if change_type == "removed":
        return ("WARN", "TEARDOWN", f"BT PipeWire node removed: {display}")

    if change_type == "changed":
        if codec:
            return ("INFO", "AUDIO", f"BT codec active: {codec} on {display}")
        state = info.get("state", "")
        if state:
            return ("INFO", "AUDIO", f"BT node state: {state} on {display}")
        return ("DEBUG", "AUDIO", f"BT PipeWire node changed: {display}")

    return ("DEBUG", "AUDIO", f"BT PipeWire event: {display}")


class PipewireCollector(Collector):
    name = "pipewire"
    description = "PipeWire/PulseAudio audio pipeline monitor"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._mode: str = "none"  # "pipewire" or "pulseaudio" or "none"
        self._known_bt_nodes: Dict[int, dict] = {}  # pw object id → last state

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [],
            "provides": ["PIPEWIRE"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        self._running = True

        # Detect audio system: prefer PipeWire, fall back to PulseAudio
        if shutil.which("pw-dump"):
            self._mode = "pipewire"
            self._task = asyncio.create_task(self._start_pw_dump())
        elif shutil.which("pactl"):
            self._mode = "pulseaudio"
            self._task = asyncio.create_task(self._start_pactl())
        else:
            self._mode = "none"
            await self.bus.publish(Event.new(
                source="PIPEWIRE",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary="Neither pw-dump nor pactl found — audio pipeline monitoring disabled",
                raw_json={"error": "no audio system tools found"},
                source_version=self.source_version_tag,
            ))
            return

        await self.bus.publish(Event.new(
            source="PIPEWIRE",
            event_type="COLLECTOR_START",
            summary=f"Audio pipeline collector started (mode: {self._mode})",
            raw_json={"mode": self._mode},
            source_version=self.source_version_tag,
        ))

    # --- PipeWire mode ---

    async def _start_pw_dump(self) -> None:
        """Run pw-dump --monitor and parse JSON output."""
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "pw-dump", "--monitor", "--no-colors",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            await self.bus.publish(Event.new(
                source="PIPEWIRE",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary=f"Failed to start pw-dump: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))
            return

        await self._read_pw_dump_loop()

    async def _read_pw_dump_loop(self) -> None:
        """
        Parse pw-dump --monitor output.

        pw-dump emits JSON arrays — each array is a complete snapshot or delta
        of PipeWire objects. We accumulate lines until we have a complete JSON
        array, then parse and process bluetooth-related objects.
        """
        assert self._proc and self._proc.stdout

        json_buffer = ""
        bracket_depth = 0

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="PIPEWIRE",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="pw-dump exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()

            # Track JSON array boundaries
            bracket_depth += line.count("[") - line.count("]")
            json_buffer += line + "\n"

            # Complete JSON array received
            if bracket_depth <= 0 and json_buffer.strip():
                await self._process_pw_dump(json_buffer.strip())
                json_buffer = ""
                bracket_depth = 0

    async def _process_pw_dump(self, raw_json: str) -> None:
        """Process a complete pw-dump JSON array."""
        try:
            objects = json.loads(raw_json)
        except json.JSONDecodeError:
            return

        if not isinstance(objects, list):
            return

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            if not _is_bluetooth_node(obj):
                continue

            obj_id = obj.get("id", 0)
            bt_props = _extract_bt_props(obj)

            # Determine change type
            if obj_id not in self._known_bt_nodes:
                change_type = "added"
            else:
                change_type = "changed"

            severity, stage, summary = _classify_pw_change(obj, change_type)

            # Extract device address from properties
            device_addr = None
            info = obj.get("info", {})
            props = info.get("props", {})
            for key in ("bluez5.address", "api.bluez5.address"):
                addr = props.get(key)
                if addr:
                    device_addr = _normalize_addr(addr)
                    break
            if not device_addr:
                # Try to find in any property value
                for v in props.values():
                    if isinstance(v, str):
                        m = _ADDR_RE.search(v)
                        if m:
                            device_addr = _normalize_addr(m.group(1))
                            break

            await self.bus.publish(Event.new(
                source="PIPEWIRE",
                severity=severity,
                stage=stage,
                event_type=f"PW_{change_type.upper()}",
                device_addr=device_addr,
                summary=summary,
                raw_json={
                    "pw_id": obj_id,
                    "pw_type": obj.get("type", ""),
                    "change_type": change_type,
                    "bt_props": bt_props,
                },
                source_version=self.source_version_tag,
                parser_version=f"pipewire-parser-{self.version}",
            ))

            self._known_bt_nodes[obj_id] = obj

        # Detect removed objects: if a previously-known BT node isn't in
        # the new dump, it was removed. Only check on full dumps (>5 objects).
        if len(objects) > 5:
            current_ids = {o.get("id") for o in objects if isinstance(o, dict)}
            for old_id in list(self._known_bt_nodes.keys()):
                if old_id not in current_ids:
                    old_obj = self._known_bt_nodes.pop(old_id)
                    severity, stage, summary = _classify_pw_change(
                        old_obj, "removed"
                    )
                    await self.bus.publish(Event.new(
                        source="PIPEWIRE",
                        severity=severity,
                        stage=stage,
                        event_type="PW_REMOVED",
                        summary=summary,
                        raw_json={
                            "pw_id": old_id,
                            "change_type": "removed",
                        },
                        source_version=self.source_version_tag,
                        parser_version=f"pipewire-parser-{self.version}",
                    ))

    # --- PulseAudio fallback ---

    async def _start_pactl(self) -> None:
        """Fallback: run pactl subscribe for PulseAudio events."""
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "pactl", "subscribe",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            await self.bus.publish(Event.new(
                source="PIPEWIRE",
                severity="ERROR",
                event_type="COLLECTOR_ERROR",
                summary=f"Failed to start pactl subscribe: {e}",
                raw_json={"error": str(e)},
                source_version=self.source_version_tag,
            ))
            return

        await self._read_pactl_loop()

    async def _read_pactl_loop(self) -> None:
        """Parse pactl subscribe output."""
        assert self._proc and self._proc.stdout

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="PIPEWIRE",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="pactl subscribe exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            m = _PACTL_EVENT_RE.match(line)
            if not m:
                continue

            event_action = m.group(1)   # change, new, remove
            object_type = m.group(2)    # sink, source, card, etc.
            object_index = m.group(3)

            # We care about bluetooth-related audio objects
            # PulseAudio doesn't tell us if it's BT in the event line,
            # so we emit all sink/source/card events and let correlation
            # match them with D-Bus/HCI events
            if object_type in ("sink", "source", "card", "sink-input", "source-output"):
                severity = "INFO" if event_action != "remove" else "WARN"
                stage = "AUDIO" if event_action != "remove" else "TEARDOWN"

                await self.bus.publish(Event.new(
                    source="PIPEWIRE",
                    severity=severity,
                    stage=stage,
                    event_type=f"PA_{event_action.upper()}",
                    summary=f"PulseAudio: {event_action} on {object_type} #{object_index}",
                    raw_json={
                        "pa_event": event_action,
                        "pa_type": object_type,
                        "pa_index": int(object_index),
                        "mode": "pulseaudio",
                    },
                    source_version=self.source_version_tag,
                    parser_version=f"pactl-parser-{self.version}",
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
