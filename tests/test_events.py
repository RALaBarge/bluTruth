"""
Tests for blutruth.events — Event schema, factory methods, serialization.
"""
from __future__ import annotations

import json
import time

from blutruth.events import Event, SCHEMA_VERSION, SEVERITY_ORDER, STAGES, SOURCES


# ---------------------------------------------------------------------------
# Event.new()
# ---------------------------------------------------------------------------

def test_event_new_required_fields():
    ev = Event.new(source="HCI", event_type="HCI_EVT", summary="test event", raw_json={})
    assert ev.source == "HCI"
    assert ev.event_type == "HCI_EVT"
    assert ev.summary == "test event"


def test_event_new_defaults():
    ev = Event.new(source="DBUS", event_type="DBUS_PROP", summary="x", raw_json={})
    assert ev.severity == "INFO"
    assert ev.stage is None
    assert ev.adapter is None
    assert ev.device_addr is None
    assert ev.device_name is None
    assert ev.raw is None
    assert ev.group_id is None
    assert ev.tags is None
    assert ev.annotations is None
    assert ev.schema_version == SCHEMA_VERSION


def test_event_new_optional_fields():
    ev = Event.new(
        source="SYSFS",
        event_type="ADAPTER_REMOVED",
        summary="adapter gone",
        raw_json={"adapter": "hci0"},
        severity="WARN",
        stage="TEARDOWN",
        adapter="hci0",
        device_addr="AA:BB:CC:DD:EE:FF",
        device_name="My Headset",
        raw="raw btmon line",
        tags=["usb", "power"],
        source_version="sysfs-collector-0.1.0",
        parser_version="sysfs-parser-0.1.0",
    )
    assert ev.severity == "WARN"
    assert ev.stage == "TEARDOWN"
    assert ev.adapter == "hci0"
    assert ev.device_addr == "AA:BB:CC:DD:EE:FF"
    assert ev.device_name == "My Headset"
    assert ev.raw == "raw btmon line"
    assert ev.tags == ["usb", "power"]
    assert ev.source_version == "sysfs-collector-0.1.0"
    assert ev.parser_version == "sysfs-parser-0.1.0"


def test_event_new_unique_ids():
    ev1 = Event.new(source="HCI", event_type="HCI_EVT", summary="a", raw_json={})
    ev2 = Event.new(source="HCI", event_type="HCI_EVT", summary="b", raw_json={})
    assert ev1.event_id != ev2.event_id
    assert len(ev1.event_id) == 16  # uuid4().hex[:16]


def test_event_new_monotonic_timestamps():
    ev1 = Event.new(source="HCI", event_type="HCI_EVT", summary="first", raw_json={})
    time.sleep(0.005)
    ev2 = Event.new(source="HCI", event_type="HCI_EVT", summary="second", raw_json={})
    assert ev2.ts_mono_us >= ev1.ts_mono_us


def test_event_new_ts_wall_is_iso8601():
    import datetime as dt
    ev = Event.new(source="RUNTIME", event_type="GENERIC", summary="x", raw_json={})
    # Should parse without error
    dt.datetime.fromisoformat(ev.ts_wall)


def test_event_new_raw_json_preserved():
    payload = {"key_size": 7, "knob_risk": "HIGH", "handle": 256}
    ev = Event.new(source="HCI", event_type="HCI_EVT", summary="x", raw_json=payload)
    assert ev.raw_json == payload


# ---------------------------------------------------------------------------
# Event.to_dict() and to_json()
# ---------------------------------------------------------------------------

def test_event_to_dict_has_all_fields():
    ev = Event.new(source="HCI", event_type="HCI_EVT", summary="x", raw_json={"a": 1})
    d = ev.to_dict()
    assert d["source"] == "HCI"
    assert d["event_type"] == "HCI_EVT"
    assert d["raw_json"] == {"a": 1}
    assert d["group_id"] is None
    assert "event_id" in d
    assert "ts_mono_us" in d
    assert "ts_wall" in d


def test_event_to_json_is_valid():
    ev = Event.new(source="DBUS", event_type="DBUS_SIG", summary="x", raw_json={})
    s = ev.to_json()
    parsed = json.loads(s)
    assert parsed["source"] == "DBUS"


# ---------------------------------------------------------------------------
# Event.from_dict()
# ---------------------------------------------------------------------------

def test_event_from_dict_round_trip():
    original = Event.new(
        source="SYSFS",
        event_type="USB_POWER_CHANGE",
        summary="power changed",
        raw_json={"curr_status": "suspended"},
        severity="WARN",
        device_addr="11:22:33:44:55:66",
        adapter="hci0",
    )
    d = original.to_dict()
    restored = Event.from_dict(d)

    assert restored.source == original.source
    assert restored.event_type == original.event_type
    assert restored.summary == original.summary
    assert restored.severity == original.severity
    assert restored.device_addr == original.device_addr
    assert restored.adapter == original.adapter
    assert restored.raw_json == original.raw_json


def test_event_from_dict_resets_group_id():
    ev = Event.new(source="HCI", event_type="HCI_EVT", summary="x", raw_json={})
    d = ev.to_dict()
    d["group_id"] = 99  # simulate stored correlated event
    restored = Event.from_dict(d)
    assert restored.group_id is None


def test_event_from_dict_regenerates_event_id():
    ev = Event.new(source="HCI", event_type="HCI_EVT", summary="x", raw_json={})
    d = ev.to_dict()
    restored = Event.from_dict(d)
    assert restored.event_id != ev.event_id


def test_event_from_dict_missing_fields_use_defaults():
    restored = Event.from_dict({"source": "RUNTIME", "summary": "minimal"})
    assert restored.source == "RUNTIME"
    assert restored.summary == "minimal"
    assert restored.severity == "INFO"
    assert restored.event_type == "GENERIC"
    assert restored.raw_json == {}


# ---------------------------------------------------------------------------
# SEVERITY_ORDER
# ---------------------------------------------------------------------------

def test_severity_order_ascending():
    assert SEVERITY_ORDER["DEBUG"] < SEVERITY_ORDER["INFO"]
    assert SEVERITY_ORDER["INFO"] < SEVERITY_ORDER["WARN"]
    assert SEVERITY_ORDER["WARN"] < SEVERITY_ORDER["ERROR"]
    assert SEVERITY_ORDER["ERROR"] < SEVERITY_ORDER["SUSPICIOUS"]


def test_severity_order_has_all_levels():
    for level in ("DEBUG", "INFO", "WARN", "ERROR", "SUSPICIOUS"):
        assert level in SEVERITY_ORDER


# ---------------------------------------------------------------------------
# STAGES and SOURCES constants
# ---------------------------------------------------------------------------

def test_stages_contains_expected():
    for stage in ("DISCOVERY", "CONNECTION", "HANDSHAKE", "DATA", "AUDIO", "TEARDOWN"):
        assert stage in STAGES


def test_sources_contains_expected():
    for src in ("HCI", "DBUS", "DAEMON", "KERNEL", "SYSFS", "RUNTIME"):
        assert src in SOURCES
