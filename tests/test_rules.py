"""
Tests for blutruth.correlation.rules — TriggerSpec, _values_match, Rule.from_dict,
and basic RuleEngine matching behavior.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blutruth.correlation.rules import TriggerSpec, Rule, _values_match
from blutruth.events import Event


def _ev(
    source: str = "HCI",
    event_type: str = "HCI_EVT",
    device_addr: str = "AA:BB:CC:DD:EE:FF",
    raw_json: dict = None,
    severity: str = "INFO",
) -> Event:
    return Event.new(
        source=source,
        event_type=event_type,
        summary="test event",
        raw_json=raw_json or {},
        severity=severity,
        device_addr=device_addr,
    )


# ---------------------------------------------------------------------------
# _values_match
# ---------------------------------------------------------------------------

def test_values_match_equal_strings():
    assert _values_match("hello", "hello") is True


def test_values_match_equal_ints():
    assert _values_match(42, 42) is True


def test_values_match_bool_true():
    assert _values_match(True, True) is True


def test_values_match_bool_false_vs_true():
    assert _values_match(False, True) is False


def test_values_match_string_bool_coercion():
    # YAML parses "false" as False; actual may be string "false"
    assert _values_match("false", False) is True
    assert _values_match("true", True) is True


def test_values_match_numeric_coercion():
    assert _values_match("42", 42) is True
    assert _values_match(42, "42") is True


def test_values_match_case_insensitive_strings():
    assert _values_match("WARN", "warn") is True


def test_values_match_none_vs_none():
    assert _values_match(None, None) is True


def test_values_match_none_vs_value():
    assert _values_match(None, "something") is False


# ---------------------------------------------------------------------------
# TriggerSpec.matches
# ---------------------------------------------------------------------------

def test_trigger_matches_event_type():
    spec = TriggerSpec(event_type="HCI_EVT")
    assert spec.matches(_ev(event_type="HCI_EVT")) is True


def test_trigger_wrong_event_type():
    spec = TriggerSpec(event_type="DBUS_PROP")
    assert spec.matches(_ev(event_type="HCI_EVT")) is False


def test_trigger_matches_with_source():
    spec = TriggerSpec(event_type="HCI_EVT", source="HCI")
    assert spec.matches(_ev(source="HCI", event_type="HCI_EVT")) is True


def test_trigger_wrong_source():
    spec = TriggerSpec(event_type="HCI_EVT", source="DBUS")
    assert spec.matches(_ev(source="HCI", event_type="HCI_EVT")) is False


def test_trigger_any_source_when_none():
    spec = TriggerSpec(event_type="HCI_EVT", source=None)
    assert spec.matches(_ev(source="HCI", event_type="HCI_EVT")) is True
    assert spec.matches(_ev(source="DBUS", event_type="HCI_EVT")) is True


def test_trigger_condition_exact_match():
    spec = TriggerSpec(event_type="HCI_EVT", conditions={"key_size": 7})
    ev = _ev(raw_json={"key_size": 7})
    assert spec.matches(ev) is True


def test_trigger_condition_wrong_value():
    spec = TriggerSpec(event_type="HCI_EVT", conditions={"key_size": 16})
    ev = _ev(raw_json={"key_size": 7})
    assert spec.matches(ev) is False


def test_trigger_condition_missing_key():
    spec = TriggerSpec(event_type="HCI_EVT", conditions={"key_size": 7})
    ev = _ev(raw_json={})
    assert spec.matches(ev) is False


def test_trigger_condition_nested_dot_notation():
    spec = TriggerSpec(event_type="DBUS_PROP", conditions={"changed.Connected": False})
    ev = _ev(
        source="DBUS",
        event_type="DBUS_PROP",
        raw_json={"changed": {"Connected": False}},
    )
    assert spec.matches(ev) is True


def test_trigger_condition_nested_wrong_value():
    spec = TriggerSpec(event_type="DBUS_PROP", conditions={"changed.Connected": True})
    ev = _ev(
        source="DBUS",
        event_type="DBUS_PROP",
        raw_json={"changed": {"Connected": False}},
    )
    assert spec.matches(ev) is False


def test_trigger_multiple_conditions_all_must_match():
    spec = TriggerSpec(
        event_type="HCI_EVT",
        conditions={"key_size": 6, "knob_risk": "HIGH"},
    )
    ev_match = _ev(raw_json={"key_size": 6, "knob_risk": "HIGH"})
    ev_partial = _ev(raw_json={"key_size": 6, "knob_risk": "POSSIBLE"})

    assert spec.matches(ev_match) is True
    assert spec.matches(ev_partial) is False


# ---------------------------------------------------------------------------
# Rule.from_dict
# ---------------------------------------------------------------------------

def test_rule_from_dict_basic():
    d = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "A test",
        "triggers": [
            {"event_type": "HCI_EVT", "source": "HCI"},
        ],
        "time_window_ms": 500,
        "same_device": True,
        "severity": "warn",
        "summary": "Pattern: {name}",
        "action": "Do something",
    }
    rule = Rule.from_dict(d)
    assert rule.id == "test_rule"
    assert rule.name == "Test Rule"
    assert len(rule.triggers) == 1
    assert rule.triggers[0].event_type == "HCI_EVT"
    assert rule.triggers[0].source == "HCI"
    assert rule.time_window_ms == 500
    assert rule.same_device is True
    assert rule.severity == "WARN"  # uppercased


def test_rule_from_dict_severity_uppercased():
    d = {
        "id": "r",
        "triggers": [{"event_type": "X"}],
        "severity": "error",
    }
    rule = Rule.from_dict(d)
    assert rule.severity == "ERROR"


def test_rule_from_dict_defaults():
    d = {
        "id": "minimal",
        "triggers": [{"event_type": "X"}],
    }
    rule = Rule.from_dict(d)
    assert rule.time_window_ms == 500  # default
    assert rule.same_device is True    # default
    assert rule.severity == "WARN"     # default
    assert rule.name == "minimal"      # falls back to id


def test_rule_from_dict_multiple_triggers():
    d = {
        "id": "multi",
        "triggers": [
            {"event_type": "A", "source": "HCI"},
            {"event_type": "B", "source": "DBUS", "conditions": {"k": "v"}},
        ],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 2
    assert rule.triggers[1].conditions == {"k": "v"}


def test_rule_from_dict_trigger_conditions():
    d = {
        "id": "with_conditions",
        "triggers": [
            {"event_type": "HCI_EVT", "conditions": {"reason_code": "0x08"}},
        ],
    }
    rule = Rule.from_dict(d)
    assert rule.triggers[0].conditions == {"reason_code": "0x08"}


# ---------------------------------------------------------------------------
# RuleEngine basic loading and event matching
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_engine_load_from_yaml(tmp_path: Path):
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "test_rules.yaml"
    rule_file.write_text("""
rules:
  - id: test_knob_detection
    name: "KNOB Attack Detected"
    description: "Encryption key size critically reduced"
    triggers:
      - event_type: HCI_EVT
        source: HCI
        conditions:
          knob_risk: "HIGH"
    time_window_ms: 1000
    severity: ERROR
    summary: "KNOB detected on {device_addr}"
    action: "Investigate encryption"
""")

    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    count = engine.load_rules([rule_file])

    assert count == 1


@pytest.mark.asyncio
async def test_rule_engine_fires_on_matching_event(tmp_path: Path):
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: knob_single_trigger
    name: "KNOB"
    description: "Single-trigger test rule"
    triggers:
      - event_type: HCI_EVT
        conditions:
          knob_risk: HIGH
    time_window_ms: 1000
    severity: ERROR
    summary: "KNOB detected"
    action: "Check"
""")

    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    ev = _ev(
        source="HCI",
        event_type="HCI_EVT",
        device_addr="AA:BB:CC:DD:EE:FF",
        raw_json={"knob_risk": "HIGH", "key_size": 6},
        severity="ERROR",
    )

    await engine._process_event(ev)

    # Should have emitted a PATTERN_MATCH event
    pattern_events = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(pattern_events) == 1
    assert pattern_events[0].severity == "ERROR"


@pytest.mark.asyncio
async def test_rule_engine_does_not_fire_on_non_matching_event(tmp_path: Path):
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: knob_only
    name: "KNOB"
    description: "Only fires on KNOB events"
    triggers:
      - event_type: HCI_EVT
        conditions:
          knob_risk: HIGH
    time_window_ms: 500
    severity: ERROR
    summary: "KNOB"
    action: "Check"
""")

    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    # Event with POSSIBLE risk — should NOT fire the HIGH rule
    ev = _ev(
        source="HCI",
        event_type="HCI_EVT",
        raw_json={"knob_risk": "POSSIBLE", "key_size": 10},
    )
    await engine._process_event(ev)

    pattern_events = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(pattern_events) == 0


@pytest.mark.asyncio
async def test_rule_engine_two_trigger_sequence(tmp_path: Path):
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: disconnect_then_dbus
    name: "Disconnect followed by D-Bus update"
    description: "Two-event sequence test"
    triggers:
      - event_type: HCI_EVT
        source: HCI
      - event_type: DBUS_PROP
        source: DBUS
    time_window_ms: 2000
    same_device: true
    severity: WARN
    summary: "Sequence fired"
    action: "Investigate"
""")

    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    addr = "AA:BB:CC:DD:EE:FF"

    # First trigger
    ev1 = _ev(source="HCI", event_type="HCI_EVT", device_addr=addr)
    await engine._process_event(ev1)

    # No match yet (sequence incomplete)
    pattern_events = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(pattern_events) == 0

    # Second trigger — completes the sequence
    ev2 = _ev(source="DBUS", event_type="DBUS_PROP", device_addr=addr)
    await engine._process_event(ev2)

    pattern_events = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(pattern_events) == 1
