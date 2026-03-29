"""
Tests for blutruth.correlation.rules — TriggerSpec, _values_match, Rule.from_dict,
and basic RuleEngine matching behavior (including count and negate triggers).
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


# ---------------------------------------------------------------------------
# count trigger
# ---------------------------------------------------------------------------

def test_rule_from_dict_count_expands_triggers():
    """count: 3 on one trigger entry should expand to 3 identical TriggerSpec objects."""
    d = {
        "id": "count_test",
        "triggers": [
            {"event_type": "AUTH_FAILURE", "source": "HCI", "count": 3},
        ],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 3
    for t in rule.triggers:
        assert t.event_type == "AUTH_FAILURE"
        assert t.source == "HCI"
        assert t.negate is False


def test_rule_from_dict_count_one_is_unchanged():
    d = {
        "id": "r",
        "triggers": [{"event_type": "X", "count": 1}],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 1


def test_rule_from_dict_count_mixed():
    """count on one trigger, plain on another."""
    d = {
        "id": "mixed",
        "triggers": [
            {"event_type": "A", "count": 2},
            {"event_type": "B"},
        ],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 3
    assert rule.triggers[0].event_type == "A"
    assert rule.triggers[1].event_type == "A"
    assert rule.triggers[2].event_type == "B"


@pytest.mark.asyncio
async def test_count_trigger_fires_after_n_events(tmp_path: Path):
    """Rule with count:3 should fire after the third matching event, not before."""
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: auth_loop
    name: "Auth Loop"
    triggers:
      - event_type: AUTH_FAILURE
        source: HCI
        count: 3
    time_window_ms: 5000
    same_device: true
    severity: ERROR
    summary: "Auth loop on {device_addr}"
    action: "Re-pair"
""")
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    addr = "AA:BB:CC:DD:EE:FF"

    for i in range(2):
        await engine._process_event(_ev(source="HCI", event_type="AUTH_FAILURE", device_addr=addr))
        assert len([e for e in bus.events if e.event_type == "PATTERN_MATCH"]) == 0

    # Third event fires the rule
    await engine._process_event(_ev(source="HCI", event_type="AUTH_FAILURE", device_addr=addr))
    matches = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(matches) == 1
    assert matches[0].severity == "ERROR"


@pytest.mark.asyncio
async def test_count_trigger_different_device_does_not_advance(tmp_path: Path):
    """Count should not advance when events come from a different device address."""
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: count_same_device
    name: "Count same device"
    triggers:
      - event_type: AUTH_FAILURE
        count: 2
    time_window_ms: 5000
    same_device: true
    severity: WARN
    summary: "Two failures"
    action: ""
""")
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    # First event from device A starts a partial
    await engine._process_event(_ev(event_type="AUTH_FAILURE", device_addr="AA:BB:CC:DD:EE:FF"))
    # Second event from device B should NOT complete the partial for device A
    await engine._process_event(_ev(event_type="AUTH_FAILURE", device_addr="11:22:33:44:55:66"))
    assert len([e for e in bus.events if e.event_type == "PATTERN_MATCH"]) == 0


# ---------------------------------------------------------------------------
# negate trigger
# ---------------------------------------------------------------------------

def test_rule_from_dict_negate_flag():
    d = {
        "id": "bias",
        "triggers": [
            {"event_type": "AUTH_COMPLETE", "source": "HCI"},
            {"event_type": "ENCRYPT_CHANGE", "source": "HCI", "negate": True},
        ],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 2
    assert rule.triggers[0].negate is False
    assert rule.triggers[1].negate is True


def test_rule_from_dict_negate_ignores_count():
    """count on a negate trigger should be ignored (always 1)."""
    d = {
        "id": "r",
        "triggers": [
            {"event_type": "A"},
            {"event_type": "B", "negate": True, "count": 5},
        ],
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 2  # not 6
    assert rule.triggers[1].negate is True


@pytest.mark.asyncio
async def test_negate_trigger_fires_when_event_absent(tmp_path: Path):
    """Negate rule fires when the negated event does NOT appear within the window."""
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: bias_test
    name: "BIAS Test"
    triggers:
      - event_type: AUTH_COMPLETE
        source: HCI
      - event_type: ENCRYPT_CHANGE
        source: HCI
        negate: true
    time_window_ms: 100
    same_device: true
    severity: SUSPICIOUS
    summary: "BIAS on {device_addr}"
    action: "Disconnect"
""")
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    addr = "AA:BB:CC:DD:EE:FF"
    await engine._process_event(_ev(source="HCI", event_type="AUTH_COMPLETE", device_addr=addr))

    # No ENCRYPT_CHANGE → should not fire yet
    assert len([e for e in bus.events if e.event_type == "PATTERN_MATCH"]) == 0

    # Simulate window expiry by backdating the partial
    for pm in engine._partials[addr]:
        pm.started_at_mono -= 0.2  # 200ms ago, window is 100ms

    # Expiry pass fires the negate match
    await engine._expire_old_partials()

    matches = [e for e in bus.events if e.event_type == "PATTERN_MATCH"]
    assert len(matches) == 1
    assert matches[0].severity == "SUSPICIOUS"


@pytest.mark.asyncio
async def test_negate_trigger_cancelled_when_event_appears(tmp_path: Path):
    """Negate rule is cancelled when the negated event DOES appear."""
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: bias_cancel
    name: "BIAS Cancel Test"
    triggers:
      - event_type: AUTH_COMPLETE
        source: HCI
      - event_type: ENCRYPT_CHANGE
        source: HCI
        negate: true
    time_window_ms: 2000
    same_device: true
    severity: SUSPICIOUS
    summary: "BIAS on {device_addr}"
    action: "Disconnect"
""")
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    addr = "AA:BB:CC:DD:EE:FF"

    # First trigger: auth complete
    await engine._process_event(_ev(source="HCI", event_type="AUTH_COMPLETE", device_addr=addr))
    # Partial should be waiting on negate
    assert any(pm.waiting_for_negate for pm in engine._partials[addr])

    # Negated event arrives → partial cancelled
    await engine._process_event(_ev(source="HCI", event_type="ENCRYPT_CHANGE", device_addr=addr))
    assert len(engine._partials[addr]) == 0

    # No PATTERN_MATCH emitted (normal connection, no anomaly)
    assert len([e for e in bus.events if e.event_type == "PATTERN_MATCH"]) == 0


@pytest.mark.asyncio
async def test_negate_trigger_same_device_only(tmp_path: Path):
    """ENCRYPT_CHANGE from a different device should not cancel the BIAS partial."""
    from blutruth.correlation.rules import RuleEngine
    from blutruth.config import Config
    from tests.conftest import MockBus

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("""
rules:
  - id: bias_device
    name: "BIAS device isolation"
    triggers:
      - event_type: AUTH_COMPLETE
      - event_type: ENCRYPT_CHANGE
        negate: true
    time_window_ms: 2000
    same_device: true
    severity: SUSPICIOUS
    summary: "BIAS"
    action: ""
""")
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.load_rules([rule_file])

    victim = "AA:BB:CC:DD:EE:FF"
    other  = "11:22:33:44:55:66"

    await engine._process_event(_ev(event_type="AUTH_COMPLETE", device_addr=victim))
    # ENCRYPT_CHANGE from a different device — should NOT cancel victim's partial
    await engine._process_event(_ev(event_type="ENCRYPT_CHANGE", device_addr=other))
    assert any(pm.waiting_for_negate for pm in engine._partials[victim])


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
