"""
Tests for blutruth.correlation — CorrelationEngine and RuleEngine.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from blutruth.bus import EventBus
from blutruth.config import Config
from blutruth.correlation.engine import CorrelationEngine
from blutruth.correlation.rules import (
    Rule, TriggerSpec, PartialMatch, RuleEngine, load_rule_paths, _values_match,
)
from blutruth.events import Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> Event:
    defaults = dict(
        source="HCI",
        summary="test",
        raw_json={},
        event_type="TEST",
        severity="INFO",
    )
    defaults.update(overrides)
    return Event.new(**defaults)


# ---------------------------------------------------------------------------
# CorrelationEngine._cluster_events
# ---------------------------------------------------------------------------

def test_cluster_events_basic():
    events = [
        {"ts_mono_us": 1000, "source": "HCI"},
        {"ts_mono_us": 1050, "source": "DBUS"},
        {"ts_mono_us": 5000, "source": "HCI"},
    ]
    clusters = CorrelationEngine._cluster_events(events, window_us=200)
    assert len(clusters) == 1
    assert len(clusters[0]) == 2  # first two events


def test_cluster_events_all_in_window():
    events = [
        {"ts_mono_us": 100, "source": "HCI"},
        {"ts_mono_us": 150, "source": "DBUS"},
        {"ts_mono_us": 200, "source": "DAEMON"},
    ]
    clusters = CorrelationEngine._cluster_events(events, window_us=200)
    assert len(clusters) == 1
    assert len(clusters[0]) == 3


def test_cluster_events_separate_clusters():
    events = [
        {"ts_mono_us": 100, "source": "HCI"},
        {"ts_mono_us": 150, "source": "DBUS"},
        {"ts_mono_us": 10000, "source": "HCI"},
        {"ts_mono_us": 10050, "source": "DBUS"},
    ]
    clusters = CorrelationEngine._cluster_events(events, window_us=200)
    assert len(clusters) == 2


def test_cluster_events_empty():
    assert CorrelationEngine._cluster_events([], window_us=200) == []


def test_cluster_events_single():
    events = [{"ts_mono_us": 100, "source": "HCI"}]
    clusters = CorrelationEngine._cluster_events(events, window_us=200)
    assert clusters == []  # single event can't form a cluster


# ---------------------------------------------------------------------------
# TriggerSpec matching
# ---------------------------------------------------------------------------

def test_trigger_matches_event_type():
    t = TriggerSpec(event_type="DISCONNECT")
    ev = _make_event(event_type="DISCONNECT")
    assert t.matches(ev) is True


def test_trigger_no_match_wrong_type():
    t = TriggerSpec(event_type="DISCONNECT")
    ev = _make_event(event_type="CONNECT")
    assert t.matches(ev) is False


def test_trigger_matches_source():
    t = TriggerSpec(event_type="DISCONNECT", source="HCI")
    ev = _make_event(event_type="DISCONNECT", source="HCI")
    assert t.matches(ev) is True


def test_trigger_no_match_wrong_source():
    t = TriggerSpec(event_type="DISCONNECT", source="HCI")
    ev = _make_event(event_type="DISCONNECT", source="DBUS")
    assert t.matches(ev) is False


def test_trigger_matches_conditions():
    t = TriggerSpec(event_type="DISCONNECT", conditions={"reason_code": "0x08"})
    ev = _make_event(event_type="DISCONNECT", raw_json={"reason_code": "0x08"})
    assert t.matches(ev) is True


def test_trigger_no_match_wrong_condition():
    t = TriggerSpec(event_type="DISCONNECT", conditions={"reason_code": "0x08"})
    ev = _make_event(event_type="DISCONNECT", raw_json={"reason_code": "0x13"})
    assert t.matches(ev) is False


def test_trigger_dot_notation_conditions():
    t = TriggerSpec(event_type="DBUS_PROP", conditions={"changed.State": "active"})
    ev = _make_event(event_type="DBUS_PROP", raw_json={"changed": {"State": "active"}})
    assert t.matches(ev) is True


# ---------------------------------------------------------------------------
# _values_match
# ---------------------------------------------------------------------------

def test_values_match_string():
    assert _values_match("hello", "hello") is True
    assert _values_match("hello", "world") is False


def test_values_match_bool_coercion():
    assert _values_match("true", True) is True
    assert _values_match("false", False) is True


def test_values_match_numeric():
    assert _values_match(8, "8") is True
    assert _values_match("0x08", "0x08") is True


# ---------------------------------------------------------------------------
# Rule.from_dict
# ---------------------------------------------------------------------------

def test_rule_from_dict_basic():
    d = {
        "id": "test_rule",
        "name": "Test Rule",
        "description": "A test",
        "triggers": [
            {"event_type": "DISCONNECT", "source": "HCI"},
            {"event_type": "DBUS_PROP", "source": "DBUS"},
        ],
        "time_window_ms": 500,
        "severity": "WARN",
    }
    rule = Rule.from_dict(d)
    assert rule.id == "test_rule"
    assert len(rule.triggers) == 2
    assert rule.time_window_ms == 500


def test_rule_from_dict_count_expansion():
    d = {
        "id": "count_rule",
        "triggers": [{"event_type": "DISCONNECT", "count": 3}],
        "time_window_ms": 1000,
    }
    rule = Rule.from_dict(d)
    assert len(rule.triggers) == 3
    assert all(t.event_type == "DISCONNECT" for t in rule.triggers)


def test_rule_from_dict_negate_ignores_count():
    d = {
        "id": "negate_rule",
        "triggers": [
            {"event_type": "DISCONNECT"},
            {"event_type": "CONNECT", "negate": True, "count": 5},
        ],
        "time_window_ms": 1000,
    }
    rule = Rule.from_dict(d)
    # negate trigger should NOT be expanded
    assert len(rule.triggers) == 2
    assert rule.triggers[1].negate is True


# ---------------------------------------------------------------------------
# RuleEngine — load
# ---------------------------------------------------------------------------

def test_load_builtin_rules():
    """Built-in rule YAML files should load without errors."""
    from blutruth.config import Config
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    paths = load_rule_paths(cfg)
    assert len(paths) >= 3  # security, connection, audio, profiles

    engine = RuleEngine(EventBus(), cfg)
    n = engine.load_rules(paths)
    assert n >= 20  # we have 24+ built-in rules


def test_load_invalid_rule_file(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("rules:\n  - id: broken\n    triggers: not_a_list\n")

    engine = RuleEngine(EventBus(), Config(Path("/tmp/_blutruth_test_nonexistent.yaml")))
    n = engine.load_rules([bad_yaml])
    assert n == 0  # broken rule should be skipped, not crash


def test_load_empty_rule_file(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")

    engine = RuleEngine(EventBus(), Config(Path("/tmp/_blutruth_test_nonexistent.yaml")))
    n = engine.load_rules([empty])
    assert n == 0


# ---------------------------------------------------------------------------
# RuleEngine — process events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_engine_single_trigger_fires():
    bus = EventBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)

    rule = Rule.from_dict({
        "id": "single",
        "name": "Single Trigger",
        "triggers": [{"event_type": "DISCONNECT"}],
        "time_window_ms": 500,
        "severity": "WARN",
        "summary": "Pattern: {name}",
    })
    engine.rules = [rule]

    # Collect emitted events
    output_queue = await bus.subscribe(max_queue=100)
    await engine.start()

    ev = _make_event(event_type="DISCONNECT", device_addr="AA:BB:CC:DD:EE:FF")
    await bus.publish(ev)

    # Give the engine time to process
    await asyncio.sleep(0.2)

    await engine.stop()

    # Check for PATTERN_MATCH in queue
    matches = []
    while not output_queue.empty():
        e = output_queue.get_nowait()
        if e.event_type == "PATTERN_MATCH":
            matches.append(e)

    assert len(matches) == 1
    assert matches[0].raw_json["rule_id"] == "single"


@pytest.mark.asyncio
async def test_rule_engine_multi_trigger_fires():
    bus = EventBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)

    rule = Rule.from_dict({
        "id": "multi",
        "name": "Multi Trigger",
        "triggers": [
            {"event_type": "DISCONNECT", "source": "HCI"},
            {"event_type": "DBUS_PROP", "source": "DBUS"},
        ],
        "time_window_ms": 5000,
        "severity": "INFO",
        "summary": "Pattern: {name}",
    })
    engine.rules = [rule]

    output_queue = await bus.subscribe(max_queue=100)
    await engine.start()

    ev1 = _make_event(event_type="DISCONNECT", source="HCI", device_addr="AA:BB:CC:DD:EE:FF")
    ev2 = _make_event(event_type="DBUS_PROP", source="DBUS", device_addr="AA:BB:CC:DD:EE:FF")
    await bus.publish(ev1)
    await asyncio.sleep(0.05)
    await bus.publish(ev2)
    await asyncio.sleep(0.2)

    await engine.stop()

    matches = []
    while not output_queue.empty():
        e = output_queue.get_nowait()
        if e.event_type == "PATTERN_MATCH":
            matches.append(e)

    assert len(matches) == 1
    assert matches[0].raw_json["rule_id"] == "multi"


@pytest.mark.asyncio
async def test_rule_engine_no_fire_wrong_event():
    bus = EventBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)

    rule = Rule.from_dict({
        "id": "nope",
        "triggers": [{"event_type": "DISCONNECT"}],
        "time_window_ms": 500,
        "severity": "WARN",
    })
    engine.rules = [rule]

    output_queue = await bus.subscribe(max_queue=100)
    await engine.start()

    ev = _make_event(event_type="CONNECT")
    await bus.publish(ev)
    await asyncio.sleep(0.2)

    await engine.stop()

    matches = []
    while not output_queue.empty():
        e = output_queue.get_nowait()
        if e.event_type == "PATTERN_MATCH":
            matches.append(e)

    assert len(matches) == 0


@pytest.mark.asyncio
async def test_rule_engine_stats():
    bus = EventBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    engine = RuleEngine(bus, cfg)
    engine.rules = [Rule.from_dict({
        "id": "stats_test",
        "triggers": [{"event_type": "TEST"}],
        "time_window_ms": 500,
    })]

    stats = engine.stats
    assert "rules_loaded" in stats
    assert "total_fired" in stats
    assert "active_partials" in stats
