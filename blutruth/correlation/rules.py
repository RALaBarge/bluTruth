"""
blutruth.correlation.rules — Named pattern rule engine

Loads YAML rule packs and runs them against the live event stream.
When a rule's trigger sequence fires, emits a synthetic PATTERN_MATCH event.

Rule file format (YAML):
  rules:
    - id: unique_rule_id
      name: "Human-readable name"
      description: "What this pattern indicates"
      triggers:
        - source: HCI               # optional; omit to match any source
          event_type: DISCONNECT    # required
          conditions:               # optional key=value checks on raw_json
            reason_code: 8
          count: 3                  # optional; expand to N identical triggers (default: 1)
        - source: HCI
          event_type: ENCRYPT_CHANGE
          negate: true              # optional; rule fires if this does NOT occur within window
      time_window_ms: 500           # triggers must all occur within this window
      same_device: true             # all triggers must share device_addr (default: true)
      severity: WARN                # severity of the emitted PATTERN_MATCH event
      summary: "Pattern: {name} on {device_addr}"  # {fields} from first trigger event
      action: "Check RF link quality"

Trigger types:
  Normal:  rule advances when the event occurs (default)
  count:N: shorthand for repeating a trigger N times (e.g. count:3 = 3 identical triggers)
  negate:  rule advances when the event does NOT occur within time_window_ms.
           At parse time, count triggers are expanded to N identical TriggerSpec entries.
           A negate trigger CANNOT be trigger[0] (there must be something to wait after).
           When the engine reaches a negate trigger, it sets waiting_for_negate=True on
           the partial and waits. If the negated event arrives → partial is cancelled.
           If time_window_ms elapses → partial advances (and fires if it was the last trigger).

Rule loading order:
  1. Built-in rules from blutruth/rules/*.yaml (shipped with package)
  2. User rules from rules_path in config (default: ~/.blutruth/rules/*.yaml)
  User rules take precedence: if a user rule has the same id as a built-in,
  the user rule wins.

FUTURE: Add 'cross_device' rules (e.g., same name, different addr).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from blutruth.bus import EventBus
from blutruth.config import Config
from blutruth.events import Event


@dataclass
class TriggerSpec:
    event_type: str
    source: Optional[str] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    negate: bool = False  # if True: partial advances when this event does NOT appear

    def matches(self, ev: Event) -> bool:
        if self.source and ev.source != self.source:
            return False
        if ev.event_type != self.event_type:
            return False
        if self.conditions:
            raw = ev.raw_json or {}
            for k, v in self.conditions.items():
                # Support nested key lookup with dot notation
                actual = raw
                for part in k.split("."):
                    if isinstance(actual, dict):
                        actual = actual.get(part)
                    else:
                        actual = None
                        break
                # Flexible comparison: str/int/bool coercion
                if not _values_match(actual, v):
                    return False
        return True


def _values_match(actual: Any, expected: Any) -> bool:
    """Loose equality: handles bool/int/str coercion for YAML values."""
    if actual == expected:
        return True
    # bool/int: yaml parses true→True, false→False
    if isinstance(expected, bool):
        if isinstance(actual, str):
            return actual.lower() == str(expected).lower()
        return bool(actual) == expected
    # numeric comparison via string
    try:
        return float(actual) == float(expected)
    except (TypeError, ValueError):
        pass
    return str(actual).lower() == str(expected).lower()


@dataclass
class Rule:
    id: str
    name: str
    description: str
    triggers: List[TriggerSpec]
    time_window_ms: int
    same_device: bool
    severity: str
    summary_template: str
    action: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Rule":
        triggers: List[TriggerSpec] = []
        for t in d.get("triggers", []):
            spec = TriggerSpec(
                event_type=t["event_type"],
                source=t.get("source"),
                conditions=t.get("conditions", {}),
                negate=bool(t.get("negate", False)),
            )
            # count: N expands to N identical TriggerSpec entries (negate ignores count)
            repeat = 1 if spec.negate else max(1, int(t.get("count", 1)))
            triggers.extend([spec] * repeat)
        return cls(
            id=d["id"],
            name=d.get("name", d["id"]),
            description=d.get("description", ""),
            triggers=triggers,
            time_window_ms=int(d.get("time_window_ms", 500)),
            same_device=bool(d.get("same_device", True)),
            severity=d.get("severity", "WARN").upper(),
            summary_template=d.get("summary", "Pattern: {name}"),
            action=d.get("action", ""),
        )


@dataclass
class PartialMatch:
    """An in-progress rule match waiting for the next trigger."""
    rule: Rule
    matched_events: List[Event]
    next_trigger_idx: int
    started_at_mono: float          # monotonic time in seconds
    waiting_for_negate: bool = False  # True when sitting at a negate trigger


class RuleEngine:
    """
    Subscribes to the event bus and runs all loaded rules against the stream.

    Maintains per-device partial match state. Each device has a list of
    PartialMatch objects — one per rule that has seen at least one trigger
    event for that device but hasn't yet completed.

    On each event:
      1. Expire partial matches older than their rule's time_window_ms
      2. Try to advance any existing partial matches
      3. Start new partial matches for rules where this event matches trigger[0]
      4. If any partial match just completed, emit PATTERN_MATCH event

    For rules with same_device=False, device key is "_global_".
    """

    def __init__(self, bus: EventBus, config: Config) -> None:
        self.bus = bus
        self.config = config
        self.rules: List[Rule] = []
        self._task: Optional[asyncio.Task] = None
        self._queue: Optional[asyncio.Queue] = None
        self._running = False
        # key: device_addr (or "_global_") → list of PartialMatch
        self._partials: Dict[str, List[PartialMatch]] = defaultdict(list)
        self._total_fired: int = 0

    def load_rules(self, paths: List[Path]) -> int:
        """Load rules from YAML files. Returns number of rules loaded."""
        loaded: Dict[str, Rule] = {}

        # Load in order: built-ins first, then user rules (user wins on duplicate id)
        for p in paths:
            if not p.exists():
                continue
            try:
                data = yaml.safe_load(p.read_text()) or {}
                for rule_dict in data.get("rules", []):
                    try:
                        rule = Rule.from_dict(rule_dict)
                        loaded[rule.id] = rule  # later files override earlier
                    except Exception:
                        pass
            except Exception:
                pass

        self.rules = list(loaded.values())
        return len(self.rules)

    async def start(self) -> None:
        if not self.rules:
            return  # no rules, nothing to do
        self._running = True
        self._queue = await self.bus.subscribe(max_queue=5000)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._queue:
            await self.bus.unsubscribe(self._queue)
            self._queue = None

    async def _run(self) -> None:
        assert self._queue
        while self._running:
            try:
                ev = await asyncio.wait_for(self._queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await self._expire_old_partials()
                continue
            except asyncio.CancelledError:
                break

            # Skip meta events to avoid infinite loops
            if ev.event_type in ("PATTERN_MATCH", "COLLECTOR_START", "COLLECTOR_STOP",
                                  "RUNTIME_START", "CONFIG_RELOAD"):
                continue

            await self._process_event(ev)

    async def _process_event(self, ev: Event) -> None:
        now = time.monotonic()
        device_key = ev.device_addr if ev.device_addr else "_global_"

        # 1. Expire stale partials; negate-triggered ones fire now
        for pm in self._expire_partials_for(device_key, now):
            await self._emit_match(pm)

        # 2. Cancel negate-waiting partials if the negated event arrives
        updated: List[PartialMatch] = []
        for pm in self._partials[device_key]:
            if not pm.waiting_for_negate:
                updated.append(pm)
                continue
            negate_t = pm.rule.triggers[pm.next_trigger_idx]
            # Enforce same_device: only react to events from the same device
            if pm.rule.same_device:
                first_addr = pm.matched_events[0].device_addr if pm.matched_events else None
                if first_addr and ev.device_addr and first_addr != ev.device_addr:
                    updated.append(pm)
                    continue
            if negate_t.matches(ev):
                pass  # negated event appeared → cancel (not an anomaly)
            else:
                updated.append(pm)
        self._partials[device_key] = updated

        # 3. Try to advance existing non-negate partials
        completed: List[PartialMatch] = []
        for pm in list(self._partials[device_key]):
            if pm.waiting_for_negate:
                continue
            next_t = pm.rule.triggers[pm.next_trigger_idx]
            if not next_t.matches(ev):
                continue
            if pm.rule.same_device and ev.device_addr:
                first_addr = pm.matched_events[0].device_addr if pm.matched_events else None
                if first_addr and first_addr != ev.device_addr:
                    continue
            pm.matched_events.append(ev)
            pm.next_trigger_idx += 1
            if pm.next_trigger_idx >= len(pm.rule.triggers):
                completed.append(pm)
                self._partials[device_key].remove(pm)
            elif pm.rule.triggers[pm.next_trigger_idx].negate:
                pm.waiting_for_negate = True

        # 4. Start new partials for rules whose trigger[0] matches
        for rule in self.rules:
            if not rule.triggers or rule.triggers[0].negate:
                continue  # negate cannot be trigger[0]
            if not rule.triggers[0].matches(ev):
                continue
            pm = PartialMatch(
                rule=rule,
                matched_events=[ev],
                next_trigger_idx=1,
                started_at_mono=now,
            )
            if len(rule.triggers) == 1:
                completed.append(pm)
            else:
                if rule.triggers[1].negate:
                    pm.waiting_for_negate = True
                self._partials[device_key].append(pm)

        for pm in completed:
            await self._emit_match(pm)

    async def _emit_match(self, pm: PartialMatch) -> None:
        self._total_fired += 1
        rule = pm.rule
        first = pm.matched_events[0]

        # Template substitution on summary
        summary = rule.summary_template
        try:
            summary = summary.format(
                name=rule.name,
                device_addr=first.device_addr or "unknown",
                device_name=first.device_name or "",
                source=first.source,
                rule_id=rule.id,
            )
        except (KeyError, ValueError):
            summary = f"Pattern: {rule.name}"

        window_ms = (
            (pm.matched_events[-1].ts_mono_us - first.ts_mono_us) / 1000
            if len(pm.matched_events) > 1 else 0
        )

        await self.bus.publish(Event.new(
            source="RUNTIME",
            severity=rule.severity,
            event_type="PATTERN_MATCH",
            device_addr=first.device_addr,
            device_name=first.device_name,
            summary=summary,
            raw_json={
                "rule_id":        rule.id,
                "rule_name":      rule.name,
                "description":    rule.description,
                "action":         rule.action,
                "window_ms":      round(window_ms, 1),
                "trigger_count":  len(pm.matched_events),
                "matched_events": [
                    {
                        "source":     e.source,
                        "event_type": e.event_type,
                        "ts_wall":    e.ts_wall,
                        "summary":    e.summary[:120],
                    }
                    for e in pm.matched_events
                ],
            },
            tags=["pattern", rule.id],
        ))

    def _expire_partials_for(self, device_key: str, now: float) -> List[PartialMatch]:
        """
        Remove stale partials and return any negate-triggered ones that should fire.

        Negate-waiting partials fire when time_window_ms elapses without the
        negated event appearing. Normal partials are discarded at 2× the window.
        """
        active: List[PartialMatch] = []
        to_fire: List[PartialMatch] = []

        for pm in self._partials[device_key]:
            elapsed_ms = (now - pm.started_at_mono) * 1000
            if pm.waiting_for_negate:
                if elapsed_ms >= pm.rule.time_window_ms:
                    # Window expired without negated event → advance past negate trigger
                    pm.next_trigger_idx += 1
                    pm.waiting_for_negate = False
                    if pm.next_trigger_idx >= len(pm.rule.triggers):
                        to_fire.append(pm)
                    else:
                        # More triggers remain; continue (check if next is also negate)
                        if pm.rule.triggers[pm.next_trigger_idx].negate:
                            pm.waiting_for_negate = True
                        active.append(pm)
                else:
                    active.append(pm)
            else:
                if elapsed_ms < pm.rule.time_window_ms * 2:
                    active.append(pm)
                # else: normal expiry, discard silently

        self._partials[device_key] = active
        return to_fire

    async def _expire_old_partials(self) -> None:
        """Periodic expiry pass — also fires negate-triggered matches that timed out."""
        now = time.monotonic()
        for key in list(self._partials.keys()):
            for pm in self._expire_partials_for(key, now):
                await self._emit_match(pm)

    @property
    def stats(self) -> dict:
        return {
            "rules_loaded": len(self.rules),
            "total_fired":  self._total_fired,
            "active_partials": sum(len(v) for v in self._partials.values()),
        }


def load_rule_paths(config: Config) -> List[Path]:
    """
    Return list of YAML rule file paths in load order:
      1. Built-in rules (blutruth/rules/*.yaml)
      2. User rules from config's rules_path (user rules override built-ins)
    """
    paths: List[Path] = []

    # Built-in rules shipped with the package
    builtin_dir = Path(__file__).parent.parent / "rules"
    if builtin_dir.is_dir():
        paths.extend(sorted(builtin_dir.glob("*.yaml")))

    # User rules
    rules_path = config.get("correlation", "rules_path", default="~/.blutruth/rules/")
    if rules_path:
        user_dir = Path(rules_path).expanduser()
        if user_dir.is_dir():
            paths.extend(sorted(user_dir.glob("*.yaml")))

    return paths
