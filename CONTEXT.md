# CONTEXT.md — bluTruth Codebase Reference

> Self-reference for Claude Code sessions. Not user-facing docs.
> Last updated: 2026-03-14

---

## What This Is

bluTruth is a **Bluetooth stack diagnostic platform** in pure Python. It captures:
- HCI frames via `btmon` subprocess
- D-Bus signals via `dbus-next` watching `org.bluez`
- bluetoothd daemon logs via `journalctl`
- (optional) kernel driver events, sysfs polling, udev hotplug, PipeWire audio, L2CAP RTT, battery levels, Ubertooth, BLE sniffer, eBPF

All streams are normalized into a shared `Event` schema → written to SQLite + JSONL → linked by a background correlation engine with time-windowed grouping and a YAML-driven pattern rule engine.

**Status as of 2026-03-14**: Core collection + storage working, 24+ production rules, web UI functional, 193+ tests.

---

## Hard Constraints (Read First)

1. **Schema stability** — `Event` fields are a contract with a future Rust port. Never rename/remove fields. Add new data via `annotations`, `tags`, `misc1`, `misc2`. Changes must be backward-compatible.
2. **`Event.new()` factory** — always use this, never construct `Event(...)` directly.
3. **`ts_mono_us`** is the primary sort key — microseconds since process start, not wall time.
4. **SQLite WAL mode** — readers don't block writers; write path is always async via thread executor.
5. **EventBus is best-effort** — slow subscribers drop events (queue.put_nowait). This is intentional.

---

## Directory Map

```
blutruth/
  __init__.py          # version = "0.1.0"
  __main__.py          # python -m blutruth → cli.main()
  events.py            # Event dataclass + schema constants (THE contract)
  bus.py               # In-process fan-out pub/sub
  config.py            # YAML config with hot reload
  runtime.py           # Wires everything; start/stop orchestration
  cli.py               # argparse entry point (collect, serve, tail, query, etc.)
  web.py               # aiohttp HTTP API + SSE + web UI

  collectors/
    base.py            # Collector ABC
    __init__.py        # re-exports; optional ones wrapped in try/except
    hci.py             # btmon subprocess → HCI events (515 lines)
    dbus_monitor.py    # dbus-next watching org.bluez (345 lines)
    daemon_log.py      # journalctl / bluetoothd -n -d (373 lines)
    mgmt_api.py        # btmgmt --monitor (430 lines, requires root)
    kernel_driver.py   # dmesg + ftrace (570 lines, requires root)
    sysfs.py           # /sys/class/bluetooth polling (411 lines)
    udev.py            # udevadm monitor for hotplug (193 lines)
    pipewire.py        # pw-dump / pactl audio state (463 lines)
    l2ping.py          # L2CAP RTT measurement (261 lines)
    battery.py         # org.bluez.Battery1 via D-Bus (330 lines)
    ubertooth.py       # Classic BT air-level (173 lines, needs hardware)
    ble_sniffer.py     # BLE air-level (181 lines, needs hardware)
    ebpf.py            # Kernel tracepoints via eBPF (212 lines, needs CAP_BPF)

  correlation/
    engine.py          # Time-window clustering; assigns group_id (188 lines)
    rules.py           # YAML rule engine; emits PATTERN_MATCH events (~350 lines)

  storage/
    sqlite.py          # SqliteSink — batched inserts, WAL, query API (500+ lines)
    jsonl.py           # JsonlSink — append-only JSONL (57 lines)

  enrichment/
    oui.py             # OUI → manufacturer lookup (600+ entry static dict)
    hci_codes.py       # HCI error/reason/IO capability code maps

  analysis/
    history.py         # Per-device disconnect analysis across sessions

  rules/               # Built-in YAML rule packs
    security.yaml      # 24+ rules: auth loops, KNOB, BIAS, scan floods, SSP downgrade
    connection.yaml    # Connection failures, timeouts, link quality
    audio.yaml         # A2DP codec changes, transport state transitions

tests/
  conftest.py
  test_events.py       # Event schema, serialization
  test_bus.py          # pub/sub, overflow
  test_config.py       # load, merge, hot reload
  test_dbus.py         # D-Bus path parsing, property classification
  test_enrichment.py   # OUI lookup
  test_rules.py        # Rule loading, trigger matching, pattern firing
  test_sysfs.py        # Adapter state parsing
  test_hci_parser.py   # btmon output parsing (22K lines of test data)

2600/                  # Design docs (read for context on decisions)
  README.md            # Index
  architecture.md
  hci_event_taxonomy.md
  collector_design.md
  changelog.md
  session-mar05-2026.md
  session-mar09-2026.md
  session-mar10-2026.md
```

---

## Core Data Flow

```
Collectors (HCI / DBUS / DAEMON / KERNEL / PIPEWIRE / ...)
    │  Event.new(...)
    ▼
EventBus (bus.py)
    │  fan-out: each subscriber gets its own asyncio.Queue
    ├──▶ Runtime._writer_loop  →  SqliteSink + JsonlSink (concurrent writes)
    └──▶ CorrelationEngine._run  (every batch_interval_s, queries recent events,
                                   clusters by device+time, writes group_id back)
         └──▶ RuleEngine (subscribes too; emits PATTERN_MATCH events when rules fire)
```

---

## Key Files — What To Know

### `events.py`
- `SCHEMA_VERSION = 1`
- `Event` is `@dataclass(slots=True)` — use `Event.new(source=..., event_type=..., summary=..., ...)`
- Critical fields: `ts_mono_us`, `source`, `severity`, `stage`, `device_addr`, `raw_json`, `group_id`
- `raw_json` is a JSON string holding structured payload: `rssi_dbm`, `reason_code`, `reason_name`, `handle`, `key_size`, `knob_risk`, `io_capability`, `codec_name`
- `annotations` / `tags` / `misc1` / `misc2` — free-form; use these before touching normalized fields
- `from_dict()` resets `event_id` and `group_id` (for replay)

### `bus.py`
- `EventBus.publish(event)` — non-blocking; drops if queue full
- `EventBus.subscribe(max_queue=5000)` → `asyncio.Queue[Event]`
- `EventBus.stats` → `{subscribers, total_published, total_dropped}`

### `config.py`
- `Config(path).load()` → `True` if changed (mtime-guarded)
- `config.get("collectors", "hci", "enabled")` — dot-path access
- `collectors_changed()` — for selective collector restart
- Default path: `~/.blutruth/config.yaml` (auto-created)
- Key sections: `listen`, `storage`, `collectors`, `correlation`, `ui`, `security`
- `correlation.time_window_ms` default 100; `correlation.batch_interval_s` default 2.0

### `runtime.py`
- `Runtime(config_path, force_disabled, session_name)`
- Startup order: storage → session → writer task → privilege check → collectors → correlation → rules → config watch
- Shutdown order: reverse
- Core collectors (always): `HciCollector`, `DbusCollector`, `DaemonLogCollector`
- Optional (fail-open): everything else
- `Runtime.stats` → aggregate stats from all components

### `cli.py`
- Commands: `collect`, `serve`, `tail`, `status`, `query`, `sessions`, `devices`, `replay`, `export`, `history`
- `--no-hci`, `--no-dbus`, `--no-daemon` flags disable specific collectors
- Colored ANSI terminal output; verbose mode subscribes to bus

### `web.py`
- `GET /` — live multi-column UI (dark terminal aesthetic, SSE streaming)
- `GET /query` — history query panel
- `GET /device/<addr>` — device timeline
- `GET /v1/events` — JSON query with filters
- `POST /v1/events` — ingest external events
- `GET /v1/stream` — Server-Sent Events (`event: ev\ndata: {...}`)
- `GET /v1/status` — runtime stats JSON
- `GET /v1/devices/<addr>` — device timeline JSON
- NOTE: `/v1/control` endpoint is NOT implemented yet

---

## Collector Interface

```python
class MyCollector(Collector):
    name = "my"
    description = "..."
    version = "0.1.0"

    async def start(self): ...
    async def stop(self): ...

    def capabilities(self):
        return {
            "requires_root": False,
            "exclusive_resource": None,   # e.g. "hci_monitor_socket"
            "optional_root_benefits": ["..."],
            "provides": ["MY_SOURCE"],
            "depends_on": [],
        }
```

- `enabled()` reads `config.get("collectors", self.name, "enabled")`
- Runtime emits `RUNTIME` events when collectors are skipped or fail
- `source_version_tag` → `"{name}-collector-{version}"`

---

## HCI Collector Details

- Runs `btmon` as subprocess (needs `cap_net_admin` or root)
- Exclusive resource: `"hci_monitor_socket"` (only one btmon at a time)
- `_HCI_CLASSIFICATION` dict maps ~130 event names → `(severity, stage)`
- Extracts `rssi_dbm`, `reason_code`, `reason_name`, `handle` into `raw_json`
- RSSI thresholds configurable: `rssi_warn_dbm`, `rssi_error_dbm`
- btmon 5.72 quirk: crashes with `-T` flag when piped → don't use `-T`

## D-Bus Collector Details

- `dbus-next` pure Python async library
- Watches `org.bluez` on system bus
- Listens to: `PropertiesChanged`, `InterfacesAdded`, `InterfacesRemoved`
- Extracts `device_addr` from path: `/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF`
- `_classify_property_change(interface, changed)` → `(severity, stage)`
- A2DP codec bytes decoded via `_decode_a2dp_codec(val)`
- `Connected: false` → WARN; `Powered` changes → WARN

## Daemon Log Collector Details

- Default: `journalctl -u bluetooth -f -o json` (no root needed)
- Optional managed mode: stop system bluetoothd, run `bluetoothd -n -d` (root, maximum verbosity)
- `_guess_stage(text)` → stage from keyword matching
- Syslog priority → severity mapping

---

## Correlation Engine

- Runs every `batch_interval_s` (default 2.0s)
- Queries events within 5s lookback window (uncorrelated only)
- Groups by `device_addr`, sorts by `ts_mono_us`
- Sliding window: clusters events within `time_window_ms` of each other
- Cross-source clusters get a shared `group_id` (written back to SQLite)
- Watermark `_last_processed_us` prevents reprocessing

---

## Rule Engine

Rule file format:
```yaml
rules:
  - id: unique_rule_id
    name: "Display Name"
    description: "What this indicates"
    triggers:
      - source: HCI
        event_type: DISCONNECT
        conditions:
          reason_code: 8          # supports dot notation for nested keys
      - source: DBUS
        event_type: DBUS_PROP
        conditions:
          key: Connected
          value: false
    time_window_ms: 500
    same_device: true             # false = "_global_" key (cross-device)
    severity: WARN
    summary: "Pattern: {name} on {device_addr}"
    action: "Check RF link quality"
```

- `TriggerSpec.matches(ev)` checks source, event_type, nested conditions (dot notation)
- `_values_match(actual, expected)` — loose bool/int/str coercion
- Partial sequences expire after `time_window_ms`
- PATTERN_MATCH events are skipped (no infinite recursion)
- Built-in rules: `blutruth/rules/security.yaml` (24+), `connection.yaml`, `audio.yaml`

---

## SQLite Schema

```sql
-- events: core table
ts_mono_us INTEGER  -- primary sort key
source              -- HCI|DBUS|DAEMON|KERNEL|SYSFS|RUNTIME
severity            -- DEBUG|INFO|WARN|ERROR|SUSPICIOUS
stage               -- DISCOVERY|CONNECTION|HANDSHAKE|DATA|AUDIO|TEARDOWN
group_id INTEGER    -- set by correlation engine (NULL until correlated)
raw_json TEXT       -- structured payload as JSON string
annotations TEXT    -- free-form
tags_json TEXT      -- free-form

-- devices: known devices
canonical_addr UNIQUE
known_addrs, name, class, manufacturer, first_seen, last_seen

-- event_groups: correlation groups
group_id, event_id REFERENCES events(id), role TEXT

-- sessions: collection sessions
id, name, started_at, ended_at, notes
```

Pragmas: WAL mode, synchronous=NORMAL, 8MB cache.

---

## Known Gaps / Not Yet Implemented

| Feature | Status |
|---------|--------|
| `retention_days` cleanup | Parsed, loop exists, does nothing |
| `/v1/control` endpoint | Not implemented |
| btmon binary (btsnoop) parsing | Deferred (text parsing only) |
| Ubertooth/BLE sniffer/eBPF | Require hardware/caps; graceful no-op |
| YAML correlation rule packs | Phase 2; time-window only for now |
| Rule: 'negate' trigger | Not implemented |
| Rule: 'count' trigger | Not implemented |
| Rule: 'cross_device' rules | Not implemented |
| Daemon split (IPC) | Deferred (all in one process) |
| bluetoothd debug output structured parsing | Deferred |
| Metrics export (Prometheus etc.) | Not implemented |
| Test coverage: kernel_driver, pipewire, ubertooth, ble_sniffer, ebpf, l2ping, battery | Missing |

---

## Test Suite

```bash
pytest                          # 193+ tests
pytest tests/test_hci_parser.py # btmon parsing (22K lines)
pytest -x                       # stop on first failure
```

Covered: events, bus, config, dbus, enrichment, rules, sysfs, hci_parser
Not covered: kernel_driver, pipewire, ubertooth, ble_sniffer, ebpf, l2ping, battery, web, cli

---

## Config Defaults (key values)

```yaml
listen:
  host: 127.0.0.1
  port: 8484
storage:
  sqlite_path: ~/.blutruth/events.db
  jsonl_path: ~/.blutruth/events.jsonl
  retention_days: 30
collectors:
  hci.enabled: true
  dbus.enabled: true
  journalctl.enabled: true
  # all others default to their own config
correlation:
  time_window_ms: 100
  batch_interval_s: 2.0
  rules_path: ~/.blutruth/rules/
```

---

## Future Rust Port Notes

- `Event` schema and SQLite structure are designed for compatibility
- `EventBus` → `tokio::sync::broadcast`
- `Config` → `serde_yaml` + `notify` crate
- `WebServer` → `axum` with same routes
- `SqliteSink` → `rusqlite`
- `OUI table` → `phf::Map` for zero-cost lookups
- `Runtime` → long-lived `bt-diagd` daemon

---

## Source/Severity/Stage Constants

```python
SOURCES = ("HCI", "DBUS", "DAEMON", "KERNEL", "SYSFS", "UDEV",
           "UBERTOOTH", "BLE_AIR", "EBPF_KERNEL", "RUNTIME")

SEVERITIES = ("DEBUG", "INFO", "WARN", "ERROR", "SUSPICIOUS")
SEVERITY_ORDER = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "SUSPICIOUS": 4}

STAGES = ("DISCOVERY", "CONNECTION", "HANDSHAKE", "DATA", "AUDIO", "TEARDOWN")
```
