# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bluTruth is a Bluetooth stack diagnostic platform. It captures HCI frames (via `btmon`), D-Bus signals (via `dbus-next` watching `org.bluez`), and bluetoothd daemon logs (via `journalctl`) concurrently. All three streams are normalized into a shared event schema, written to SQLite + JSONL, and linked by a background correlation engine using time-windowed grouping.

The Python prototype is the source of truth. A Rust port is planned — the database schema and `Event` format are the cross-implementation contract and must not be broken without deliberate versioning.

See `2600/` for architecture decisions, HCI event taxonomy, and design notes.

## Setup

```bash
# Uses uv — installs it if missing
bash setup.sh

# Or manually
uv venv .venv
uv pip install -e ".[dev]"
source .venv/bin/activate
```

btmon requires `cap_net_admin` or root:
```bash
sudo setcap cap_net_admin+eip $(which btmon)
```

## Commands

```bash
# Run the daemon (all collectors, foreground)
sudo blutruth collect
sudo blutruth collect -v            # verbose: print events to stdout
sudo blutruth collect --no-hci      # disable HCI collector

# Collect + web UI at http://127.0.0.1:8484
sudo blutruth serve
sudo blutruth serve --host 0.0.0.0 --port 9090

# Live tail (like tail -f)
blutruth tail
blutruth tail -s HCI                # filter by source
blutruth tail -d AA:BB:CC:DD:EE:FF  # filter by device

# Status / devices
blutruth status
blutruth devices

# Config (default: ~/.blutruth/config.yaml — auto-created on first run)
blutruth -c /path/to/config.yaml collect
```

## Tests

```bash
pytest
pytest tests/test_foo.py::test_bar   # single test
pytest -x                            # stop on first failure
```

## Architecture

### Data Flow

```
Collectors (HCI / DBUS / DAEMON / KERNEL / PIPEWIRE)
    │  publish Event objects
    ▼
EventBus  (blutruth/bus.py)
    │  fan-out: each subscriber gets its own asyncio.Queue
    ▼
Runtime._writer_loop  (blutruth/runtime.py)
    │  concurrent writes to both sinks
    ├─▶ SqliteSink  (blutruth/storage/sqlite.py)  — batched inserts, WAL mode
    └─▶ JsonlSink   (blutruth/storage/jsonl.py)   — line-delimited JSON

CorrelationEngine  (blutruth/correlation/engine.py)
    │  background task, subscribes to EventBus separately
    │  every batch_interval_s: queries SQLite for recent uncorrelated events,
    │  groups by (device_addr, time_window), assigns shared group_id
    └─▶ writes group_id back to SQLite events table + event_groups table
```

### Key Files

| File | Role |
|---|---|
| `blutruth/events.py` | `Event` dataclass — the cross-implementation schema contract (`SCHEMA_VERSION`) |
| `blutruth/runtime.py` | `Runtime` — wires all components; start/stop order matters |
| `blutruth/bus.py` | `EventBus` — in-process pub/sub; best-effort (drops if subscriber is slow) |
| `blutruth/config.py` | `Config` — YAML with defaults; hot-reload via 1s polling |
| `blutruth/collectors/base.py` | `Collector` ABC — `capabilities()` declares root/exclusive resource needs |
| `blutruth/storage/sqlite.py` | `SqliteSink` — schema DDL, batched writes, query methods |
| `blutruth/web.py` | `WebServer` — aiohttp, SSE stream at `/v1/stream`, multi-column UI at `/` |
| `blutruth/cli.py` | Entry point, argparse subcommands |

### Collector Plugin Interface

All collectors extend `Collector` (ABC in `collectors/base.py`):
- `name`, `description`, `version` class attributes
- `async start()` / `async stop()`
- `enabled()` — reads `config.get("collectors", self.name, "enabled")`
- `capabilities()` — returns dict declaring `requires_root`, `exclusive_resource`, `provides`, `depends_on`

The `Runtime` checks capabilities before starting each collector and emits `RUNTIME` events for skipped/failed collectors. Config hot-reload restarts only the collectors section.

### Event Schema Contract

`Event` in `events.py` is a `@dataclasses.dataclass(slots=True)`. Critical fields:
- `ts_mono_us` — microseconds since process start (primary sort key; **not** wall time)
- `source` — one of: `HCI | DBUS | DAEMON | KERNEL | SYSFS | RUNTIME`
- `severity` — `DEBUG | INFO | WARN | ERROR | SUSPICIOUS`
- `stage` — `DISCOVERY | CONNECTION | HANDSHAKE | DATA | AUDIO | TEARDOWN`
- `group_id` — set by correlation engine; NULL until correlated
- `annotations` / `tags` — free-form; use these instead of altering normalized fields

Always use `Event.new(...)` factory — never construct directly. The `raw_json` field holds the full structured payload; `summary` is the human-readable one-liner.

### Storage

Default paths (configurable in `~/.blutruth/config.yaml`):
- SQLite: `~/.blutruth/events.db` (WAL mode, safe for concurrent reads during collection)
- JSONL: `~/.blutruth/events.jsonl`

SQLite tables: `events`, `devices`, `event_groups`, `sessions`. The schema is defined in `SqliteSink._SCHEMA_DDL`.

### Design Constraints

- **Schema stability is a hard constraint.** The Python and Rust implementations share the same database and event format. Don't rename or remove fields; add with defaults or use `annotations`/`tags`/`misc1`/`misc2` for new data.
- **Annotations over schema changes.** During debugging, use `annotations`, `tags`, or scratch fields rather than altering normalized fields.
- The EventBus is best-effort — slow subscribers drop events. The writer loop uses `max_queue=10000`.
- SQLite writes run in a thread executor to avoid blocking the asyncio event loop.
- Config polling restarts only affected collectors; the bus, storage, and correlation continue uninterrupted.
