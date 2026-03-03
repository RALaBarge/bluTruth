# bluTruth — Unified Bluetooth Diagnostic Platform

> **Status: Discovery / Prototype Phase** — Python collection daemon is standing and writing events to SQLite. Architecture is validated.

---

## What Is This?

Most Bluetooth debugging tools look at exactly one layer of the stack in isolation. `btmon` sees HCI frames. `bluetoothctl` sees D-Bus objects. `journalctl` sees daemon log lines. None of them talk to each other, which means when a disconnect happens you are manually stitching together three different log streams and hoping the timestamps line up.

bluTruth solves this by running a single collection daemon that captures all three streams concurrently, normalizes them into a shared event schema, writes them to SQLite, and then runs a correlation engine that links related events across sources using time-windowed grouping. The result is a single database you can query to ask questions like *"show me every HCI event, D-Bus signal, and log line that touched device `DC:A6:32:xx:xx:xx` in the 500ms window around that disconnect."*

I have always had issues with BT stuff not working the way in my opinion it should.  I dont know what I liked less, my devices not working or me not knowing precisely why.  This is going to help me fix that.

---

## The Stack We're Observing

```
Your App (Spotify, etc.)
      ↓
PipeWire / PulseAudio
      ↓
BlueZ profile plugins  (A2DP · HFP · HID · ...)
      ↓
bluetoothd  ←→  D-Bus  ←→  desktop / CLI tools
      ↓
mgmt API  (netlink socket to kernel)
      ↓
core  bluetooth.ko
      ↓
btusb.ko / hci_uart.ko
      ↓
hardware
```

bluTruth currently has eyes on the **middle three layers**: HCI (via `btmon`), D-Bus (via `dbus-next` watching `org.bluez`), and bluetoothd internals (via `journalctl`). The mgmt API / kernel layer and the PipeWire handoff are documented observability gaps we will address in later phases.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Collection Daemon                  │
│                                                     │
│  HCICollector   DBusMonitor   DaemonLogCollector    │
│       │               │               │             │
│       └───────────────┼───────────────┘             │
│                       ▼                             │
│              Shared asyncio Queue                   │
│                       │                             │
│                       ▼                             │
│           Batched SQLite Writer (WAL mode)          │
│                       │                             │
│                       ▼                             │
│              events.db  (SQLite)                    │
│                       │                             │
│                       ▼                             │
│            Correlation Engine (background)          │
│         (time-window grouping, group_id links)      │
└─────────────────────────────────────────────────────┘
```

All collectors are async (`asyncio`) and feed a single queue. The database writer batches inserts to avoid per-event write overhead. The correlation engine runs background passes and stamps related events with a shared `group_id`.

---

## Package Layout

```
blutruth/
├── __init__.py
├── cli.py                  # Entry point — collect / status / tail / devices
├── db.py                   # Schema creation, WAL setup, batched writer
├── models.py               # Normalized BluetoothEvent dataclass
├── collectors/
│   ├── __init__.py
│   ├── hci.py              # Parses btmon subprocess output
│   ├── dbus_monitor.py     # Watches org.bluez via dbus-next
│   └── daemon_log.py       # Tails journalctl for bluetoothd
└── correlation/
    └── engine.py           # Time-windowed cross-source event linking
```

---

## Event Schema

Every event from every source is normalized before it hits the queue:

| Field | Description |
|---|---|
| `id` | Auto-increment primary key |
| `timestamp` | ISO-8601, microsecond precision |
| `source` | `hci` · `dbus` · `daemon` |
| `event_type` | Normalized type string |
| `severity` | `debug` · `info` · `warning` · `error` · `critical` |
| `device_addr` | BD_ADDR if known |
| `raw` | Original unparsed line / payload |
| `parsed` | JSON blob of structured fields |
| `group_id` | Correlation group (NULL until correlated) |
| `lifecycle_stage` | `discovery` · `connecting` · `connected` · `disconnecting` · `error` |
| `source_version` | Version of the source tool that produced the data |
| `parser_version` | Version of the parser that processed it |
| `annotations` | Free-form JSON for user notes during active debug sessions |
| `misc1` / `misc2` | Extra scratch fields for marking events during live triage |

The `misc1`/`misc2` fields are intentional — they exist because during active debugging you need somewhere to flag items without altering the normalized schema.  Ahh a lifetime of troubleshooting, paying off!

---

## Getting Started

### Prerequisites

```bash
# bluez tools
sudo apt install bluez

# Python deps
pip install dbus-next

# btmon requires cap_net_admin or sudo
sudo setcap cap_net_admin+eip $(which btmon)
# or just run the daemon with sudo for now
```

### Run the Daemon

```bash
# Collect from all three sources
sudo python -m blutruth collect

# Disable individual collectors
sudo python -m blutruth collect --no-hci
sudo python -m blutruth collect --no-dbus
sudo python -m blutruth collect --no-daemon-log

# Verbose — print events to stdout as they arrive
sudo python -m blutruth collect -v
```

### Query What You've Got

```bash
# Overall status
python -m blutruth status

# Live tail (like tail -f, but correlated)
python -m blutruth tail

# Show known devices
python -m blutruth devices
```

### Database Location

Events are written to `~/.local/share/blutruth/events.db` by default (WAL mode, safe for concurrent readers). You can open it with any SQLite client:

```bash
sqlite3 ~/.local/share/blutruth/events.db \
  "SELECT timestamp, source, event_type, device_addr FROM events ORDER BY timestamp DESC LIMIT 50;"
```

---

## Configuration

YAML config with hot-reload is on the roadmap. For now, collector behavior is controlled via CLI flags and constants at the top of each collector module.

---

## What's Working Now

- [x] HCI collector — parses `btmon` output into structured events with severity and lifecycle stage
- [x] D-Bus monitor — watches `org.bluez` signals (property changes, interface add/remove, device state transitions)
- [x] Daemon log collector — tails `journalctl` for bluetoothd output
- [x] Shared asyncio queue + batched SQLite writer
- [x] WAL mode for concurrent read access while daemon is running
- [x] Correlation engine — background passes link events within time windows via `group_id`
- [x] CLI: `collect`, `status`, `tail`, `devices`
- [x] Normalized event schema with annotations and misc fields

---

## Known Observability Gaps (Next Phases)

| Layer | Gap | Notes |
|---|---|---|
| mgmt API | No listener on netlink socket | Would expose kernel↔bluetoothd control path |
| PipeWire handoff | No capture of audio stream negotiation | Need to hook PipeWire IPC or use pw-dump |
| kernel internals | bluetooth.ko / btusb.ko state not visible | Would require eBPF tracepoints |
| HCI sniffer (hardware) | No air-level capture | Would need Ubertooth or similar |

---

## Planned: JSONL Flight Recorder

A parallel JSONL log alongside SQLite for portability — lets you `scp` a flat file off a device for offline analysis without needing SQLite tooling.

---

## Roadmap

1. **Now** — Python prototype, validate data collection and correlation
2. **Next** — YAML rule-pack driven correlation engine, web UI (progressive enhancement, not React SPA)
3. **Later** — Rust port, same DB schema and event format contracts, performance for embedded targets

---

## Design Philosophy

- **Correlation is the differentiator.** Individual tools already exist. The value is in connecting events across layers.
- **Modular collectors with declared capabilities.** Each collector exposes what root permissions it needs and what resources it holds exclusively, so the daemon can manage privilege safely.
- **Schema stability first.** The Python prototype and the eventual Rust port share the same database schema and event format. Don't break that contract.
- **Annotations over schema changes.** Need to mark something during a debug session? Use `annotations`, `misc1`, or `misc2`. Don't alter the normalized fields.

---

## Contributing / Development Notes

The project is currently solo (Ryan). Architecture decisions are documented in the technical spec. Before changing the event schema or collector plugin interface, read the spec — several decisions that look arbitrary have hard-won reasons behind them (the `misc1`/`misc2` fields being a good example).

When the Rust port begins, the Python implementation's database schema and event format are the source of truth. The Rust implementation must be a consumer-compatible replacement, not a redesign.
