# bluTruth — Unified Bluetooth Diagnostic Platform

> **Status: Active development** — Full collection daemon running, all stack layers covered, SQLite + JSONL storage, correlation engine, web UI, CLI tooling.

---

## What Is This?

Most Bluetooth debugging tools look at exactly one layer of the stack in isolation. `btmon` sees HCI frames. `bluetoothctl` sees D-Bus objects. `journalctl` sees daemon log lines. None of them talk to each other, which means when a disconnect happens you're manually stitching together three different log streams and hoping the timestamps line up.

bluTruth runs a single collection daemon that captures all stack layers concurrently, normalizes them into a shared event schema, writes them to SQLite + JSONL, and runs a correlation engine that links related events across sources using time-windowed grouping.

When something breaks, the question isn't "which log do I check?" — it's "show me everything that touched this device in the 500ms around that disconnect, across every layer simultaneously."

I have always had issues with BT stuff not working the way it should. I don't know what I liked less — my devices not working, or me not knowing precisely why. This fixes that.

---

## The Stack We're Observing

```
Your App (Spotify, etc.)         ← PipewireCollector
      ↓
PipeWire / PulseAudio
      ↓
BlueZ profile plugins
      ↓
bluetoothd ←→ D-Bus              ← DbusCollector
      ↓                          ← DaemonLogCollector
mgmt API (netlink)               ← MgmtApiCollector
      ↓
core bluetooth.ko                ← KernelDriverCollector (dmesg + ftrace)
      ↓                          ← EbpfCollector (requires root + CAP_BPF)
btusb.ko / hci_uart.ko           ← HciCollector (btmon)
      ↓                          ← SysfsCollector (adapter state + USB power)
hardware (USB hub, dongle)       ← UdevCollector (hotplug)
      ↓
RF / air                         ← UbertoothCollector (requires hardware)
                                 ← BleSnifferCollector (requires hardware)
```

Active-monitoring collectors: L2pingCollector (RTT), BatteryCollector (GATT battery level).

---

## Architecture

```
Collectors (async, one per stack layer)
    │  publish Event objects
    ▼
EventBus  (in-process fan-out pub/sub)
    │
    ├─▶ Runtime._writer_loop
    │       ├─▶ SqliteSink  (batched inserts, WAL mode)
    │       └─▶ JsonlSink   (line-delimited JSON)
    │
    └─▶ CorrelationEngine  (background, time-windowed group_id linking)
    └─▶ RuleEngine         (YAML pattern rules → PATTERN_MATCH events)
```

---

## Event Schema

Every event from every source is normalized before storage:

| Field | Description |
|---|---|
| `ts_mono_us` | Microseconds since process start (primary sort key) |
| `ts_wall` | ISO-8601 wall time |
| `source` | `HCI` · `DBUS` · `DAEMON` · `KERNEL` · `SYSFS` · `RUNTIME` |
| `severity` | `DEBUG` · `INFO` · `WARN` · `ERROR` · `SUSPICIOUS` |
| `stage` | `DISCOVERY` · `CONNECTION` · `HANDSHAKE` · `DATA` · `AUDIO` · `TEARDOWN` |
| `event_type` | Normalized type string (`HCI_EVT`, `DBUS_PROP`, `DISCONNECT`, …) |
| `device_addr` | BD_ADDR if known |
| `device_name` | Friendly name if known |
| `adapter` | `hci0` etc. |
| `group_id` | Correlation group (NULL until correlated) |
| `session_id` | Collection session (stamped at insert) |
| `raw_json` | Full structured payload — extracted fields live here |
| `raw` | Original unparsed line / payload |
| `summary` | Human-readable one-liner |
| `annotations` / `tags` | Free-form; use instead of altering normalized fields |
| `misc1` / `misc2` | Scratch fields for live triage |

`raw_json` structured fields of note:
- `rssi_dbm` — signal strength when available (HCI + D-Bus)
- `reason_code` / `reason_name` — HCI disconnect reason with plain-English decode
- `handle` — HCI connection handle (mapped to device_addr automatically)
- `key_size` / `knob_risk` — encryption key size; KNOB attack indicator
- `io_capability` — SSP IO capability type from pairing exchange
- `codec_name` — A2DP codec (SBC / AAC / aptX / LDAC / LC3) from MediaTransport1

---

## Getting Started

```bash
# Uses uv
bash setup.sh

# btmon needs cap_net_admin (or run as root)
sudo setcap cap_net_admin+eip $(which btmon)
```

---

## Commands

```bash
# Collect from all sources (foreground)
sudo blutruth collect
sudo blutruth collect -v                        # verbose: print events to stdout
sudo blutruth collect --session "reproduce-bug" # named session

# Collect + web UI at http://127.0.0.1:8484
sudo blutruth serve

# Live tail
blutruth tail
blutruth tail -s HCI                            # filter by source
blutruth tail -d AA:BB:CC:DD:EE:FF              # filter by device

# Query stored events
blutruth query --device AA:BB:CC:DD:EE:FF --severity WARN
blutruth query --source HCI --limit 500 --json

# Device history — disconnect analysis across sessions
blutruth history AA:BB:CC:DD:EE:FF
blutruth history AA:BB:CC:DD:EE:FF --sessions 10

# Sessions, devices, export
blutruth sessions
blutruth devices                                # includes OUI manufacturer
blutruth export --format csv -o events.csv --session-id 12

# Replay a JSONL capture (re-correlates into new session)
blutruth replay capture.jsonl --speed 1.0

# Status / prerequisites
blutruth status
```

---

## Configuration

`~/.blutruth/config.yaml` — auto-created on first run with all defaults.

Key settings:

```yaml
collectors:
  hci:
    rssi_warn_dbm: -75    # active-connection RSSI WARN threshold
    rssi_error_dbm: -85   # active-connection RSSI ERROR threshold
  l2ping:
    poll_interval_s: 30   # RTT check interval per connected device
    rtt_warn_ms: 50
  battery:
    poll_interval_s: 60
    low_battery_warn: 20

storage:
  sqlite_path: ~/.blutruth/events.db
  jsonl_path: ~/.blutruth/events.jsonl
  retention_days: 30

correlation:
  time_window_ms: 100
  rules_path: ~/.blutruth/rules/   # user YAML rule packs
```

Hot-reload: config changes apply within ~1 second (inotify-based, polling fallback).

---

## What Each Collector Catches

| Collector | What it sees | Root? |
|---|---|---|
| `HciCollector` | HCI frames (btmon): connect/disconnect, auth, encryption, RSSI, key size, IO capability, handle→addr mapping | No (cap_net_admin) |
| `DbusCollector` | All org.bluez signals: device appear/disappear, Connected, Paired, RSSI, A2DP codec, audio transport state | No |
| `DaemonLogCollector` | bluetoothd log output via journalctl | No |
| `MgmtApiCollector` | Kernel mgmt API (btmgmt --monitor): power state, connections at kernel level | Yes |
| `KernelDriverCollector` | dmesg BT patterns: firmware load/fail, USB errors, driver resets, module state | Yes |
| `SysfsCollector` | Adapter state, rfkill blocks, **USB power runtime_status** (hub power failure detection) | No |
| `UdevCollector` | USB hotplug: adapter insert/remove, driver bind/unbind | No |
| `EbpfCollector` | Kernel BT tracepoints (requires CAP_BPF) | Yes |
| `L2pingCollector` | Active RTT measurement per connected device | No |
| `BatteryCollector` | GATT Battery Service level via D-Bus | No |
| `PipewireCollector` | Audio pipeline state (pw-dump / pactl) | No |
| `UbertoothCollector` | Classic BT air-level (requires Ubertooth One hardware) | No |
| `BleSnifferCollector` | BLE air-level (requires nRF sniffer / btlejack) | No |

Collectors that can't start (no root, no hardware, tool not found) emit a WARN event and do nothing — they don't crash the daemon.

---

## Diagnosing Hardware Problems

### USB hub power failure

If your BT adapter disappears intermittently due to hub power issues, bluTruth shows:

```
SYSFS INFO  USB BT adapter hci0: Realtek [0bda:b00a] power=500mA status=active
SYSFS WARN  USB adapter hci0 power: 'active' → 'suspended'
SYSFS WARN  ADAPTER_REMOVED: hci0 [7C:10:C9:75:8D:37]
```

The `suspended` before `REMOVED` is the tell. A software disconnect or rfkill block won't produce a USB power state change. This sequence is distinctive of power starvation.

### RF / antenna issues

Use `blutruth history <addr>` to see disconnect reason patterns across sessions.
`CONNECTION_TIMEOUT (0x08)` and `LMP_RESPONSE_TIMEOUT (0x22)` repeating across
multiple sessions strongly suggests RF — cable, antenna, or interference.
`l2ping` RTT trends (visible in the DB) confirm or rule out latency issues.

### Security anomalies

- `knob_risk: POSSIBLE/HIGH` in HCI events → encryption key size reduced below spec
- `io_capability: NoInputNoOutput` when device previously used `DisplayYesNo` → potential SSP downgrade
- Pattern rules in `blutruth/rules/security.yaml` fire `SUSPICIOUS` events for auth loops, scan floods, unexpected pairing

---

## Design Decisions

**Correlation is the differentiator.** Individual tools already exist. The value is connecting events across layers with a shared `group_id`.

**Annotations over schema changes.** Adding new data? Use `annotations`, `tags`, `misc1`, `misc2`, or `raw_json` fields. Don't alter the normalized schema.

**Schema stability.** The SQLite schema and Event format are stable contracts. Add with defaults; don't rename or remove fields.

**Collectors declare capabilities.** Each collector exposes what root permissions it needs and what resources it holds exclusively (`hci_monitor_socket`). The runtime checks before starting.

**EventBus is best-effort.** Slow subscribers drop events. The writer loop uses `max_queue=10000`. This is intentional — the daemon stays alive even under load.

---

## Design Docs

`2600/` — architecture decisions, HCI event taxonomy, collector design notes, session logs.

```
2600/
├── README.md                  index
├── architecture.md            data flow, storage, correlation engine
├── hci_event_taxonomy.md      HCI event classification reference
├── collector_design.md        collector plugin interface decisions
├── changelog.md               tier-by-tier feature log
├── session-mar05-2026.md      observability gaps, hardware sniffers, 7 value-adds
└── session-mar09-2026.md      gap analysis, USB power, KNOB/RSSI/IO cap/codec
```
