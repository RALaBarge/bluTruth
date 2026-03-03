# bluTruth Architecture & Design Decisions

## The Problem Being Solved

Every existing Bluetooth debug tool looks at exactly one layer of the stack in isolation. `btmon` sees HCI frames. `bluetoothctl` sees D-Bus objects. `journalctl` sees daemon logs. None of them speak to each other. When a device disconnects, you're manually correlating three separate log streams and praying the timestamps align.

bluTruth's core thesis: **a unified timeline beats three separate tools**. Capture all layers concurrently, normalize into one schema, then stamp related events with a shared `group_id` so you can query "everything that touched this device in the 500ms around the disconnect."

---

## Design Decisions

### 1. Single asyncio process (not separate daemons)

**Decision:** One process, one event loop, all collectors as async tasks.

**Why:** For the Python prototype, this is the right call. The overhead of IPC (sockets, serialization, framing) would cost more than it saves, and the diagnostic scenario doesn't need the fault isolation of separate processes.

**Future intent:** The `Runtime` class is deliberately shaped like a daemon's core — the event bus, storage writers, and collectors are already separated by clean interfaces. When the Rust port or daemon-split phase arrives, the collectors move into `bt-diagd`, the bus gets replaced with a unix socket + framed JSON, and the HTTP API becomes a client. This is why the code has all those `FUTURE (daemon split):` comments.

### 2. Fan-out event bus (not direct collector → storage writes)

**Decision:** Collectors publish to `EventBus`; storage sinks, the correlation engine, and the CLI tail are all subscribers with independent queues.

**Why:** This decouples collection from storage. A slow SQLite write doesn't block HCI event capture. New subscribers (SSE stream, future rule engine) can be added without touching collectors. The bus is best-effort by design — if a subscriber's queue fills, it drops events rather than blocking the publisher. The writer loop uses `max_queue=10000` because it must never drop; the CLI tail uses `max_queue=5000` and it's OK if it misses some under load.

### 3. Batched SQLite writes, not per-event commits

**Decision:** `SqliteSink` buffers events and flushes on `batch_size=100` events OR every `flush_interval_s=0.25` seconds.

**Why:** `btmon` can produce bursts of hundreds of events per second during active scanning or connection setup. Per-event commits would serialize and serialize is slow. WAL mode lets readers query during collection without blocking writes.

**Trade-off:** Up to ~250ms of events could be lost on a hard crash. Acceptable for a diagnostic tool — we're not a financial ledger.

### 4. Parallel JSONL alongside SQLite

**Decision:** Every event gets written to both `~/.blutruth/events.db` and `~/.blutruth/events.jsonl`.

**Why:** The JSONL file is portable. You can `scp events.jsonl` off a headless embedded device and analyze it on a machine without SQLite tooling. Also useful for streaming to external tools (`tail -f events.jsonl | jq ...`). The two sinks are written concurrently via `asyncio.gather`.

### 5. Correlation by time-window grouping, not explicit rules (Phase 1)

**Decision:** The correlation engine groups events by `(device_addr, time_window)` across multiple sources. No rule definitions required.

**Why:** Time-window correlation catches the most important correlations automatically — an HCI disconnect event, a D-Bus `Connected: false` property change, and a bluetoothd log line all happen within 100ms of each other and all mention the same device address. Explicit rule packs (Phase 2) will add semantic correlation (e.g., "KNOB attack pattern") on top.

**How it works:** Background task runs every `batch_interval_s` (default 2s). Queries recent uncorrelated events from SQLite. Groups by `device_addr`. Sliding window clusters events within `time_window_ms` (default 100ms). Assigns a shared `group_id` to clusters that span at least 2 sources. Writes `group_id` back to both `events.events.group_id` and the `event_groups` join table.

### 6. Config hot-reload, collectors only

**Decision:** Config is polled every 1s. If the `collectors` section changes, affected collectors restart. The bus, storage, and correlation engine are not restarted.

**Why:** You shouldn't have to restart the daemon to enable/disable a collector during a debug session. The bus and storage are stateful — restarting them would lose buffered events and close the database mid-write. Collectors are stateless enough to restart safely.

### 7. Collector `capabilities()` instead of hard-coded root checks

**Decision:** Every collector declares its privilege requirements via `capabilities()`. The `Runtime` checks these before starting and emits a clear warning when something is skipped.

**Why:** "This collector needs root" and "running managed bluetoothd stops the system bluetooth service" are things the user needs to know before they happen. Making them declarative means the `status` command can show them without starting collection, and it's easy to add new privilege types (e.g., `requires_debugfs`) without touching the runtime logic.

---

## Stack Coverage Map

```
Your App (Spotify, etc.)
      ↓
PipeWire / PulseAudio          ← PipewireCollector  (pw-dump / pactl)
      ↓
BlueZ profile plugins (A2DP · HFP · HID)
      ↓
bluetoothd  ←→  D-Bus          ← DbusCollector       (dbus-next)
                               ← DaemonLogCollector   (journalctl / managed bluetoothd -n -d)
      ↓
mgmt API (netlink)             ← MgmtApiCollector     (btmgmt --monitor / sysfs)
      ↓
core bluetooth.ko
      ↓
btusb.ko / hci_uart.ko         ← KernelDriverCollector (dmesg / ftrace / lsmod)
      ↓
HCI frames                     ← HciCollector         (btmon subprocess)
      ↓
hardware
```

---

## Current Build State (as of 0.1.0)

**Fully wired into Runtime:**
- `HciCollector` — btmon subprocess, parses multi-line event blocks, classifies to severity + lifecycle stage
- `DbusCollector` — dbus-next, watches all `org.bluez` signals, extracts device_addr from object paths
- `DaemonLogCollector` — journalctl JSON mode + optional managed `bluetoothd -n -d`

**Implemented but not yet wired into Runtime.start():**
- `MgmtApiCollector` — btmgmt --monitor + sysfs/debugfs polling. Requires root. Provides `KERNEL` source.
- `PipewireCollector` — pw-dump --monitor JSON parsing + pactl fallback. Provides `PIPEWIRE` source. No root required.
- `KernelDriverCollector` — dmesg --follow + optional ftrace tracepoints + lsmod polling. Requires root. Provides `KERNEL` source.

**Next step:** Wire the three new collectors into `Runtime.start()` and update `collectors/__init__.py` to export them.

---

## Schema Stability Contract

`events.py:Event` is the cross-implementation contract. When the Rust port begins, it must produce and consume databases that are byte-for-byte compatible with what the Python implementation produces. This means:

- **Never rename or remove fields from `Event` or the SQLite schema without a version bump and migration.**
- `schema_version` is in every row for exactly this reason.
- To add data during a debug session: use `annotations`, `tags`, or the scratch fields. Don't touch the normalized fields.
- `ts_mono_us` (microseconds since process start) is the primary sort key — **not** wall time. Wall time (`ts_wall`) is ISO-8601 for display only. This matters for ordering events that happen within the same wall-clock second.

---

## Planned Phases

| Phase | What |
|---|---|
| **Now (Python prototype)** | Collection, correlation, CLI, web UI |
| **Next** | YAML rule-pack correlation engine, device detail pages, anomaly patterns (KNOB/BIAS/SSP downgrade) |
| **Later** | Rust port — same schema, same event format, tokio runtime, axum HTTP, zbus D-Bus, btmgmt crate |
