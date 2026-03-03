# Collector Design & Integration Notes

## The Collector ABC

Every data source implements `Collector` from `collectors/base.py`. Three required things:

1. **Class attributes:** `name` (config key), `description`, `version`
2. **`async start()` / `async stop()`**
3. **`capabilities()` dict** — declares what the collector needs and provides

The `name` class attribute is the config key: `config.get("collectors", self.name, "enabled")`. So a collector with `name = "hci"` reads `collectors.hci.enabled` from the YAML.

## capabilities() Contract

```python
def capabilities(self) -> dict:
    return {
        "requires_root": bool,       # Runtime skips if not root
        "requires_debugfs": bool,    # For future capability gating
        "exclusive_resource": str,   # e.g., "hci_monitor_socket" — only one owner
        "optional_root_benefits": list[str],  # Human-readable, shown in status output
        "provides": list[str],       # Source tags this collector emits (HCI, DBUS, etc.)
        "depends_on": list[str],     # Other collector names that must start first
    }
```

Runtime uses this to:
- Skip collectors that need root if not running as root (emits a WARN event explaining what visibility is lost)
- Show capability status in `blutruth status` output
- Future: order startup based on `depends_on`, manage exclusive resource contention

## Collector Subprocess Pattern

All subprocess-based collectors (HCI, DaemonLog, MgmtApi, KernelDriver) follow the same pattern:
1. `asyncio.create_subprocess_exec(...)` — never shell=True
2. `asyncio.create_task(self._read_loop())` — non-blocking reader
3. Read loop: `await proc.stdout.readline()` → decode → parse → `await self.bus.publish(Event.new(...))`
4. Stop: cancel task, terminate proc, wait with timeout

Important: `_running` flag must be checked in the read loop and set to `False` in `stop()` before cancelling the task — otherwise the "process exited unexpectedly" warning fires on normal shutdown.

## Source Tags

Each collector declares what source tags it emits via `capabilities()["provides"]`. These become `Event.source` values:

| Collector | source |
|---|---|
| HciCollector | `HCI` |
| DbusCollector | `DBUS` |
| DaemonLogCollector | `DAEMON` |
| MgmtApiCollector | `KERNEL` |
| KernelDriverCollector | `KERNEL` |
| PipewireCollector | `PIPEWIRE` |

Note: Both `MgmtApiCollector` and `KernelDriverCollector` emit `KERNEL` source. The correlation engine doesn't care which physical collector produced an event, only the source tag. When both are active, `KERNEL` events from the mgmt layer and from dmesg appear in the same column in the web UI and are correlated together.

## Wiring New Collectors into Runtime

Currently `Runtime.start()` in `runtime.py` only instantiates 3 collectors:
```python
self.collectors = [
    HciCollector(self.bus, self.config),
    DbusCollector(self.bus, self.config),
    DaemonLogCollector(self.bus, self.config),
]
```

The other three (`MgmtApiCollector`, `PipewireCollector`, `KernelDriverCollector`) are written and tested in isolation but not yet wired in. To add them:
1. Import from `blutruth.collectors`
2. Add to the `self.collectors` list in `Runtime.start()`
3. Export from `collectors/__init__.py`
4. Add their config sections to `DEFAULT_CONFIG` in `config.py` (with `enabled: False` as default where root is required)

## D-Bus Collector Specifics

Uses `dbus-next` (pure Python, no C extensions). The collector subscribes to:
- `type='signal',sender='org.bluez'` — all BlueZ signals
- `type='signal',interface='org.freedesktop.DBus.ObjectManager',arg0namespace='org.bluez'` — device appear/disappear

Key signal types handled:
- `PropertiesChanged` → extracts interface name and changed properties, classifies by which property changed (Connected, ServicesResolved, Paired, RSSI, etc.)
- `InterfacesAdded` → device appeared in the object tree
- `InterfacesRemoved` → device removed from object tree

Device address is extracted from the D-Bus object path: `/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF` → `AA:BB:CC:DD:EE:FF`. The `_path_to_addr()` helper in `dbus_monitor.py` handles this.

D-Bus Variant values are unwrapped via `v.value if hasattr(v, "value") else v` throughout. The `_safe_serialize()` function recursively handles all dbus-next type wrappers for JSON serialization.

## DaemonLog Collector: Two Modes

**Normal mode (default):** `journalctl -u bluetooth -f -o json`
- Non-destructive, works with the running system service
- Parses journal JSON format for structured severity (PRIORITY field), message, and metadata
- Config key: `collectors.journalctl`

**Advanced mode (opt-in):** Stops `bluetooth.service`, runs `bluetoothd -n -d` directly
- Maximum verbosity — internal debug logging not visible in normal journalctl output
- Risky: stops the system bluetooth service. The collector tracks `_managed_service_was_active` and restores the service in `stop()` via `_restore_service()`
- Config: `collectors.advanced_bluetoothd.enabled: true`

**Stage guessing from log text:** The daemon log output is unstructured text. `_guess_stage()` does keyword matching (`"pair"` → HANDSHAKE, `"disconnect"` → TEARDOWN, `"a2dp"` → AUDIO, etc.). This is approximate — improving it means building a structured parser for bluetoothd's internal log format.

## PipeWire Collector Specifics

`pw-dump --monitor --no-colors` outputs JSON arrays — each array is a complete snapshot or delta of the PipeWire object graph. The collector:
1. Accumulates lines tracking `[` / `]` bracket depth
2. When depth returns to 0, parses the complete JSON array
3. Filters to bluetooth-related objects via `_is_bluetooth_node()` (checks `device.api == "bluez5"`, `device.bus == "bluetooth"`, property name prefixes, node name patterns)
4. Diffs against `_known_bt_nodes` dict to classify changes as `added`, `changed`, or `removed`

Fallback: if `pw-dump` isn't found, tries `pactl subscribe` for PulseAudio events. The pactl events are coarser (no codec/format data) but still useful for timeline correlation.

## MgmtApi Collector Specifics

Two concurrent strategies:
1. **btmgmt --monitor** — same multi-line block pattern as btmon, but simpler (single-level indent). Event lines start with `@ EventName: payload`.
2. **sysfs polling** — reads `/sys/class/bluetooth/hciN/` and `/sys/kernel/debug/bluetooth/hciN/` every `sysfs_poll_s` (default 5s). Diffs against previous state and emits `SYSFS_CHANGE` events for any changed values.

Requires root. debugfs path `/sys/kernel/debug/bluetooth/` requires both root and debugfs to be mounted.

## Native Implementation Goal

The current collectors all shell out to external tools (`btmon`, `btmgmt`, `pw-dump`, `dmesg`). This works but has real costs:
- Each subprocess is an external dependency that may not exist or may change format
- We're parsing human-readable text that was never designed as a machine interface
- There's a parsing layer that can break on btmon version updates (the -T flag crash is one example)
- Subprocess overhead and pipe buffering add latency

The goal is to eventually replace each subprocess-based collector with a native implementation that talks directly to the kernel or system interfaces:

| Collector | Current | Native target |
|---|---|---|
| HCI | `btmon` subprocess | Open `AF_BLUETOOTH / HCI_CHANNEL_MONITOR` socket directly via Python `socket` or ctypes. Same data btmon reads, no text parsing. |
| Mgmt API | `btmgmt --monitor` subprocess | Open `AF_BLUETOOTH / HCI_CHANNEL_CONTROL` socket directly. Raw mgmt frames, parse opcodes ourselves. |
| D-Bus | `dbus-next` (already native) | Already native — no subprocess. |
| Daemon log | `journalctl` subprocess | Read journal directly via `systemd.journal` Python bindings or the journal binary format. |
| PipeWire | `pw-dump` subprocess | Use `libpipewire` Python bindings (when stable) or the PipeWire native protocol socket. |
| Kernel driver | `dmesg` subprocess | Read `/dev/kmsg` directly — it's a character device that supports `read()` and `seek()` with structured records. No parsing needed, fields are delimited. |

The Rust port is the natural moment to do this properly — `btmgmt` crate, `zbus` for D-Bus, `pipewire-rs`, direct `AF_BLUETOOTH` socket via `libc`. The Python prototype can be migrated incrementally as the native interfaces prove stable.

The schema and event format stay identical regardless of collection method. The `source_version` and `parser_version` fields on each event track which implementation produced it.

---

## KernelDriver Collector Specifics

Three concurrent strategies:
1. **dmesg --follow** — filters lines matching bluetooth kernel subsystem names (`bluetooth`, `btusb`, `btintel`, `hci_uart`, etc.)
2. **ftrace** (optional, root + debugfs) — enables `bluetooth/hci_send_frame` and `bluetooth/hci_recv_frame` tracepoints, reads `trace_pipe`. These are the raw kernel-level HCI frames *before* btmon sees them. Disabled in config by default.
3. **Module polling** — reads `/sys/module/{bluetooth,btusb,...}/` for version, refcount, and parameters. Detects module loads/unloads, which can indicate driver issues.

ftrace cleanup: `stop()` disables the trace events by writing `0` to the enable files. Always clean up — leaving ftrace enabled causes performance overhead for all processes on the system.
