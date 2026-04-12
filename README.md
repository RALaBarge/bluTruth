# bluTruth -- Unified Bluetooth Diagnostic Platform

Most Bluetooth debugging tools look at one layer of the stack in isolation. `btmon` sees HCI frames. `bluetoothctl` sees D-Bus objects. `journalctl` sees daemon log lines. None of them talk to each other, which means when a disconnect happens you're manually stitching together three different log streams and hoping the timestamps line up.

bluTruth runs a single collection daemon that captures every observable layer of the Bluetooth stack simultaneously, normalizes all events into a shared schema, writes to SQLite + JSONL, correlates related events across sources, and fires pattern rules that detect known failure modes automatically.

When something breaks, the question isn't "which log do I check?" -- it's "show me everything that touched this device in the last 500ms, across every layer."

---

## Stack Coverage

```
Your App (Spotify, etc.)         <-- PipewireCollector
      |
PipeWire / PulseAudio           <-- codec negotiation, buffer xruns, routing
      |
BlueZ profile plugins           <-- GattCollector (service/characteristic discovery)
      |
bluetoothd <--> D-Bus           <-- DbusCollector (all org.bluez signals)
      |                         <-- DaemonLogCollector (journalctl + managed mode)
mgmt API (netlink)              <-- MgmtApiCollector (btmgmt + sysfs debug)
      |
core bluetooth.ko               <-- KernelDriverCollector (dmesg + ftrace + modules)
      |                         <-- EbpfCollector (kernel tracepoints, ns timestamps)
btusb.ko / hci_uart.ko          <-- HciCollector (btmon: frames, RSSI, encryption, features)
      |                         <-- SysfsCollector (adapter state, rfkill, USB power)
hardware (USB hub, dongle)       <-- UdevCollector (hotplug: insert/remove/bind/unbind)
      |
RF / air                        <-- UbertoothCollector (Classic BT air -- requires hardware)
                                 <-- BleSnifferCollector (BLE air -- requires hardware)
```

Active-monitoring collectors: **L2pingCollector** (L2CAP round-trip time), **BatteryCollector** (GATT battery level polling).

Everything above the RF line works without specialized hardware. The two air-level collectors (Ubertooth, BLE sniffer) require dedicated radio hardware and are mock-only -- see [Not Supported](#not-supported-without-hardware) below.

---

## Setup

```bash
# Uses uv -- installs it if missing
bash setup.sh

# Or manually
uv venv .venv
uv pip install -e ".[dev]"
source .venv/bin/activate
```

btmon needs `cap_net_admin` (or root):
```bash
sudo setcap cap_net_admin+eip $(which btmon)
```

For eBPF kernel tracing (recommended):
```bash
sudo apt install python3-bpfcc bpfcc-tools
# or: sudo apt install bpftrace
```

### Dependencies

| Package | Purpose |
|---|---|
| `pyyaml` | Config file parsing |
| `dbus-next` | D-Bus monitoring (org.bluez signals, GATT introspection) |
| `aiohttp` | Web UI server + REST API |
| `watchfiles` | Config hot-reload (inotify, falls back to polling) |
| `python3-bpfcc` | eBPF kernel tracing (optional, requires root) |

Python 3.10+ required. Tested on 3.11, 3.12, 3.13.

---

## Commands

```bash
# Collect from all sources (foreground)
sudo blutruth collect
sudo blutruth collect -v                         # verbose: print events to stdout
sudo blutruth collect --no-hci                   # disable specific collectors
sudo blutruth collect --session "reproduce-bug"  # named session

# Collect + web UI
sudo blutruth serve
sudo blutruth serve --host 0.0.0.0 --port 9090

# Live tail (like tail -f)
blutruth tail
blutruth tail -s HCI                             # filter by source
blutruth tail -d AA:BB:CC:DD:EE:FF               # filter by device

# Query stored events
blutruth query --device AA:BB:CC:DD:EE:FF --severity WARN
blutruth query --source HCI --limit 500 --json

# Device history -- disconnect analysis across sessions
blutruth history AA:BB:CC:DD:EE:FF
blutruth history AA:BB:CC:DD:EE:FF --sessions 10 --json

# List sessions, devices
blutruth sessions
blutruth devices                                 # includes OUI manufacturer

# Export
blutruth export --format csv -o events.csv
blutruth export --format jsonl --session-id 12 --source HCI

# Replay a JSONL capture through correlation
blutruth replay capture.jsonl --speed 1.0 --session "replay-test"

# Status / prerequisites
blutruth status
```

### CLI Flags

| Flag | Commands | Effect |
|---|---|---|
| `-c, --config` | All | Config file path (default: `~/.blutruth/config.yaml`) |
| `-v, --verbose` | collect, serve, tail | Print events to stdout |
| `--no-hci` | collect, serve | Disable HCI collector |
| `--no-dbus` | collect, serve | Disable D-Bus collector |
| `--no-daemon` | collect, serve | Disable daemon log collector |
| `--no-mgmt` | collect, serve | Disable management API collector |
| `--no-pipewire` | collect, serve | Disable PipeWire collector |
| `--no-kernel` | collect, serve | Disable kernel driver collector |
| `--session` | collect, serve, replay | Named session label |
| `--host` | serve | Bind address (default: 127.0.0.1) |
| `--port` | serve | Bind port (default: 8484) |
| `-s, --source` | tail, query, export | Filter by event source |
| `-d, --device` | tail, query, export | Filter by device address |
| `--severity` | query, export | Minimum severity filter |
| `--json` | query, history | JSON output |
| `-l, --limit` | query, export | Max events returned |
| `-o, --output` | export | Output file path |
| `--format` | export | `jsonl` or `csv` |
| `--session-id` | export | Filter to specific session |
| `--speed` | replay | Playback speed multiplier |
| `-n, --sessions` | history | Number of sessions to analyze |

---

## Collectors

### HCI Collector

Runs `btmon` as a subprocess and parses its structured output into events with full field extraction.

| What it extracts | Details |
|---|---|
| Disconnect reasons | `reason_code` (hex) + `reason_name` (human-readable), auto-normalized |
| RSSI | `rssi_dbm` from Read RSSI, Inquiry Result, LE Advertising Report |
| Encryption key size | `key_size` with KNOB attack detection (`knob_risk: HIGH` if <7, `POSSIBLE` if <16) |
| Encryption state | `encryption_enabled` (bool) from Encryption Change events |
| IO capabilities | `io_capability` from SSP exchange (downgrade detection) |
| LMP features | Decoded feature bitmap from Read Remote Features (via enrichment module) |
| SMP pairing | `smp_io_capability`, `smp_auth_req`, `smp_auth_flags`, `smp_max_key_size` |
| CIS/BIS isochronous | `cig_id`, `cis_id`, `big_handle`, `sdu_interval_us`, `iso_interval` |
| SCO codec | `sco_codec` (CVSD, mSBC) from Synchronous Connection events |
| ACL packets | `num_completed_packets` for bandwidth tracking |
| Handle mapping | Connection handle to device address, maintained across events |

**Config:**
```yaml
collectors:
  hci:
    enabled: true
    rssi_warn_dbm: -75    # WARN when active-connection RSSI below this
    rssi_error_dbm: -85   # ERROR when active-connection RSSI below this
```

Requires: `btmon` (from `bluez-utils` or `bluez` package). Exclusive resource: `hci_monitor_socket`.

**Event types:** `DISCONNECT`, `CONNECT`, `CONNECT_FAILED`, `AUTH_COMPLETE`, `AUTH_FAILURE`, `ENCRYPT_CHANGE`, `LE_ADV_REPORT`, `IO_CAP`, `PAIR_COMPLETE`, `LINK_KEY`, `SMP_PAIRING`, `SMP_PAIR_FAILED`, `HCI_HARDWARE_ERROR`, `CIS_ESTABLISHED`, `CIS_REQUEST`, `BIG_CREATED`, `BIG_SYNC`, `BIG_SYNC_LOST`, `BIG_TERMINATED`, `SCO_CONNECT`, `SCO_CHANGED`, `REMOTE_FEATURES`, `ACL_COMPLETED`, `HCI_CMD`, `HCI_EVT`, `HCI_ACL`, `HCI_SCO`, `HCI_INDEX`, `HCI_MGMT`

### D-Bus Collector

Monitors all signals from `org.bluez` on the system D-Bus using `dbus-next`.

**Watches:**
- `PropertiesChanged` on all `/org/bluez/*` paths (Device1, Adapter1, MediaTransport1, MediaPlayer1)
- `InterfacesAdded` / `InterfacesRemoved` (device appear/disappear)
- A2DP codec byte decoding (SBC, MP3, AAC, ATRAC, Vendor)
- Property change severity/stage classification (Connected, ServicesResolved, Paired, RSSI, Powered, etc.)

**Event types:** `DBUS_PROP`, `DBUS_SIG`

No root required. No config options.

### GATT Service Discovery Collector

When a BLE device connects and resolves services, introspects the full GATT hierarchy via D-Bus.

**Discovers:**
- All `org.bluez.GattService1` interfaces (UUID, primary/secondary, mapped to known service names)
- All `org.bluez.GattCharacteristic1` interfaces (UUID, flags, mapped to known names)
- All `org.bluez.GattDescriptor1` interfaces
- Reads safe characteristic values: Device Name, Appearance, Battery Level, Model/Serial/Firmware/Hardware/Software Revision, Manufacturer Name

**Config:**
```yaml
collectors:
  gatt:
    read_characteristics: true   # set false to skip characteristic reads
```

**Event types:** `GATT_DISCOVERY` (full tree summary), `GATT_SERVICE` (per-service), `GATT_READ` (characteristic values), `GATT_ERROR`

Triggers on `ServicesResolved=true`. Deduplicates per device per session. Also scans already-connected devices on startup.

### Daemon Log Collector

Captures `bluetoothd` output with automatic stage classification.

**Two modes:**
1. **Journal mode** (default): `journalctl -u bluetooth -f -o json`
2. **Managed mode** (opt-in): Stops the system bluetooth service, runs `bluetoothd -n -d` for full debug output, restores the service on stop

Classifies log lines by keyword matching into stages: DISCOVERY, CONNECTION, HANDSHAKE, AUDIO, TEARDOWN, DATA.

**Config:**
```yaml
collectors:
  journalctl:
    enabled: true
    unit: bluetooth
    format: json
  advanced_bluetoothd:
    enabled: false    # opt-in: managed debug daemon mode
    bluetoothd_path: /usr/lib/bluetooth/bluetoothd
```

**Event type:** `LOG`

### Management API Collector

Accesses the kernel Bluetooth management interface and debugfs.

**Three strategies:**
1. `btmgmt --monitor` -- kernel management events (connections, power state)
2. Sysfs polling -- reads `/sys/kernel/debug/bluetooth/hci*/` for controller internals (features, manufacturer, HCI version, connection parameters)
3. USB power tracking -- monitors adapter USB power state for hub failure detection

**Config:**
```yaml
collectors:
  mgmt:
    enabled: true
    sysfs_poll_s: 5.0    # debugfs poll interval
```

**Event types:** `MGMT_EVT`, `SYSFS_SNAPSHOT`, `SYSFS_CHANGE`

Requires root for btmgmt socket and debugfs access.

### PipeWire / PulseAudio Collector

Monitors the audio routing layer between BlueZ and applications.

**PipeWire mode** (preferred): Parses `pw-dump --monitor --no-colors` JSON streams. Detects bluetooth node creation/destruction, codec negotiation, state changes, buffer xruns.

**PulseAudio fallback**: Parses `pactl subscribe` for sink/source/card events.

**Features:**
- Bluetooth node detection via `device.api=bluez5` property
- Codec quality ranking (enriched via A2DP codec module)
- Buffer xrun (underrun/overrun) detection via `clock.xrun-count`
- Audio format extraction: sample rate, format, channels

**Event types:** `PW_ADDED`, `PW_CHANGED`, `PW_REMOVED`, `PW_XRUN`, `PA_NEW`, `PA_CHANGE`, `PA_REMOVE`

No root required. Auto-detects available audio system.

### eBPF Kernel Tracing Collector

Attaches eBPF programs to kernel Bluetooth tracepoints for zero-overhead in-kernel event capture.

**Tracepoints:**
- `bluetooth:hci_send_frame` -- HCI frame leaving host to controller
- `bluetooth:hci_recv_frame` -- HCI frame arriving from controller

**What it adds over btmon:**
- Nanosecond kernel timestamps (CLOCK_MONOTONIC)
- Per-process attribution (PID + process name -- which process triggered each BT operation)
- ACL/SCO/ISO bandwidth aggregation (frame counts and byte totals)
- No text parsing overhead -- structured data via perf ring buffer

**Two backends:**
1. **BCC** (preferred): Python BPF bindings, structured perf buffer output
2. **bpftrace** (fallback): Subprocess with text parsing

High-frequency frames (ACL, SCO, ISO) are aggregated into periodic bandwidth summaries instead of individual events.

**Config:**
```yaml
collectors:
  ebpf:
    enabled: true       # enabled by default, gracefully skips if not root
    mock_data: false     # set true for synthetic events without root
```

Requires: root (or `CAP_BPF` + `CAP_PERFMON`), kernel 5.15+, `python3-bpfcc` or `bpftrace`.

**Event types:** `EBPF_HCI_CMD`, `EBPF_HCI_EVT`, `EBPF_ACL`, `EBPF_SCO`, `EBPF_ISO`, `EBPF_ACL_STATS`

### Kernel Driver Collector

Monitors the kernel Bluetooth subsystem via dmesg, ftrace, and module state.

**Three strategies:**
1. `dmesg --follow` filtered for bluetooth-related messages (firmware, USB, resets, errors)
2. Kernel ftrace tracepoints (opt-in: `bluetooth:hci_send_frame`, `bluetooth:hci_recv_frame`)
3. Module state polling: monitors load/unload/refcount for bluetooth, btusb, btintel, btrtl, btbcm, btmtk, btmrvl, hci_uart, rfcomm, bnep, hidp

**Config:**
```yaml
collectors:
  kernel_trace:
    enabled: true
    ftrace: false          # opt-in: enables bluetooth tracepoints
    module_poll_s: 10.0    # module state poll interval
```

**Event types:** `KERNEL_LOG`, `KERNEL_FW`, `KERNEL_USB_ENUM`, `KERNEL_RESET`, `KERNEL_ERROR`, `KERNEL_DISCONNECT`, `KERNEL_FTRACE`, `KERNEL_MODULE_SNAPSHOT`, `KERNEL_MODULE_LOAD`, `KERNEL_MODULE_UNLOAD`, `KERNEL_MODULE_CHANGE`

Requires root for dmesg follow and ftrace. Module polling works without root.

### Sysfs Collector

Polls `/sys/class/bluetooth/`, `/sys/class/rfkill/`, and USB device sysfs for adapter state.

**Monitors:**
- Adapter properties: address, type, bus, name, manufacturer
- rfkill state: soft block, hard block (filtered to bluetooth type)
- USB power: runtime_status (active/suspended/error), max power draw, vendor/product IDs

USB power state changes are the distinctive indicator of hub power failure vs. software disconnect.

**Config:**
```yaml
collectors:
  sysfs:
    enabled: true
    poll_s: 2.0    # poll interval in seconds
```

**Event types:** `SYSFS_SNAPSHOT`, `SYSFS_CHANGE`, `ADAPTER_REMOVED`, `RFKILL_CHANGE`, `USB_POWER_CHANGE`

No root required.

### Udev Collector

Monitors Bluetooth hotplug events via `udevadm monitor`.

**Actions tracked:** add, remove, change, bind, unbind, online, offline

**Event types:** `UDEV_ADD`, `UDEV_REMOVE`, `UDEV_CHANGE`, `UDEV_BIND`, `UDEV_UNBIND`

No root required.

### L2ping Collector

Active L2CAP round-trip time measurement for connected Classic BT devices.

Watches the D-Bus event stream for `Connected=true` events, then periodically pings each connected device. BLE devices are skipped (L2CAP echo not supported on BLE).

**Config:**
```yaml
collectors:
  l2ping:
    enabled: true
    poll_interval_s: 30    # seconds between ping rounds
    ping_count: 5          # pings per measurement
    ping_timeout_s: 2      # per-ping timeout
    rtt_warn_ms: 50        # WARN if avg RTT above this
    rtt_error_ms: 150      # ERROR if avg RTT above this
```

**Event types:** `L2PING_RTT`, `L2PING_TIMEOUT`, `L2PING_FAILED`

### Battery Collector

Polls `org.bluez.Battery1` for battery percentage on connected devices.

**Two modes:**
1. Polled: reads `Battery1.Percentage` every N seconds (suppresses unchanged values)
2. Reactive: watches `PropertiesChanged` on `org.bluez.Battery1`

**Config:**
```yaml
collectors:
  battery:
    enabled: true
    poll_interval_s: 60
    low_battery_warn: 20    # WARN below this percentage
    low_battery_error: 10   # ERROR below this percentage
```

**Event type:** `BATTERY_LEVEL`

---

## Enrichment Modules

Static lookup tables applied during event processing. No network calls, no runtime dependencies beyond the BT Core Spec.

### HCI Error Codes
67 codes from Bluetooth Core Spec 5.4, Vol 1, Part F. Each entry includes: name, description, likely cause, suggested action.
```python
from blutruth.enrichment.hci_codes import decode_hci_error
info = decode_hci_error(0x08)
# {"name": "CONNECTION_TIMEOUT", "description": "...", "cause": "...", "action": "..."}
```

### OUI Manufacturer Lookup
391 IEEE OUI prefixes mapped to manufacturer names. Covers >90% of real-world Bluetooth addresses.
```python
from blutruth.enrichment.oui import enrich_oui
enrich_oui("00:17:F2:AA:BB:CC")  # "Apple"
```

### LMP Feature Decoder
55 page-0 features, 4 page-1, 11 page-2 bit positions from BT Core Spec Vol 2, Part C. Decodes the 8-byte feature bitmask from Read Remote Features Complete events.
```python
from blutruth.enrichment.lmp_features import decode_lmp_features, summarize_capabilities
features = decode_lmp_features(0x875bffdbfe8fffff)
# ["3-slot packets", "5-slot packets", "encryption", "LE supported (ctrl)", "SSP", ...]

caps = summarize_capabilities(0x875bffdbfe8fffff)
# {"encryption": True, "le_supported": True, "ssp": True, "edr_2mbps": True, ...}
```

### SMP Feature Decoder
Decodes Security Manager Protocol pairing exchanges from BLE traffic.

| Function | Decodes |
|---|---|
| `decode_io_capability(0x03)` | `"NoInputNoOutput"` |
| `decode_auth_req(0x0D)` | `["bonding", "MITM", "SC"]` |
| `decode_key_dist(0x07)` | `["EncKey", "IdKey", "Sign"]` |
| `predict_pairing_method(init_io, resp_io, sc)` | Pairing method from IO capabilities |
| `assess_security(io_cap, auth_req, sc)` | Security level assessment (high/medium/low) |

Pairing method prediction covers all 25 IO capability combinations with Secure Connections awareness. Security assessment explains why a configuration is weak.

### GATT UUID Mapping
80 service UUIDs, 89 characteristic UUIDs, 12 descriptor UUIDs from Bluetooth SIG Assigned Numbers.

Includes standard services (Generic Access, Device Information, Battery, Heart Rate, HID, Audio Stream Control, etc.) and common vendor UUIDs (Apple, Google Fast Pair, Bose, Samsung, Xiaomi, Fitbit, Sony, etc.).
```python
from blutruth.enrichment.gatt_uuids import service_name, uuid_name, is_vendor_uuid
service_name("180f")                                    # "Battery Service"
service_name("0000180f-0000-1000-8000-00805f9b34fb")    # "Battery Service"
uuid_name("2a19")                                       # ("characteristic", "Battery Level")
is_vendor_uuid("fe2c")                                  # True (Google Fast Pair)
```

### USB Adapter Database
21 adapters from Intel, Realtek, Qualcomm/Atheros, Broadcom, MediaTek, CSR, TP-Link, ASUS. Each entry includes: vendor, name, chipset, driver, BT version, notes.

5 known-issue patterns covering: CSR8510 clone detection, Realtek firmware dependency, Intel firmware dependency, MediaTek early driver issues.
```python
from blutruth.enrichment.usb_ids import lookup_adapter, known_issues, adapter_summary
adapter_summary(0x8087, 0x0029)  # "Intel AX200 (Intel AX200, BT 5.0)"
known_issues(0x0a12, 0x0001)     # [{"issue": "CSR8510 clone detection", ...}, ...]
```

### A2DP Codec Decoder
Decodes codec configuration bytes from AVDTP exchanges and BlueZ MediaTransport1 properties.

| Function | Decodes |
|---|---|
| `decode_codec_id(type, vid, cid)` | Codec name (SBC, AAC, aptX, aptX HD, LDAC, LC3, Samsung Scalable) |
| `decode_sbc_config(bytes)` | Sampling freq, channel mode, block length, subbands, allocation, bitpool, estimated bitrate |
| `decode_aac_config(bytes)` | Object type, sampling freq, channels, VBR flag, bitrate |
| `decode_ldac_config(bytes)` | Sampling freq, channel mode |
| `decode_aptx_config(bytes, hd)` | Sampling freq, channel mode, nominal bitrate |
| `codec_quality_rank(name)` | 1-5 quality ranking (SBC=1, LDAC=5) |
| `is_codec_downgrade(from, to)` | True if switching to a lower-quality codec |

---

## Pattern Rules

33 YAML rules across 4 categories. Rules fire `PATTERN_MATCH` events when trigger sequences are detected in the live event stream. Each rule includes a description explaining what the pattern means and an action with specific remediation steps.

Rules support: multi-trigger sequences, time windows, same-device constraints, condition matching with dot-notation (`changed.State`), count expansion (repeat N identical triggers), and negate triggers (fire if event does NOT appear within window).

User rules in `~/.blutruth/rules/*.yaml` override built-in rules by ID.

### Security Rules (12 rules)

| Rule | Detects | Severity |
|---|---|---|
| `knob_attack_critical` | Encryption key negotiated below 7 bytes (CVE-2019-9506) | SUSPICIOUS |
| `knob_attack_possible` | Encryption key below 16 bytes | WARN |
| `auth_failure_unknown_device` | Auth failure from device not in pairing database | WARN |
| `controller_throttled_auth` | Controller rate-limiting due to Repeated Attempts (0x17) | SUSPICIOUS |
| `mic_failure_disconnect` | Message Integrity Check failure -- possible active attack | SUSPICIOUS |
| `encryption_rejected` | Remote device rejected encryption mode | WARN |
| `insufficient_security_disconnect` | Disconnect due to insufficient security level | WARN |
| `ssp_noio_pairing` | NoInputNoOutput SSP pairing (no MITM protection) | WARN |
| `unexpected_just_works_pairing` | Just Works completed when device has display/keyboard | SUSPICIOUS |
| `device_impersonation` | Same name from different address in short window | SUSPICIOUS |
| `scan_flood` | 50+ LE advertising reports in 10 seconds from one address | WARN |
| `bias_indicator` | BIAS attack pattern: role switch after auth (CVE-2020-10135) | SUSPICIOUS |

### Connection Rules (8 rules)

| Rule | Detects | Severity |
|---|---|---|
| `auth_loop` | 3+ auth failures for same device in 5s | ERROR |
| `silent_reconnect` | Connection Timeout disconnect followed by reconnect within 30s | WARN |
| `lmp_timeout_disconnect` | LMP Response Timeout -- firmware hang or severe RF | ERROR |
| `repeated_timeouts` | 3+ connection timeouts in 2 minutes | ERROR |
| `reconnect_flood` | Connect/disconnect/connect cycle in 10 seconds | ERROR |
| `page_timeout_on_connect` | Page Timeout on connection attempt | WARN |
| `hci_disconnect_plus_dbus` | HCI + D-Bus disconnect correlation (baseline check) | INFO |
| `usb_hub_power_failure` | USB power state change followed by adapter removal | ERROR |

### Audio Rules (5 rules)

| Rule | Detects | Severity |
|---|---|---|
| `a2dp_codec_downgrade_to_sbc` | A2DP fell back to SBC (lowest quality codec) | WARN |
| `a2dp_codec_change` | A2DP codec changed mid-session (causes dropout) | INFO |
| `sco_connection_fail` | SCO/eSCO disconnect -- voice audio lost | ERROR |
| `a2dp_suspend_resume_flood` | Rapid A2DP transport state cycling (buffer underrun) | WARN |
| `audio_disconnect_on_rssi_drop` | Audio disconnect following RSSI drop -- confirms RF cause | WARN |

### Profile Lifecycle Rules (8 rules)

| Rule | Detects | Severity |
|---|---|---|
| `a2dp_transport_stuck_pending` | A2DP transport in pending >10s -- audio daemon may have failed | WARN |
| `a2dp_no_transport_after_connect` | Device connected but no A2DP transport created in 15s | INFO |
| `a2dp_transport_rapid_cycle` | 4+ transport state changes in 5s -- PipeWire/PulseAudio conflict | WARN |
| `hfp_sco_setup_timeout` | No SCO link after HFP connect -- voice may not work | WARN |
| `hfp_sco_repeated_failure` | 2+ SCO connection failures -- voice calls broken | ERROR |
| `avrcp_player_not_registered` | A2DP active but no AVRCP player -- media controls won't work | INFO |
| `profile_connect_without_services` | Profile activity before ServicesResolved -- BlueZ race condition | WARN |
| `all_profiles_disconnected` | All profiles removed but ACL still up -- zombie connection | INFO |

---

## Correlation Engine

Runs as a background task, periodically scanning recent events and grouping them by `(device_addr, time_window)`. Events from multiple sources that occur within the correlation window get a shared `group_id`.

**Config:**
```yaml
correlation:
  time_window_ms: 100       # events within this window are candidates
  batch_interval_s: 2.0     # how often the correlation pass runs
  rules_path: ~/.blutruth/rules/   # user rule packs (override built-ins by ID)
```

The rule engine subscribes to the event bus separately and maintains per-device partial match state. Negate triggers fire when an expected event does NOT appear within the time window (e.g., "encryption change did not follow authentication" is suspicious).

---

## Event Schema

Every event from every source is normalized into the same 19-field structure before storage:

| Field | Type | Description |
|---|---|---|
| `schema_version` | int | Schema version (currently 1) |
| `source_version` | str | Collector version (e.g., `hci-collector-0.2.0`) |
| `parser_version` | str | Parser version |
| `event_id` | str | UUID (16 hex chars) |
| `ts_mono_us` | int | Microseconds since process start (primary sort key) |
| `ts_wall` | str | ISO-8601 wall time (display only) |
| `source` | str | `HCI`, `DBUS`, `DAEMON`, `KERNEL`, `SYSFS`, `UDEV`, `PIPEWIRE`, `EBPF_KERNEL`, `RUNTIME` |
| `severity` | str | `DEBUG`, `INFO`, `WARN`, `ERROR`, `SUSPICIOUS` |
| `stage` | str | `DISCOVERY`, `CONNECTION`, `HANDSHAKE`, `DATA`, `AUDIO`, `TEARDOWN` |
| `event_type` | str | Normalized type (`DISCONNECT`, `DBUS_PROP`, `GATT_DISCOVERY`, ...) |
| `adapter` | str | `hci0`, etc. |
| `device_addr` | str | `AA:BB:CC:DD:EE:FF` |
| `device_name` | str | Friendly name |
| `summary` | str | Human-readable one-liner |
| `raw_json` | dict | Full structured payload (all extracted fields live here) |
| `raw` | str | Original unparsed line/bytes |
| `group_id` | int | Correlation group (null until correlated) |
| `tags` | list/dict | Free-form tags |
| `annotations` | dict | User scratch space |

**Schema stability is a hard constraint.** Don't rename or remove fields. Use `annotations`, `tags`, or `raw_json` for new data.

### Notable `raw_json` fields

| Field | Source | Description |
|---|---|---|
| `rssi_dbm` | HCI | Signal strength (dBm) |
| `reason_code` / `reason_name` | HCI | Disconnect reason with plain-English decode |
| `handle` | HCI | Connection handle (mapped to device_addr) |
| `key_size` / `knob_risk` | HCI | Encryption key size; KNOB attack indicator |
| `encryption_enabled` | HCI | True/false from Encryption Change |
| `io_capability` | HCI | SSP IO capability type |
| `lmp_features` / `lmp_page` | HCI | Decoded LMP feature list |
| `smp_io_capability` / `smp_auth_flags` | HCI | SMP pairing parameters |
| `smp_max_key_size` | HCI | Maximum SMP encryption key size |
| `cig_id` / `cis_id` / `big_handle` | HCI | LE Audio isochronous parameters |
| `sdu_interval_us` / `iso_interval` | HCI | ISO timing parameters |
| `sco_codec` | HCI | SCO voice codec (CVSD, mSBC) |
| `num_completed_packets` | HCI | ACL completed packet count |
| `codec_name` | DBUS | A2DP codec (SBC/AAC/aptX/LDAC) |
| `interface` / `changed` | DBUS | D-Bus property change details |
| `services` / `characteristics` | DBUS | GATT tree from discovery |
| `ts_kernel_ns` / `pid` / `comm` | EBPF | Kernel timestamp, process attribution |
| `acl_bytes_tx` / `acl_bytes_rx` | EBPF | ACL bandwidth counters |
| `xrun` | PIPEWIRE | Buffer underrun/overrun details |
| `codec_info` | PIPEWIRE | Codec with quality rank |
| `rtt_avg_ms` / `rtt_min_ms` / `rtt_max_ms` | L2PING | Round-trip time statistics |

---

## Storage

Dual-write to SQLite (indexed, queryable) and JSONL (portable, append-only).

**SQLite tables:**
- `events` -- all events with indexes on time, device+time, source+time, severity, group_id
- `devices` -- canonical device registry with manufacturer, first/last seen
- `event_groups` -- correlation group membership with role (PRIMARY/CORRELATED)
- `sessions` -- collection session metadata

**Config:**
```yaml
storage:
  sqlite_path: ~/.blutruth/events.db
  jsonl_path: ~/.blutruth/events.jsonl
  retention_days: 30       # auto-delete old events (0 = disabled)
  size_warn_mb: 500        # warn at startup if storage exceeds this
```

SQLite runs in WAL mode with batched inserts (100 events per batch, 250ms flush interval). Writes run in a thread executor to avoid blocking the asyncio event loop.

JSONL is line-buffered and append-only. Attach it to a bug report.

Both can be rolled (archived to timestamped backup) or deleted via the web API.

---

## Configuration Reference

`~/.blutruth/config.yaml` -- auto-created on first run. Hot-reloads within ~1 second (inotify via watchfiles, polling fallback). Config changes restart only affected collectors; bus, storage, and correlation continue uninterrupted.

Validated on every load: negative time windows, zero intervals, invalid ports, and other nonsensical values log warnings.

```yaml
listen:
  host: 127.0.0.1
  port: 8484

storage:
  sqlite_path: ~/.blutruth/events.db
  jsonl_path: ~/.blutruth/events.jsonl
  retention_days: 30
  size_warn_mb: 500

collectors:
  hci:
    enabled: true
    rssi_warn_dbm: -75
    rssi_error_dbm: -85
  dbus:
    enabled: true
  journalctl:
    enabled: true
    unit: bluetooth
    format: json
  advanced_bluetoothd:
    enabled: false
    bluetoothd_path: /usr/lib/bluetooth/bluetoothd
  mgmt:
    enabled: true
    sysfs_poll_s: 5.0
  pipewire:
    enabled: true
  kernel_trace:
    enabled: true
    ftrace: false
    module_poll_s: 10.0
  sysfs:
    enabled: true
    poll_s: 2.0
  udev:
    enabled: true
  ebpf:
    enabled: true
    mock_data: false
  l2ping:
    enabled: true
    poll_interval_s: 30
    ping_count: 5
    ping_timeout_s: 2
    rtt_warn_ms: 50
    rtt_error_ms: 150
  battery:
    enabled: true
    poll_interval_s: 60
    low_battery_warn: 20
    low_battery_error: 10
  gatt:
    read_characteristics: true
  ubertooth:
    enabled: true
    mock_data: false
  ble_sniffer:
    enabled: true
    mock_data: false

correlation:
  time_window_ms: 100
  batch_interval_s: 2.0
  rules_path: ~/.blutruth/rules/

ui:
  live_mode_default: true
  fallback_refresh_seconds: 2
  max_rows: 500

security:
  local_only: true
```

---

## Diagnosing Common Problems

### USB hub power failure

```
SYSFS INFO  USB BT adapter hci0: Realtek [0bda:b00a] power=500mA status=active
SYSFS WARN  USB adapter hci0 power: 'active' -> 'suspended'
SYSFS WARN  ADAPTER_REMOVED: hci0 [7C:10:C9:75:8D:37]
```

The `suspended` before `REMOVED` is the tell. Software disconnects and rfkill blocks don't produce USB power state changes. This sequence is distinctive of power starvation.

### RF / antenna issues

`blutruth history <addr>` shows disconnect reason patterns across sessions. `CONNECTION_TIMEOUT (0x08)` and `LMP_RESPONSE_TIMEOUT (0x22)` repeating across multiple sessions points to RF. L2ping RTT trends confirm latency issues.

### Security anomalies

- `knob_risk: HIGH` -- encryption key below 7 bytes, likely KNOB attack
- `io_capability: NoInputNoOutput` when device previously used `DisplayYesNo` -- SSP downgrade
- `SUSPICIOUS` severity events from security rules (BIAS indicator, MIC failure, impersonation)

### Audio quality drops

- `a2dp_codec_downgrade_to_sbc` -- codec negotiation fell back to lowest quality
- `PW_XRUN` events -- PipeWire buffer underruns causing glitches
- `sco_connection_fail` -- HFP voice link failed (mSBC/CVSD negotiation issue)
- `a2dp_transport_stuck_pending` -- PipeWire didn't start streaming

---

## Not Supported (Without Hardware)

Two capabilities require dedicated radio hardware and are currently mock-only:

### Ubertooth One (~$150) -- Classic BT Air-Level Sniffing

Captures raw BR/EDR packets over the air between any two devices (not just your adapter). Sees: LAP/UAP/access codes, piconet hopping sequences, AFH channel maps, timing anomalies, devices rejected at RF level. Requires an [Ubertooth One](https://greatscottgadgets.com/ubertoothone/) dongle.

The collector stub exists (`blutruth/collectors/ubertooth.py`) with full capability documentation. Set `mock_data: true` in config to emit synthetic events for pipeline testing.

### nRF BLE Sniffer (~$10-15) -- BLE Air-Level Sniffing

Captures BLE advertising and connection packets between other devices. Sees: connection parameter negotiation from outside, BLE devices your adapter never responded to, advertising/connection interval verification, pairing failures before HCI involvement. Works with any [Nordic nRF52840 dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle), Adafruit nRF52840, or Micro:bit v1 with [btlejack](https://github.com/virtualabs/btlejack) firmware.

The collector stub exists (`blutruth/collectors/ble_sniffer.py`). Set `mock_data: true` for testing.

Both collectors are registered in the runtime and will activate when hardware is present and tools are installed. No code changes needed -- just plug in the hardware.

---

## Architecture

```
Collectors (async, one per stack layer)
    |  publish Event objects
    v
EventBus  (in-process fan-out pub/sub, best-effort, drops on slow subscribers)
    |
    +---> Runtime._writer_loop (stop-event drain, concurrent writes)
    |       +---> SqliteSink  (batched inserts, WAL mode, thread executor)
    |       +---> JsonlSink   (line-buffered append)
    |
    +---> CorrelationEngine  (background, time-windowed group_id linking)
    +---> RuleEngine         (YAML pattern rules -> PATTERN_MATCH events)
```

### Design Principles

- **Correlation is the differentiator.** Individual tools exist. The value is connecting events across layers with a shared `group_id`.
- **Schema stability is a hard constraint.** The Python and Rust implementations share the same database and event format. Add with defaults; don't rename or remove fields.
- **Annotations over schema changes.** Use `annotations`, `tags`, or `raw_json` for new data during debugging.
- **Collectors declare capabilities.** Each collector exposes its root requirements and exclusive resources. The runtime checks before starting.
- **EventBus is best-effort.** Slow subscribers drop events (logged every 100 drops). The writer loop uses `max_queue=10000`. The daemon stays alive under load.
- **Graceful degradation.** Collectors that can't start (no root, no hardware, missing tool) emit a notice and do nothing. They don't crash the daemon.

---

## Tests

321 tests covering events, bus, config, collectors, storage, correlation, enrichment, and rules.

```bash
pytest                           # run all
pytest tests/test_foo.py         # single module
pytest -x                        # stop on first failure
```

CI runs on Python 3.11, 3.12, 3.13 via GitHub Actions.

---

## Design Docs

`2600/` -- architecture decisions, HCI event taxonomy, collector design notes, session logs.
