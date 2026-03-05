# Session — March 5, 2026

## What we covered

Conversation starting from "what other information should I select that I cannot?"
through hardware sniffers, BPF/eBPF, to a full roadmap of software-only value adds.
All 7 items were then built.

---

## Observability gaps discussion

### The full stack, re-examined

```
Your App (Spotify, etc.)         ← PipeWire collector (existing)
      ↓
PipeWire / PulseAudio
      ↓
BlueZ profile plugins
      ↓
bluetoothd ←→ D-Bus              ← DbusCollector (existing)
      ↓                          ← DaemonLogCollector (existing)
mgmt API                         ← MgmtApiCollector (existing)
      ↓
core bluetooth.ko                ← KernelDriverCollector (existing, dmesg/ftrace)
      ↓                          ← EbpfCollector (mock — see below)
btusb.ko / hci_uart.ko           ← SysfsCollector, UdevCollector (new this session)
      ↓
hardware
      ↓
RF / air                         ← UbertoothCollector (mock), BleSnifferCollector (mock)
```

### Hardware sniffers — why mocked

**Ubertooth One ($120, or ~$35 AliExpress clone):**
- Chip is a TI CC2400 — a general-purpose 2.4GHz radio, NOT a BT controller
- CC2400 exposes raw promiscuous RX mode; most BT SoCs don't
- The $110 over chip cost = RF PCB layout, LNA, Cypress FX2 USB interface,
  open firmware for piconet following (clock recovery is hard)
- Implementation path: `ubertooth-rx -l <LAP>` subprocess + line parsing
- Key insight: `ubertooth-scan` (device detection mode) is easy; piconet following requires
  clock sync via `ubertooth-follow` (harder but the firmware does it)

**BLE sniffer ($5-20 nRF51/nRF52 dongle):**
- nRF51/52 are BLE-ONLY — completely different radio architecture from Classic BT
- Works: btlejack firmware on nRF51822 or nRF52840 USB dongle
- Implementation path: `btlejack -d /dev/ttyACM0 -s` subprocess + line parsing
- Advertising channel scanning (ch 37/38/39) is simple; follow-connection mode
  requires catching CONNECT_IND and extracting CRCInit/AccessAddress/HopIncrement

**Why nRF51 can't do Ubertooth's job:**
Classic BT = FHSS, 79 channels, 1MHz, GFSK/π/4-DQPSK/8DPSK.
BLE = 40 channels, 2MHz, GFSK only. Different silicon, not a firmware difference.

### eBPF — what it is and why it's mocked

**BPF** = Berkeley Packet Filter, originally for tcpdump. **eBPF** = extended BPF,
a general-purpose sandboxed VM that runs inside the Linux kernel. Attach programs to
tracepoints, kprobes, syscalls. Programs run in-kernel, push data to ring buffers.

**BCC** = BPF Compiler Collection. Embeds Clang/LLVM, compiles C to BPF bytecode
at runtime, loads into kernel, provides Python bindings. Heavy dep (~200MB LLVM).

**What it would add for bluTruth:**
- Nanosecond kernel-side timestamps (CLOCK_MONOTONIC, before any userspace copy)
- Per-process attribution: which process (spotify, bluetoothd, pipewire) triggered each HCI op
- Cross-layer timing precision for the correlation engine

**In-kernel aggregation:** NOT that useful for our volume. BT HCI traffic is low-rate.
The value is timestamps + attribution, not aggregation.

**Easiest path to real:** `bpftrace` subprocess (apt install bpftrace) — same
subprocess pattern as btmon. No bcc, no LLVM. `sudo bpftrace -e 'tracepoint:bluetooth:hci_cmd_send { printf(...) }'`
Implement as real collector without bcc dep.

---

## Piconets

One piconet = 1 master + up to 7 active slaves. No fixed number in environment —
every connected pair/group is its own piconet. A home typically has 3-10.
A scatternet is a device participating in multiple piconets simultaneously.

---

## 7 value-add items built this session

### 1. OUI Manufacturer Lookup (`blutruth/enrichment/oui.py`)
Static dict of ~600 most common manufacturers (covers >90% of real-world devices).
Falls back to OUI prefix string for unknowns. `enrich_oui(addr) -> str`.
Applied in the correlation engine and web UI to every device_addr field.

### 2. HCI Disconnect Reason Decoder (`blutruth/enrichment/hci_codes.py`)
All ~40 HCI error codes with: numeric, name, plain-English description, likely cause,
and suggested action. `decode_hci_error(code) -> dict`. Applied in HciCollector to
enrich Disconnection Complete events in `parsed` JSON. Also used by pattern rules.

### 3. Named Pattern Rules (`blutruth/correlation/rules.py` + `blutruth/rules/*.yaml`)
YAML rule pack loaded at startup. Each rule defines:
- trigger sequence: ordered list of event matchers (source, event_type, conditions)
- time_window_ms: how long the sequence can span
- severity + summary template + action hint
Pattern engine runs alongside the time-window correlator and emits a synthetic
PATTERN_MATCH event when a rule fires. Built-in rules: audio.yaml (A2DP codec
fallback, SCO issues), connection.yaml (auth loop, silent reconnect, reconnect flood),
security.yaml (device impersonation, scan flood, unexpected pairing, BIAS indicators).

### 4. l2ping Latency Monitor (`blutruth/collectors/l2ping.py`)
Runs `l2ping -c 10 -t 1 <addr>` against each currently-connected device every
`poll_interval_s` (default 30s). Parses min/avg/max RTT. Publishes as SYSFS-source
events with RTT values in parsed JSON. Maintains connected device set by watching
D-Bus DBUS_PROP Connected events on the bus. RTT timeline answers "is it RF or software?"

### 5. Battery Level Monitor (`blutruth/collectors/battery.py`)
Polls `org.bluez.Battery1.Percentage` via D-Bus for each connected device.
org.bluez.Battery1 is the BlueZ GATT Battery Service proxy — no bluetoothctl subprocess.
Polls every `poll_interval_s` (default 60s). Also watches PropertiesChanged on Battery1
for devices that push updates. Emits as SYSFS-source events with percentage + device.

### 6. Security Anomaly Detection (built-in rules in `blutruth/rules/security.yaml`)
Implemented as pattern rules rather than separate collector:
- Device impersonation: same name, different addr in short window → SUSPICIOUS
- Scan flood: same addr in LE Advertising Report >20x without connection → SUSPICIOUS
- Unexpected pairing (just-works): pairing request from unknown addr → WARN
- Auth loop: 3+ auth failures same device within 5s → ERROR
- BIAS indicator: auth requested but no encryption change → WARN

### 7. Historical Session Comparison (`blutruth/analysis/history.py` + `history` CLI command)
`blutruth history <device_addr> [--sessions N]`
Queries last N sessions that included this device. Reports:
- Disconnect count + reason breakdown per session
- Session duration, first/last seen timestamps
- Most common disconnect reasons across sessions
- Anomalies: sessions with unusually high disconnect rate
Added `query_device_sessions()` to SqliteSink.

---

## Design decisions

**OUI bundled vs. downloaded:** Bundled static dict for offline/zero-dep use.
IEEE publishes the full list at standards-oui.ieee.org — too large to inline.
600 entries covers the realistic long tail for personal BT devices.

**Pattern rules in YAML not Python:** Rules as data means users can add their own
without touching source. Same philosophy as Suricata rules. The engine is in Python;
the rule definitions live in `~/.blutruth/rules/` (user) and `blutruth/rules/` (built-in).
User rules take precedence over built-ins with the same name.

**Battery via D-Bus not bluetoothctl subprocess:** BlueZ exposes `org.bluez.Battery1`
on the system bus. Direct D-Bus access is cleaner, faster, and avoids subprocess
overhead. Only works if device implements GATT Battery Service (UUID 0x180F).

**l2ping as collector not analysis:** RTT data needs to be in the event stream so the
correlation engine can link it to concurrent HCI/D-Bus events. An offline analysis
tool would miss the cross-stream correlation.

**Security rules as pattern rules not separate collector:** Security events ARE just
patterns on the same event stream. A separate "security collector" would be artificial
separation. The pattern engine handles them cleanly with severity=SUSPICIOUS.
