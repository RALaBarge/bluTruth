# Session — March 9, 2026

## Topics covered

- Rust port decision: cancelled. Python is the sole implementation.
- All optional collectors wired to auto-start with graceful fallback
- Coverage gap analysis: what signals exist vs. what we're capturing
- USB power monitoring for hardware failure diagnosis
- RSSI + disconnect reason extraction from HCI
- HCI handle→addr mapping gap identified and closed
- KNOB attack detection via encryption key size
- IO capability extraction for SSP downgrade detection
- A2DP codec identification from D-Bus MediaTransport1
- OUI in `devices` CLI output
- `status` command completeness

---

## Rust port — cancelled

Was aspirational/fashionable, not a real need for a solo diagnostic tool.
Python async is fast enough for this workload. Maintaining two implementations
of the same thing is a tax that isn't justified. All "FUTURE (Rust port):" comments
in collector files are now stale and can be ignored.

---

## All collectors auto-start

Changed DEFAULT_CONFIG to enable all collectors by default. Graceful fallback
is per-collector, not a config gate:

- Root-required (mgmt, kernel_trace, ebpf): `capabilities()["requires_root"]=True`
  causes runtime to skip with WARN — no crash, no hard failure
- Hardware-required (ubertooth, ble_sniffer): `start()` detects missing tools,
  emits WARN + no-op — collector "runs" but does nothing
- `advanced_bluetoothd`: still False — deliberately opt-in, no collector class yet

---

## Coverage gap analysis

### What we were missing vs. why it matters

**1. HCI connection handle → device_addr mapping**

Many HCI events reference only a handle number (e.g. `Handle: 256`), not a MAC
address. `Disconnection Complete`, `Number of Completed Packets`, `Read RSSI`,
`Encryption Change` all fall into this category. Without the mapping, these events
get `device_addr=None` — they're uncorrelatable.

Fix: `HciCollector._handle_addr: Dict[int, str]` populated on `Connection Complete`
(both Classic and LE), looked up when device_addr would otherwise be None, evicted
on `Disconnection Complete`.

**2. Encryption key size (KNOB attack detection)**

The KNOB attack (CVE-2019-9506) works by reducing the BR/EDR encryption key size
during negotiation to a value low enough for brute force (< 7 bytes of entropy
= trivially broken in seconds). btmon surfaces this via `Read Encryption Key Size`
command complete: `Key size: N`. Previously not extracted.

Fix: `_KEY_SIZE_RE` extracts from HCI blocks. Added to `raw_json["key_size"]`.
Severity escalation: WARN if `key_size < 16`, ERROR if `key_size < 7`.
`raw_json["knob_risk"]` = "POSSIBLE" or "HIGH".

Normal value: 16 (128-bit AES). Anything less is worth investigating.

**3. HCI Hardware Error event (0x10)**

`HCI Event: Hardware Error` was not in `_HCI_CLASSIFICATION` — fell through to
the "Error" text pattern which happened to catch it, but it got no dedicated
classification. Now explicit: `"Hardware Error": ("ERROR", None)`. Distinguishable
from software errors in queries: `event_type=HCI_EVT AND raw_json LIKE '%Hardware Error%'`.

**4. A2DP codec identification**

`org.bluez.MediaTransport1.Codec` is a byte set when an A2DP transport is
established. Previously captured in `raw_json["changed"]["Codec"]` as a raw integer
but not decoded. Now decoded into `raw_json["codec_name"]` and appended to summary.

Codec map: 0x00=SBC, 0x01=MP3, 0x02=AAC, 0x03=ATRAC, 0xFF=Vendor (aptX/LDAC/LC3/aptX-HD).
Useful for "why does audio sound bad" — SBC when you expected AAC/aptX is a common cause.

**5. IO capability exchange**

btmon surfaces `IO Capability Request` / `IO Capability Response` events with the
capability type: `DisplayOnly`, `DisplayYesNo`, `KeyboardOnly`, `NoInputNoOutput`,
`KeyboardDisplay`. Previously classified as HANDSHAKE but capability value not extracted.

Fix: `_IO_CAP_RE` extracts capability name into `raw_json["io_capability"]`.

Diagnostic value: if both sides are capable of `DisplayYesNo` but pairing proceeds
with `NoInputNoOutput`, no MITM protection is possible. This is detectable by
comparing IO Capability Response (remote's capability) against the actual pairing
method that follows.

---

## USB hub power failure diagnosis

Scenario: BT USB adapter disappears intermittently due to hub power issues.

What bluTruth now shows when this happens:

```
SYSFS INFO  USB BT adapter hci0: Realtek [0bda:b00a] power=500mA status=active
SYSFS WARN  USB adapter hci0 power: 'active' → 'suspended' (Realtek)
SYSFS WARN  ADAPTER_REMOVED: hci0 [7C:10:C9:75:8D:37]
UDEV  ERROR udev remove: /devices/.../usb1/1-1/1-1.3/bluetooth/hci0 (bluetooth)
```

The key diagnostic: `suspended` appears before `REMOVED`. A software disconnect
or rfkill block does NOT produce a USB power state change first. This sequence
is distinctive of power starvation or hub port failure.

Contrast:
- rfkill block: RFKILL_CHANGE (soft=1) only — no USB events
- bluetoothd crash: DBUS + DAEMON events — no USB events, adapter stays in sysfs
- USB hub power failure: USB_POWER_CHANGE (suspended/error) → ADAPTER_REMOVED

### How USB power monitoring works

`SysfsCollector._poll_usb_power()` follows `/sys/class/bluetooth/hciN/device`
symlink up the sysfs tree until it finds a node with `idVendor` (the USB device,
not the USB interface). Reads:
- `power/runtime_status`: active | suspended | error | unsupported
- `bMaxPower`: power budget from USB descriptor
- `manufacturer`, `product`, `idVendor`, `idProduct`

Events emitted:
- `USB_ADAPTER_INFO`: on first discovery (startup snapshot)
- `USB_POWER_CHANGE`: when runtime_status changes, severity=INFO/WARN/ERROR

Non-USB adapters (UART/SDIO/PCIe) have no `idVendor` anywhere up the tree —
silently skipped.

---

## RSSI extraction

btmon surfaces RSSI in three contexts:

1. **Inquiry Result with RSSI** — Classic BT discovery, remote device RSSI
2. **LE Advertising Report** — BLE advertisement RSSI
3. **Read RSSI command complete** — active connection RSSI (polled by host)

All three now populate `raw_json["rssi_dbm"]`. Only #3 (active connection) triggers
severity escalation: WARN below -75 dBm, ERROR below -85 dBm (configurable in
config as `collectors.hci.rssi_warn_dbm` / `rssi_error_dbm`).

Advertising RSSI being low is normal (device is far away). Active connection RSSI
being low means the link is degraded — different signal, different response.

---

## Design decisions this session

**Handle→addr as in-memory dict, not SQLite:**
The mapping is session-scoped and high-frequency. Storing in SQLite would require
a write on every connection and a read on every handle-referencing event. The in-memory
dict is zero-latency and the data evaporates on restart (which is correct — handles
are only valid for the lifetime of a connection).

**KNOB risk levels (POSSIBLE vs HIGH):**
`key_size < 16` is POSSIBLE because some older devices negotiate shorter keys
by design (e.g. 7 is valid in the spec). `key_size < 7` is HIGH because below
that threshold brute force is feasible in seconds on consumer hardware. The
threshold for "definitely broken" is commonly cited as 1-6 bytes.

**Codec decode in D-Bus handler, not enrichment module:**
The codec table is MediaTransport1-specific and only 5 entries. An enrichment
module would be over-engineering for what's essentially a lookup in a switch statement.
If the codec list grows (Bluetooth 5.4 adds LC3 etc.), it's trivially extended here.

**IO capability: extract not flag:**
Flagging `NoInputNoOutput` as suspicious is a false positive magnet — legitimate
devices (headsets, keyboards, IoT sensors) are genuinely NOIO. The right layer
for flagging is a pattern rule: "IO Capability Response = NOIO followed by pairing
success on a device that previously used DisplayYesNo" is suspicious. Extracting
the value gives the rule engine something to work with.
