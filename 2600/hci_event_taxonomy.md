# HCI Event Taxonomy

What btmon sees, what we capture from it, and how we classify it.

---

## Direction Markers

btmon prefixes every event with a direction indicator:

| Symbol | Direction | Meaning |
|---|---|---|
| `<` | Host → Controller | Command sent by bluetoothd to the hardware |
| `>` | Controller → Host | Event or data arriving from hardware |
| `=` | System | Index events (adapter appear/disappear) |
| `@` | Management (mgmt API) | Kernel management events |

The `HciCollector` maps these to `event_type` tags: `HCI_CMD`, `HCI_EVT`, `HCI_INDEX`, `HCI_MGMT`, `HCI_ACL`, `HCI_SCO`.

---

## Event Classification

Every btmon event block gets classified into `(severity, stage)`. The classification table is in `collectors/hci.py:_HCI_CLASSIFICATION`. Key rules:

- Most events are `INFO` — they're expected parts of normal operation.
- `Disconnection Complete`, `Device Disconnected` → `WARN` + `TEARDOWN` — worth flagging but not an error per se.
- `Connect Failed`, `SMP: Pairing Failed` → `ERROR` — something went wrong.
- `LE Advertising Report`, `Command Complete/Status`, `Number of Completed Packets` → `DEBUG` — high-volume noise, useful for deep dives but filtered by default.

### Overriding on Error Status Codes

After base classification, the parser scans the block text for error status codes:
```
Status: 0x05 (Authentication Failure)
Reason: 0x13 (Remote User Terminated Connection)
```

If a higher-severity error pattern is found, the severity is upgraded. This means a `Connection Complete` event with `Status: 0x04 (Page Timeout)` becomes `ERROR` even though `Connection Complete` is normally `INFO`.

---

## Lifecycle Stages

Every event is also assigned a `stage` from the connection lifecycle:

| Stage | What it covers |
|---|---|
| `DISCOVERY` | Inquiry, scanning, advertising — finding devices |
| `CONNECTION` | ACL connection setup, accept/reject, role negotiation |
| `HANDSHAKE` | Authentication, pairing, encryption, key exchange |
| `DATA` | GATT, ATT, RFCOMM — actual data transfer |
| `AUDIO` | SCO/eSCO setup, A2DP/HFP negotiation |
| `TEARDOWN` | Disconnection, removal, resource release |

Some events (e.g., `Command Complete`, `New Settings`) don't map to a stage and get `None`.

---

## Event Types in Detail

### Command Events (`<` direction, `HCI_CMD`)

Commands from the host to the controller. Examples:

| Command | Stage | Notes |
|---|---|---|
| `LE Set Scan Enable` | DISCOVERY | Starts/stops BLE scanning |
| `LE Set Scan Parameters` | DISCOVERY | Configures scan window/interval |
| `Create Connection` | CONNECTION | Classic BT connection initiation |
| `LE Create Connection` | CONNECTION | BLE connection initiation |
| `Disconnect` | TEARDOWN | Host-initiated disconnect |
| `Authentication Requested` | HANDSHAKE | Triggers pairing flow |
| `Set Connection Encryption` | HANDSHAKE | Enables link encryption |
| `Setup Synchronous Connection` | AUDIO | SCO/eSCO setup for HFP |

**Data in `raw_json`:** `direction`, `header` (command name), `lines` (full block text including parameters).

### Event/Status Events (`>` direction, `HCI_EVT`)

Events arriving from the controller. These are the responses and async notifications.

| Event | Stage | Notes |
|---|---|---|
| `Command Complete` | — | DEBUG; confirms a command was processed |
| `Command Status` | — | DEBUG; intermediate status for long commands |
| `Connection Complete` | CONNECTION | Reports result of connection attempt |
| `Disconnection Complete` | TEARDOWN | Contains reason code for disconnect |
| `LE Connection Complete` | CONNECTION | BLE-specific connection result |
| `LE Enhanced Connection Complete` | CONNECTION | BLE5 version with extra data |
| `LE Advertising Report` | DISCOVERY | DEBUG; one event per advertising packet seen |
| `Authentication Complete` | HANDSHAKE | Pairing result |
| `Encryption Change` | HANDSHAKE | Encryption enabled/changed on link |
| `Synchronous Connection Complete` | AUDIO | SCO/eSCO setup result |
| `Number of Completed Packets` | DATA | DEBUG; ACL/SCO flow control |

### L2CAP Signaling (`HCI_OTHER`)

Logical Link Control and Adaptation Protocol channel management. These show up within HCI ACL data packets and indicate profile-level channel setup:

| Signal | Stage | Notes |
|---|---|---|
| `L2CAP: Connection Request` | CONNECTION | Profile requesting a channel |
| `L2CAP: Connection Response` | CONNECTION | Channel accepted/rejected |
| `L2CAP: Configuration Request` | HANDSHAKE | MTU and option negotiation |
| `L2CAP: Configuration Response` | HANDSHAKE | Config accepted/rejected |
| `L2CAP: Disconnection Request` | TEARDOWN | Channel teardown |

### SMP (Security Manager Protocol)

BLE pairing and bonding. All in `HANDSHAKE` stage.

| Message | Severity | Notes |
|---|---|---|
| `SMP: Pairing Request/Response` | INFO | Pairing initiation |
| `SMP: Pairing Confirm/Random` | INFO | Numeric comparison / Just Works flow |
| `SMP: Pairing Failed` | ERROR | Pairing rejected or failed |
| `SMP: Encryption Information` | INFO | LTK distribution |
| `SMP: Security Request` | INFO | Peripheral requesting security |

### Management Events (`@` direction, `HCI_MGMT`)

These come from the kernel mgmt API layer, not raw HCI. Higher level than HCI commands.

| Event | Stage | Notes |
|---|---|---|
| `Device Connected` | CONNECTION | Mgmt-level connection confirmation |
| `Device Disconnected` | TEARDOWN | Mgmt-level disconnect |
| `Connect Failed` | CONNECTION | ERROR severity |
| `Discovering` | DISCOVERY | Discovery mode change |
| `Device Found` | DISCOVERY | DEBUG; device seen during scan |
| `New Link Key` / `New Long Term Key` | HANDSHAKE | Key created after pairing |
| `New Settings` | — | Controller settings changed |

### Index Events (`=` direction, `HCI_INDEX`)

Adapter lifecycle events. Not device-specific.

| Event | Notes |
|---|---|
| `New Index` | HCI adapter appeared (USB plug-in, power on) |
| `Open Index` | bluetoothd opened the adapter |
| `Delete Index` | Adapter removed |
| `Close Index` | WARN; adapter closed unexpectedly |

---

## What the Parser Extracts

For every event block, the parser extracts:

- **`adapter`** — from `[hciN]` tag in the header line
- **`device_addr`** — first MAC address found in the body lines (body preferred over header to avoid matching the adapter's own address on index events)
- **`severity`** — from classification table, upgraded if error status codes found
- **`stage`** — from classification table
- **`event_type`** — from direction + header pattern matching
- **`summary`** — `"{direction_arrow} {header}"`, truncated to 200 chars
- **`raw_json.lines`** — the full multi-line block as a list of strings
- **`raw`** — full block joined as a single string

---

## Known btmon Quirks

- **Do NOT use `-T` flag** when piping btmon. In btmon 5.72, the `-T` (timestamps) flag causes a buffer overflow crash when stdout is piped. The `HciCollector` intentionally omits it.
- **btmon[PID]: prefix** appears when piped. The header regex handles this with an optional prefix group.
- **Multi-line blocks** — a single logical HCI event spans multiple lines. The collector accumulates lines into a block until a new header line starts, then emits the completed block. This is the main complexity in the read loop.
- **HCI monitor socket is exclusive** — only one consumer can hold it at a time. `capabilities()` declares `exclusive_resource: "hci_monitor_socket"` so the runtime knows this.
