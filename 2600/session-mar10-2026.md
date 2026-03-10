# Session — March 10, 2026

## Topics covered

- Test suite: 193→212 tests across 8 modules
- `.gitignore` creation and pycache cleanup from git history
- YAML rule packs: prior art research; all 3 rule files rewritten from scratch
- Rule engine bug fixes: event_type values, reason_name format, BIAS rule
- HCI collector `_event_type()` rewrite: 12 specific types vs. generic HCI_EVT
- AUTH_FAILURE event_type override in `_emit_event`
- reason_name normalization (compound btmon names)

---

## Test suite

First test run for the project. 8 test modules, 212 tests, all passing.

Modules:
- `test_events` — Event factory, from_dict, to_dict/json, SEVERITY_ORDER
- `test_bus` — subscribe/publish/fan-out/drop (async)
- `test_hci_parser` — regex patterns, handle→addr mapping, KNOB thresholds, RSSI escalation, IO cap, `_event_type` specificity, AUTH_FAILURE override, reason_name normalization
- `test_dbus` — path parsing, codec decode, property classification, safe_serialize
- `test_sysfs` — USB device finding (mock sysfs tree), rfkill blocked, usb_snapshot
- `test_enrichment` — OUI lookup, HCI error decode (note: `decode_hci_error` returns code as hex string "0xNN" not int)
- `test_config` — Config.get() dot-path, _deep_merge, all DEFAULT_CONFIG values verified
- `test_rules` — TriggerSpec.matches, _values_match coercion, Rule.from_dict, RuleEngine single+multi trigger sequences

Run with: `.venv/bin/pytest tests/ -q`
Install deps: `uv pip install pytest pytest-asyncio`

---

## Prior art research: Bluetooth security rule sets

Searched SigmaHQ/sigma, Suricata, Snort, BlueZ, Bettercap, academic papers (NIST SP 800-121r2, CVE papers for KNOB/BIAS/BlueBorne).

**Key finding: no prior art exists.** The Sigma, Suricata, and Snort ecosystems have zero Bluetooth detection rules. Bluetooth operates below the IP layer and traditional network IDS tools cannot inspect it. bluTruth's YAML rule format is original.

What the research did produce:
- **KNOB (CVE-2019-9506) thresholds:** NIST SP 800-121r2 says Secure Connections Only requires 128-bit (key_size=16). Linux kernel `HCI_MIN_ENC_KEY_SIZE = 7` — kernel rejects below 7 with AUTH_FAILURE. key_size < 7 = HIGH risk (brute force feasible in seconds), key_size 7–15 = POSSIBLE (spec-compliant but weakened).
- **BIAS (CVE-2020-10135):** Requires "NOT followed by" trigger (negation). The attack fires when AUTH_COMPLETE happens WITHOUT subsequent ENCRYPT_CHANGE. Cannot be expressed with the current rule engine's sequential trigger model. Documented as known gap; needs negation trigger support.
- **Controller throttle (0x17 REPEATED_ATTEMPTS):** Hardware-level rate limiter kicking in = attacker already triggering it. Immediate SUSPICIOUS.
- **Scan flood threshold:** Research says 5/2s (2.5/s sustained) is defensible. Original rule had 5/10s which fires constantly during normal fast advertising.
- **SSP IO capability:** NoInputNoOutput (0x03) forces Just Works regardless of local capability. Legitimate for headsets/IoT, suspicious from phones/laptops.
- **MIC failure (0x3D):** Encrypted link authentication tag failed verification. Possible MITM or key compromise.

---

## Rule engine bugs found and fixed

All three issues meant **rules were silently never firing**:

### Bug 1: `_event_type()` returned `HCI_EVT` for everything

The rules used `DISCONNECT`, `AUTH_FAILURE`, `ENCRYPT_CHANGE`, etc. as event_type values. But `_event_type()` in the HCI collector returned `HCI_EVT` for all of them. The rules could never match.

Fix: `_event_type()` now checks header content first (before direction-based fallbacks), returning specific types:

```
"disconnection complete" in header → DISCONNECT
"authentication complete" in header → AUTH_COMPLETE (may be overridden)
"encryption change" in header      → ENCRYPT_CHANGE
"le advertising report" in header  → LE_ADV_REPORT
"connection complete" in header    → CONNECT  (checked AFTER disconnection complete)
"connect failed" in header         → CONNECT_FAILED
"io capability" in header          → IO_CAP
"simple pairing complete" in header → PAIR_COMPLETE
"link key notification" in header  → LINK_KEY
"smp: pairing failed" in header    → SMP_PAIR_FAILED
"smp: pairing" in header           → SMP_PAIRING
"hardware error" in header         → HCI_HARDWARE_ERROR
```

Direction-based fallbacks (`HCI_EVT`, `HCI_CMD`, `HCI_MGMT`, `HCI_INDEX`, `HCI_ACL`, `HCI_SCO`) apply only when none of the above match.

Critical: "disconnection complete" must be checked before "connection complete" since "Disconnection Complete" contains the substring "connection complete".

### Bug 2: reason_name conditions used snake_case, btmon outputs title case

Rules had:
```yaml
conditions:
  reason_name: CONNECTION_TIMEOUT
  reason_name: LMP_RESPONSE_TIMEOUT
```

But `reason_name` values extracted from btmon are title case: `"Connection Timeout"`, `"LMP Response Timeout"`. `_values_match` does case-insensitive exact string comparison — `"connection_timeout" != "connection timeout"`.

Fix: updated all rule conditions to use btmon title case:
```yaml
conditions:
  reason_name: "Connection Timeout"
  reason_name: "LMP Response Timeout"
```

### Bug 3: reason_name compound names break exact matching

btmon outputs some reason names as compound strings: `"LMP Response Timeout / LL Response Timeout (0x22)"`. The ` / LL Response Timeout` suffix means `reason_name: "LMP Response Timeout"` never matches exactly.

Fix: in `_emit_event`, normalize reason_name by taking only the first part:
```python
reason_name = reason_m.group(1).strip().split(" / ")[0].strip()
```

`"LMP Response Timeout / LL Response Timeout"` → `"LMP Response Timeout"`

### Bug 4: AUTH_FAILURE event_type never existed

The `auth_loop` rule triggered on `AUTH_FAILURE` event_type, which `_event_type()` never returned. An Authentication Complete with a failure status returned `AUTH_COMPLETE` just like a successful one.

Fix: in `_emit_event`, after determining `event_type = "AUTH_COMPLETE"`, check the full block text for a non-zero status code:

```python
if event_type == "AUTH_COMPLETE":
    _fail_re = re.compile(r"Status:\s+(?!Success)[^\(]+\(0x(?!00)[0-9a-f]{2}\)", re.I)
    if _fail_re.search(full_text):
        event_type = "AUTH_FAILURE"
```

btmon format: `"Status: Authentication Failure (0x05)"` — text first, hex in parens. The regex uses negative lookahead to exclude `Success` and `0x00`.

### Bug 5: BIAS rule logic was inverted

The BIAS rule fired when AUTH_COMPLETE was followed by ENCRYPT_CHANGE — which is the **normal** case. The attack fires when AUTH_COMPLETE happens WITHOUT ENCRYPT_CHANGE.

The rule engine's sequential trigger model cannot express "NOT followed by". Fix: removed the BIAS rule entirely. Added a comment block in security.yaml explaining the limitation and what to look for manually.

---

## 24 rules written (all now functional)

### security.yaml (12 rules)
| Rule ID | Severity | Pattern |
|---|---|---|
| `knob_attack_critical` | SUSPICIOUS | key_size HIGH (< 7) on HCI_EVT |
| `knob_attack_possible` | WARN | key_size POSSIBLE (7–15) on HCI_EVT |
| `auth_failure_unknown_device` | WARN | single AUTH_FAILURE from any device |
| `controller_throttled_auth` | SUSPICIOUS | DISCONNECT reason "Repeated Attempts" (0x17) |
| `mic_failure_disconnect` | SUSPICIOUS | DISCONNECT reason "Connection Terminated due to MIC Failure" |
| `encryption_rejected` | WARN | DISCONNECT reason "Encryption Mode Not Acceptable" |
| `insufficient_security_disconnect` | WARN | DISCONNECT reason "Insufficient Security" |
| `ssp_noio_pairing` | WARN | IO_CAP with io_capability: NoInputNoOutput |
| `unexpected_just_works_pairing` | SUSPICIOUS | SMP_PAIRING → DBUS_PROP Paired:true within 30s |
| `device_impersonation` | SUSPICIOUS | two DBUS_PROP Name events from different addresses within 5s |
| `scan_flood` | WARN | 5× LE_ADV_REPORT within 2s from same device |

### connection.yaml (8 rules)
| Rule ID | Severity | Pattern |
|---|---|---|
| `auth_loop` | ERROR | 3× AUTH_FAILURE within 5s |
| `silent_reconnect` | WARN | DISCONNECT (timeout) → DBUS Connected:true within 30s |
| `lmp_timeout_disconnect` | ERROR | DISCONNECT reason "LMP Response Timeout" |
| `repeated_timeouts` | ERROR | 3× DISCONNECT "Connection Timeout" within 120s |
| `reconnect_flood` | ERROR | Connected:true → Connected:false → Connected:true within 10s |
| `page_timeout_on_connect` | WARN | CONNECT_FAILED reason "Page Timeout" |
| `hci_disconnect_plus_dbus` | INFO | DISCONNECT → DBUS Connected:false within 500ms |
| `usb_hub_power_failure` | ERROR | USB_POWER_CHANGE → ADAPTER_REMOVED within 10s |

### audio.yaml (5 rules)
| Rule ID | Severity | Pattern |
|---|---|---|
| `a2dp_codec_downgrade_to_sbc` | WARN | DBUS_PROP with codec_name: SBC |
| `a2dp_codec_change` | INFO | 2× MediaTransport1 DBUS_PROP within 5s |
| `sco_connection_fail` | ERROR | DISCONNECT stage:AUDIO → DBUS Connected:false within 1s |
| `a2dp_suspend_resume_flood` | WARN | 2× MediaTransport1 DBUS_PROP within 2s |
| `audio_disconnect_on_rssi_drop` | WARN | HCI_EVT (rssi) → DISCONNECT within 30s |

---

## Design decisions this session

**_event_type checks header content first, direction second.** The previous implementation checked direction first, returning `HCI_MGMT` for all `@` direction events. This meant MGMT-sourced Connect Failed events couldn't be identified specifically. By checking header content first, both HCI and MGMT events with the same semantic (e.g., connection failures) get the same specific event_type.

**reason_name normalization in extraction, not in matching.** Could have modified `_values_match` to support substring matching. Chose to normalize at extraction instead — it's a data quality fix at the source, and substring matching would allow overly broad conditions (`reason_name: timeout` matching multiple distinct reasons).

**24 rules, all single or two-trigger.** No three-trigger rules in the audio file, fewer in security. The sequential trigger model means longer sequences have exponentially more ways to fail (wrong device_addr, timing expiry, intervening events). Two triggers is the sweet spot for most diagnostic patterns.

**BIAS detection acknowledged as impossible with current engine.** Rather than writing a wrong rule (as the previous BIAS rule was), documented the gap with a comment block explaining what to look for manually and what engine feature would enable proper detection. A "negate" trigger type is a planned FUTURE in rules.py.

**No Sigma/Snort rules to borrow from.** Confirmed no prior art exists in standard IDS rule ecosystems. This is not a gap in our research — Bluetooth genuinely has no established detection rule library because traditional network IDS tools don't have access to HCI data. bluTruth is filling that gap.
