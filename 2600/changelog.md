# bluTruth Changelog

Design-level notes on what changed and why. Implementation detail lives in the code.
For session-level reasoning, the "why we didn't do X" is as important as the "why we did Y."

---

## 2026-03-03 — Tier 1/2/3/4 sprint (post-0.1.0)

### Tier 1 — Broken promises

**Problem:** Four things in the codebase that claimed to exist but didn't.

---

#### `--no-*` flags actually wired (Item 1)

The argparse flags were parsed but silently thrown away — `Runtime` never saw them. Fix: `Runtime.__init__` now accepts `force_disabled: set[str]`. The start loop checks `collector.name in self._force_disabled` before `enabled()`, emitting a distinct `COLLECTOR_SKIP` event so the distinction shows up in the log.

Added `--no-mgmt`, `--no-pipewire`, `--no-kernel` while here. Both `collect` and `serve` pass the set.

Name mapping: `--no-hci` → `"hci"`, `--no-daemon` → `"journalctl"`, `--no-kernel` → `"kernel_trace"`. These match the collector `name` class attributes, not the CLI flag names, which is why the mapping table in `_force_disabled_from_args()` exists.

---

#### `query` subcommand (Item 2)

Was in the module docstring, not in the code. Added `SqliteSink.query_filtered(limit, source, device, severity, session_id)` — builds a safe parameterized WHERE clause, reuses the same row shape as `query_recent`. CLI gets `cmd_query` with `--source`, `--device`, `--severity`, `--limit`, `--json` flags.

---

#### `POST /v1/events` ingest (Item 3)

Was in the web docstring, route was never registered. `_handle_ingest` validates source/severity against known sets, constructs `Event.new(...)`, publishes to bus. Returns 201 with `{ts_wall, ts_mono_us}`. Useful for injecting synthetic events during testing or from external tooling.

---

#### Unused config fields (Item 4)

`ui.max_rows`, `ui.fallback_refresh_seconds`, `ui.live_mode_default` were in `DEFAULT_CONFIG` but nothing read them. Fixed by wiring them into `_handle_ui`'s rendered HTML. `security.local_only` now causes a stderr warning when `--host` is a non-loopback address. `retention_days` and `correlation.rules_path` explicitly documented as unimplemented in `config.py`'s module docstring with expected milestone.

---

### Tier 2 — Session tracking + data retention

**Why sessions matter:** The core diagnostic scenario is "I reproduced the bug." Without session tracking, a DB full of events has no seams — you can't ask "show me everything from the run where I provoked the KNOB downgrade." Sessions are the seams.

---

#### Session tracking (Item 6)

Schema: `sessions` table already existed, unused. Added `session_id INTEGER DEFAULT NULL` to `events` via `ALTER TABLE` migration at `SqliteSink.start()` — try/except handles existing databases. No Event dataclass change (schema contract preserved). The session_id is stamped at INSERT time from `sink._active_session_id`, so it never touches the in-flight `Event` object.

`Runtime` auto-creates a session on `start()` named `"collect YYYY-MM-DD HH:MM:SS pid=N"`. `--session NAME` overrides the name on both `collect` and `serve`. Session is closed in `stop()` before the final storage flush, so `ended_at` is reliable.

`blutruth sessions` lists sessions with event counts using a `LEFT JOIN` — sessions with zero events still show up (e.g., a failed run).

---

#### Data retention (Item 5)

`SqliteSink(retention_days=N)` starts a `_retention_loop` that fires immediately on startup then every 6 hours. The DELETE uses `WHERE ts_wall < datetime('now', '-N days')` — `ts_wall` (ISO8601 string) rather than `ts_mono_us` (process-relative) because only wall time is meaningful for "older than 30 days." Orphaned `event_groups` rows are cleaned up in the same transaction. `retention_days=0` (default) disables the loop entirely.

---

### Tier 3 — UI milestone (Items 7 + 8)

**Why now:** Live tail is useful; history is useless without a way to query it. Sessions + retention gave us the data model. The UI milestone makes it explorable.

---

#### Query panel — `GET /query`

Client-side filter form backed by `/v1/events?source=&severity=&session_id=&device=&limit=`. URL params pre-populate the form so `/query?device=AA:BB&severity=WARN` is a shareable link. Device addresses in results are `<a href="/device/...">` links.

`/v1/events` was previously a dumb wrapper around `query_recent`. Now delegates to `query_filtered` with all params, including `session_id`.

---

#### Device detail — `GET /device/<addr>`

Server-rendered. Events for the device in chronological (ascending) order, visually grouped by `group_id`. Uncorrelated events shown under "Uncorrelated" header. The grouping makes the correlation engine's output visible — you can see which events the engine linked and which it missed.

"Filter in query panel →" link passes `?device=<addr>` so you can pivot to the query view without retyping.

---

#### Live view device links

Device addresses in the live SSE columns are now `<a href="/device/...">` links. `onclick="event.stopPropagation()"` prevents the click from triggering the event row's expand/collapse toggle.

Shared CSS (`_base_css()` method) extracted so the three pages (live, query, device) stay visually consistent without ~100 lines of duplicated CSS.

---

### Tier 4 — Export & tooling (Items 11 + 12 + 13)

---

#### JSONL replay (Item 12)

`Event.from_dict()` added to `events.py`. Preserves original `ts_mono_us` and `ts_wall` (temporal relationships are maintained for re-correlation), resets `group_id` to None (events re-correlate in the new session), generates a fresh `event_id`.

`blutruth replay file.jsonl [--speed N] [--session NAME]` runs a minimal pipeline: EventBus + SqliteSink + JsonlSink, no collectors. At `--speed 0` (default) it fires all events as fast as possible. At `--speed 1.0` it sleeps between events to match original timing. Useful for:
- Testing the correlation engine against a known capture
- Re-running analysis on a JSONL from another machine
- Regression testing future rule packs

The replay pipeline deliberately avoids `Runtime` to keep it lightweight and avoid collector startup.

---

#### Export (Item 11)

`blutruth export [--format jsonl|csv] [-o file] [filters]` — full filter pass-through via `query_filtered`. JSONL outputs one row per line (machine-readable, jq-friendly). CSV writes headers + the human-relevant columns.

btsnoop/Wireshark export is not implemented. The HCI collector parses btmon's text output — raw binary HCI frames are not stored. The right path is to have btmon write a btsnoop file simultaneously during collection (noted as FUTURE in `collectors/hci.py`). Implementing a fake btsnoop from text-parsed events would produce an incorrect file.

---

#### inotify config hot-reload (Item 13)

Replaced the `asyncio.sleep(1.0)` polling loop in `runtime._config_watch_loop` with `watchfiles.awatch()`. On Linux this uses inotify; watchfiles handles the platform differences. Config changes now fire immediately rather than with up to 1s latency.

Falls back to 1s polling if watchfiles raises (path doesn't exist yet, permission issue, etc.). The mtime check in `config.load()` guards against spurious reloads in both paths.

`watchfiles>=0.21` added to `pyproject.toml` dependencies. The `_on_config_changed` body was extracted into its own method so both the watchfiles path and the polling fallback call the same logic without duplication.

---

## What's left

**Tier 3, Item 9 — YAML rule-pack correlation:** The correlation engine currently groups events by (device_addr, time_window). Semantic rules — "KNOB attack = Encryption Change with reduced key entropy in a HANDSHAKE window", "SSP downgrade = IO Capability Request followed by capability mismatch" — are the next layer of intelligence. The `correlation.rules_path` config field is reserved for this. The `event_groups` table already has a `role` column that would carry the rule name.

**Tier 3, Item 10 — Native collectors:** Remove subprocess dependencies one by one. Direct `AF_BLUETOOTH` + `BTPROTO_HCI` socket for HCI/mgmt replaces btmon. `/dev/kmsg` read loop replaces journalctl. libpipewire via ctypes or a small C extension replaces pw-dump. This is foundational for the Rust port — the Rust implementation will use these native interfaces from day one.
