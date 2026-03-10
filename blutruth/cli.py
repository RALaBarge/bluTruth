"""
blutruth.cli — Command-line interface

Commands:
  collect   Start the collection daemon (foreground)
  status    Show runtime status and collector health
  tail      Stream events in real time (like tail -f)
  devices   List all known devices with event counts + OUI manufacturer
  query     Query stored events with filters
  sessions  List recorded collection sessions
  replay    Replay a JSONL file through storage (re-correlates, new session)
  export    Export events to JSONL or CSV with filters
  history   Per-device session history with disconnect analysis
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path
from typing import Optional

from blutruth.config import Config
from blutruth.events import Event
from blutruth.runtime import Runtime


# --- ANSI colors for terminal output ---

_COLORS = {
    "DEBUG":      "\033[90m",      # gray
    "INFO":       "\033[37m",      # white
    "WARN":       "\033[33m",      # yellow
    "ERROR":      "\033[31m",      # red
    "SUSPICIOUS": "\033[35m",      # magenta
    "RESET":      "\033[0m",
}

_SOURCE_COLORS = {
    "HCI":     "\033[36m",   # cyan
    "DBUS":    "\033[34m",   # blue
    "DAEMON":  "\033[32m",   # green
    "KERNEL":  "\033[33m",   # yellow
    "SYSFS":   "\033[35m",   # magenta
    "RUNTIME": "\033[90m",   # gray
}


def _format_event(ev: Event, verbose: bool = False) -> str:
    """Format a single event for terminal display."""
    sev_color = _COLORS.get(ev.severity, "")
    src_color = _SOURCE_COLORS.get(ev.source, "")
    reset = _COLORS["RESET"]

    # Compact time display
    wall_short = ev.ts_wall[11:23] if len(ev.ts_wall) > 23 else ev.ts_wall

    device = ""
    if ev.device_addr:
        device = f" [{ev.device_addr}"
        if ev.device_name:
            device += f" ({ev.device_name})"
        device += "]"

    stage = f" {ev.stage}" if ev.stage else ""

    line = (
        f"{sev_color}{wall_short}{reset} "
        f"{src_color}{ev.source:7s}{reset} "
        f"{sev_color}{ev.severity:5s}{reset}"
        f"{stage}"
        f"{device} "
        f"{ev.summary}"
    )

    if verbose:
        line += f"\n    {json.dumps(ev.raw_json, ensure_ascii=False, default=str)}"

    return line


def _force_disabled_from_args(args: argparse.Namespace) -> set:
    """Build the set of collector names to forcibly disable from --no-* flags."""
    mapping = [
        ("no_hci",        "hci"),
        ("no_dbus",       "dbus"),
        ("no_daemon",     "journalctl"),
        ("no_mgmt",       "mgmt"),
        ("no_pipewire",   "pipewire"),
        ("no_kernel",     "kernel_trace"),
        ("no_sysfs",      "sysfs"),
        ("no_udev",       "udev"),
        ("no_ubertooth",  "ubertooth"),
        ("no_ble_sniffer","ble_sniffer"),
        ("no_ebpf",       "ebpf"),
        ("no_l2ping",     "l2ping"),
        ("no_battery",    "battery"),
    ]
    return {name for flag, name in mapping if getattr(args, flag, False)}


async def cmd_collect(args: argparse.Namespace) -> None:
    """Start the collection daemon in the foreground."""
    runtime = Runtime(
        Path(args.config),
        force_disabled=_force_disabled_from_args(args),
        session_name=getattr(args, "session", None) or None,
    )
    stop_event = asyncio.Event()

    def handle_signal():
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    await runtime.start()

    # If verbose, also subscribe to print events
    if args.verbose:
        queue = await runtime.bus.subscribe(max_queue=5000)
        print_task = asyncio.create_task(_print_events(queue, verbose=True))
    else:
        queue = None
        print_task = None

    print(f"bluTruth collecting → {runtime.sqlite.path}", file=sys.stderr)
    print(f"                    → {runtime.jsonl.path}", file=sys.stderr)
    print(f"Config: {runtime.config.path}", file=sys.stderr)
    print("Press Ctrl+C to stop.\n", file=sys.stderr)

    await stop_event.wait()

    print("\nShutting down...", file=sys.stderr)

    if print_task:
        print_task.cancel()
        try:
            await print_task
        except asyncio.CancelledError:
            pass
    if queue:
        await runtime.bus.unsubscribe(queue)

    await runtime.stop()

    stats = runtime.stats
    print(f"\nSession stats:", file=sys.stderr)
    print(f"  Events written (SQLite): {stats['sqlite']['total_written']}", file=sys.stderr)
    print(f"  Events written (JSONL):  {stats['jsonl']['total_written']}", file=sys.stderr)
    print(f"  Correlation groups:      {stats['correlation']['total_groups_created']}", file=sys.stderr)
    print(f"  Bus drops:               {stats['bus']['total_dropped']}", file=sys.stderr)


async def cmd_tail(args: argparse.Namespace) -> None:
    """Stream events in real time (like tail -f)."""
    runtime = Runtime(Path(args.config))
    stop_event = asyncio.Event()

    def handle_signal():
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    await runtime.start()

    queue = await runtime.bus.subscribe(max_queue=5000)
    print_task = asyncio.create_task(
        _print_events(queue, verbose=args.verbose, source_filter=args.source, device_filter=args.device)
    )

    await stop_event.wait()

    print_task.cancel()
    try:
        await print_task
    except asyncio.CancelledError:
        pass
    await runtime.bus.unsubscribe(queue)
    await runtime.stop()


async def _print_events(
    queue: asyncio.Queue,
    verbose: bool = False,
    source_filter: Optional[str] = None,
    device_filter: Optional[str] = None,
) -> None:
    """Print events from a queue to stdout."""
    while True:
        ev = await queue.get()

        # Apply filters
        if source_filter and ev.source != source_filter.upper():
            continue
        if device_filter and ev.device_addr != device_filter.upper():
            continue

        try:
            print(_format_event(ev, verbose=verbose))
        except BrokenPipeError:
            break


async def cmd_status(args: argparse.Namespace) -> None:
    """Show collector status by starting runtime briefly."""
    config = Config(Path(args.config))
    config.load()

    print("bluTruth Status")
    print("=" * 50)
    print(f"Config: {config.path}")
    print(f"SQLite: {config.get('storage', 'sqlite_path')}")
    print(f"JSONL:  {config.get('storage', 'jsonl_path')}")
    print()

    # Check what collectors would be enabled
    from blutruth.collectors import (
        HciCollector, DbusCollector, DaemonLogCollector,
        MgmtApiCollector, PipewireCollector, KernelDriverCollector,
        SysfsCollector, UdevCollector, UbertoothCollector,
        BleSnifferCollector, EbpfCollector, L2pingCollector, BatteryCollector,
    )
    from blutruth.bus import EventBus
    bus = EventBus()
    collectors = [
        HciCollector(bus, config),
        DbusCollector(bus, config),
        DaemonLogCollector(bus, config),
    ]
    for cls in (
        MgmtApiCollector, PipewireCollector, KernelDriverCollector,
        SysfsCollector, UdevCollector, UbertoothCollector,
        BleSnifferCollector, EbpfCollector, L2pingCollector, BatteryCollector,
    ):
        if cls is not None:
            collectors.append(cls(bus, config))

    print("Collectors:")
    for c in collectors:
        enabled = "✓" if c.enabled() else "✗"
        caps = c.capabilities()
        root_tag = " [needs root]" if caps.get("requires_root") else ""
        exclusive = f" [exclusive: {caps['exclusive_resource']}]" if caps.get("exclusive_resource") else ""
        print(f"  {enabled} {c.name:15s} {c.description}{root_tag}{exclusive}")

    print()

    import os
    root = "✓ root" if os.geteuid() == 0 else "✗ not root (some collectors limited)"
    print(f"Privileges: {root}")

    # Check if btmon is available
    import shutil
    btmon = "✓ found" if shutil.which("btmon") else "✗ not found"
    print(f"btmon:      {btmon}")

    # Check D-Bus
    try:
        import dbus_next
        dbus_status = f"✓ dbus-next {dbus_next.__version__ if hasattr(dbus_next, '__version__') else 'installed'}"
    except ImportError:
        dbus_status = "✗ dbus-next not installed"
    print(f"D-Bus:      {dbus_status}")


async def cmd_serve(args: argparse.Namespace) -> None:
    """Start collection daemon + web UI."""
    try:
        from blutruth.web import start_web
    except ImportError:
        print("aiohttp required for web UI: uv pip install aiohttp", file=sys.stderr)
        sys.exit(1)

    runtime = Runtime(
        Path(args.config),
        force_disabled=_force_disabled_from_args(args),
        session_name=getattr(args, "session", None) or None,
    )
    stop_event = asyncio.Event()

    def handle_signal():
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    await runtime.start()

    host = args.host or runtime.config.get("listen", "host", default="127.0.0.1")
    port = args.port or runtime.config.get("listen", "port", default=8484)

    runner = await start_web(runtime, host=host, port=port)

    print(f"bluTruth collecting → {runtime.sqlite.path}", file=sys.stderr)
    print(f"                    → {runtime.jsonl.path}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"  Web UI: http://{host}:{port}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Press Ctrl+C to stop.\n", file=sys.stderr)

    # Also print events to terminal if verbose
    if args.verbose:
        queue = await runtime.bus.subscribe(max_queue=5000)
        print_task = asyncio.create_task(_print_events(queue, verbose=True))
    else:
        queue = None
        print_task = None

    await stop_event.wait()

    print("\nShutting down...", file=sys.stderr)

    if print_task:
        print_task.cancel()
        try:
            await print_task
        except asyncio.CancelledError:
            pass
    if queue:
        await runtime.bus.unsubscribe(queue)

    await runner.cleanup()
    await runtime.stop()

    stats = runtime.stats
    print(f"\nSession stats:", file=sys.stderr)
    print(f"  Events written (SQLite): {stats['sqlite']['total_written']}", file=sys.stderr)
    print(f"  Events written (JSONL):  {stats['jsonl']['total_written']}", file=sys.stderr)
    print(f"  Correlation groups:      {stats['correlation']['total_groups_created']}", file=sys.stderr)


async def cmd_query(args: argparse.Namespace) -> None:
    """Query stored events with optional filters."""
    from blutruth.storage.sqlite import SqliteSink

    config = Config(Path(args.config))
    config.load()
    db_path = Path(config.get("storage", "sqlite_path"))

    if not db_path.exists():
        print(f"No database found at {db_path}. Run 'blutruth collect' first.", file=sys.stderr)
        return

    sink = SqliteSink(db_path)
    await sink.start()
    rows = await sink.query_filtered(
        limit=args.limit,
        source=args.source,
        device=args.device,
        severity=args.severity,
    )
    await sink.stop()

    if not rows:
        print("No events matched.")
        return

    if args.json:
        import json as _json
        for row in rows:
            print(_json.dumps(row, ensure_ascii=False, default=str))
        return

    # Tabular output
    fmt = "{:5s}  {:25s}  {:7s}  {:5s}  {:15s}  {}"
    print(fmt.format("ID", "Time", "Source", "Sev", "Device", "Summary"))
    print("-" * 90)
    for r in rows:
        ts = (r.get("ts_wall") or "")[:25]
        device = (r.get("device_addr") or "")[:15]
        print(fmt.format(
            str(r["id"]),
            ts,
            (r.get("source") or "")[:7],
            (r.get("severity") or "")[:5],
            device,
            r.get("summary", ""),
        ))


async def cmd_sessions(args: argparse.Namespace) -> None:
    """List recorded sessions from the database."""
    from blutruth.storage.sqlite import SqliteSink

    config = Config(Path(args.config))
    config.load()
    db_path = Path(config.get("storage", "sqlite_path"))

    if not db_path.exists():
        print(f"No database found at {db_path}. Run 'blutruth collect' first.", file=sys.stderr)
        return

    sink = SqliteSink(db_path)
    await sink.start()
    sessions = await sink.get_sessions()
    await sink.stop()

    if not sessions:
        print("No sessions recorded yet.")
        return

    print(f"{'ID':>4s}  {'Started':25s}  {'Ended':25s}  {'Events':>7s}  Name / Notes")
    print("-" * 100)
    for s in sessions:
        ended = (s["ended_at"] or "running")[:25]
        notes = f" [{s['notes']}]" if s.get("notes") else ""
        print(
            f"{s['id']:>4d}  "
            f"{(s['started_at'] or '')[:25]:25s}  "
            f"{ended:25s}  "
            f"{s['event_count']:>7d}  "
            f"{s['name'] or ''}{notes}"
        )


async def cmd_devices(args: argparse.Namespace) -> None:
    """List all known devices from the database."""
    from blutruth.storage.sqlite import SqliteSink

    config = Config(Path(args.config))
    config.load()
    db_path = Path(config.get("storage", "sqlite_path"))

    if not db_path.exists():
        print(f"No database found at {db_path}. Run 'blutruth collect' first.", file=sys.stderr)
        return

    sink = SqliteSink(db_path)
    await sink.start()
    devices = await sink.get_unique_devices()
    await sink.stop()

    if not devices:
        print("No devices seen yet.")
        return

    from blutruth.enrichment.oui import enrich_oui
    print(f"{'Address':20s} {'Manufacturer':18s} {'Name':22s} {'Events':>8s}  {'First Seen':19s}  {'Last Seen':19s}")
    print("-" * 115)
    for d in devices:
        mfr = enrich_oui(d['device_addr']) or ""
        print(
            f"{d['device_addr']:20s} "
            f"{mfr[:18]:18s} "
            f"{(d['device_name'] or '')[:22]:22s} "
            f"{d['event_count']:>8d}  "
            f"{(d['first_seen'] or '')[:19]:19s}  "
            f"{(d['last_seen'] or '')[:19]:19s}"
        )


async def cmd_replay(args: argparse.Namespace) -> None:
    """Replay a JSONL file through the bus and into storage."""
    import time as _time
    from blutruth.bus import EventBus
    from blutruth.storage.sqlite import SqliteSink
    from blutruth.storage.jsonl import JsonlSink
    from blutruth.events import Event

    path = Path(args.file).expanduser()
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    config = Config(Path(args.config))
    config.load()

    bus = EventBus()
    sqlite = SqliteSink(Path(config.get("storage", "sqlite_path")))
    jsonl = JsonlSink(Path(config.get("storage", "jsonl_path")))
    await sqlite.start()
    await jsonl.start()

    session_name = args.session or f"replay {path.name}"
    await sqlite.create_session(session_name)

    # Writer task
    queue = await bus.subscribe(max_queue=10000)

    async def _writer() -> None:
        while True:
            ev = await queue.get()
            await asyncio.gather(sqlite.write(ev), jsonl.write(ev), return_exceptions=True)

    writer_task = asyncio.create_task(_writer())

    # Parse events
    events = []
    errors = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except Exception:
                errors += 1

    if not events:
        print(f"No valid events in {path} ({errors} parse errors).", file=sys.stderr)
        await sqlite.stop()
        await jsonl.stop()
        return

    events.sort(key=lambda e: e.ts_mono_us)
    total = len(events)
    speed = float(args.speed)

    print(f"Replaying {total} events from {path} (speed={speed}x){' [fast]' if speed == 0 else ''}",
          file=sys.stderr)
    if errors:
        print(f"  Skipped {errors} unparseable lines.", file=sys.stderr)

    replay_wall_start = _time.monotonic()
    t0_us = events[0].ts_mono_us

    for i, ev in enumerate(events, 1):
        if speed > 0 and i > 1:
            # Sleep to maintain original timing scaled by speed
            target = replay_wall_start + (ev.ts_mono_us - t0_us) / 1_000_000 / speed
            gap = target - _time.monotonic()
            if gap > 0:
                await asyncio.sleep(gap)
        await bus.publish(ev)
        if i % 500 == 0:
            print(f"  {i}/{total} events replayed...", file=sys.stderr)

    # Drain writer
    await asyncio.sleep(0.5)
    while not queue.empty():
        await asyncio.sleep(0.1)

    writer_task.cancel()
    try:
        await writer_task
    except asyncio.CancelledError:
        pass
    await bus.unsubscribe(queue)

    if sqlite._active_session_id:
        await sqlite.end_session(sqlite._active_session_id)

    await sqlite.stop()
    await jsonl.stop()
    print(f"Replay complete. {total} events written.", file=sys.stderr)


async def cmd_history(args: argparse.Namespace) -> None:
    """Show per-device session history with disconnect analysis."""
    from blutruth.analysis.history import query_device_history, format_history

    config = Config(Path(args.config))
    config.load()
    db_path = Path(config.get("storage", "sqlite_path"))

    if not db_path.exists():
        print(f"No database found at {db_path}. Run 'blutruth collect' first.", file=sys.stderr)
        return

    history = await query_device_history(
        db_path,
        args.device,
        num_sessions=args.sessions,
    )

    if args.json:
        out = {
            "device_addr": history.device_addr,
            "device_name": history.device_name,
            "manufacturer": history.manufacturer,
            "total_disconnects": history.total_disconnects,
            "avg_disconnects_per_session": history.avg_disconnects_per_session,
            "top_disconnect_reasons": history.top_disconnect_reasons,
            "sessions": [
                {
                    "session_id": s.session_id,
                    "session_name": s.session_name,
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                    "duration_minutes": s.duration_minutes,
                    "event_count": s.event_count,
                    "disconnect_count": s.disconnect_count,
                    "disconnect_reasons": s.disconnect_reasons,
                    "severity_counts": s.severity_counts,
                }
                for s in history.sessions
            ],
        }
        import json as _json
        print(_json.dumps(out, ensure_ascii=False, default=str))
        return

    print(format_history(history))


async def cmd_export(args: argparse.Namespace) -> None:
    """Export stored events to JSONL or CSV."""
    import csv as _csv
    from blutruth.storage.sqlite import SqliteSink

    fmt = args.format.lower()
    if fmt not in ("jsonl", "csv"):
        print(f"Unsupported format '{fmt}'. Use jsonl or csv.", file=sys.stderr)
        sys.exit(1)

    config = Config(Path(args.config))
    config.load()
    db_path = Path(config.get("storage", "sqlite_path"))

    if not db_path.exists():
        print(f"No database found at {db_path}. Run 'blutruth collect' first.", file=sys.stderr)
        sys.exit(1)

    sid_raw = getattr(args, "session_id", None)
    session_id = int(sid_raw) if sid_raw and str(sid_raw).isdigit() else None

    sink = SqliteSink(db_path)
    await sink.start()
    rows = await sink.query_filtered(
        limit=args.limit,
        source=args.source or None,
        severity=args.severity or None,
        device=args.device or None,
        session_id=session_id,
    )
    await sink.stop()

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        if fmt == "jsonl":
            for row in rows:
                out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        else:  # csv
            if not rows:
                return
            writer = _csv.DictWriter(
                out,
                fieldnames=["id", "ts_wall", "source", "severity", "stage",
                            "event_type", "device_addr", "device_name", "group_id", "summary"],
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(rows)
    finally:
        if args.output:
            out.close()

    if args.output:
        print(f"Exported {len(rows)} events → {args.output}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blutruth",
        description="bluTruth — Bluetooth Stack Diagnostic Platform",
    )
    parser.add_argument(
        "-c", "--config",
        default="~/.blutruth/config.yaml",
        help="Path to YAML config file (default: ~/.blutruth/config.yaml)",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # collect
    p_collect = sub.add_parser("collect", help="Start collection daemon (foreground)")
    p_collect.add_argument("-v", "--verbose", action="store_true", help="Print events to stdout")
    p_collect.add_argument("--no-hci",      action="store_true", help="Disable HCI collector")
    p_collect.add_argument("--no-dbus",     action="store_true", help="Disable D-Bus collector")
    p_collect.add_argument("--no-daemon",   action="store_true", help="Disable daemon log collector")
    p_collect.add_argument("--no-mgmt",     action="store_true", help="Disable mgmt API collector")
    p_collect.add_argument("--no-pipewire", action="store_true", help="Disable PipeWire collector")
    p_collect.add_argument("--no-kernel",   action="store_true", help="Disable kernel driver collector")
    p_collect.add_argument("--session",     default=None, metavar="NAME", help="Name this collection session")

    # tail
    p_tail = sub.add_parser("tail", help="Stream events in real time")
    p_tail.add_argument("-v", "--verbose", action="store_true", help="Show full event payloads")
    p_tail.add_argument("-s", "--source", help="Filter by source (HCI, DBUS, DAEMON)")
    p_tail.add_argument("-d", "--device", help="Filter by device address")

    # status
    sub.add_parser("status", help="Show runtime status and prerequisites")

    # serve
    p_serve = sub.add_parser("serve", help="Start collection + web UI")
    p_serve.add_argument("-v", "--verbose", action="store_true", help="Also print events to terminal")
    p_serve.add_argument("--host", default=None, help="Bind address (default: from config)")
    p_serve.add_argument("--port", type=int, default=None, help="Bind port (default: from config)")
    p_serve.add_argument("--no-hci",      action="store_true", help="Disable HCI collector")
    p_serve.add_argument("--no-dbus",     action="store_true", help="Disable D-Bus collector")
    p_serve.add_argument("--no-daemon",   action="store_true", help="Disable daemon log collector")
    p_serve.add_argument("--no-mgmt",     action="store_true", help="Disable mgmt API collector")
    p_serve.add_argument("--no-pipewire", action="store_true", help="Disable PipeWire collector")
    p_serve.add_argument("--no-kernel",   action="store_true", help="Disable kernel driver collector")
    p_serve.add_argument("--session",     default=None, metavar="NAME", help="Name this collection session")

    # query
    p_query = sub.add_parser("query", help="Query stored events with filters")
    p_query.add_argument("-l", "--limit", type=int, default=200, help="Max rows (default: 200)")
    p_query.add_argument("-s", "--source", default=None, help="Filter by source (HCI, DBUS, DAEMON, …)")
    p_query.add_argument("-d", "--device", default=None, help="Filter by device address")
    p_query.add_argument("--severity", default=None, help="Filter by severity (DEBUG, INFO, WARN, ERROR, SUSPICIOUS)")
    p_query.add_argument("--json", action="store_true", help="Output as JSONL instead of table")

    # sessions
    sub.add_parser("sessions", help="List recorded collection sessions")

    # devices
    sub.add_parser("devices", help="List known devices from database")

    # replay
    p_replay = sub.add_parser("replay", help="Replay a JSONL file through storage")
    p_replay.add_argument("file", help="Path to .jsonl file")
    p_replay.add_argument("--speed", type=float, default=0,
                          help="Replay speed multiplier (0 = as fast as possible, 1.0 = real-time)")
    p_replay.add_argument("--session", default=None, metavar="NAME",
                          help="Name for the replay session (default: filename)")

    # history
    p_history = sub.add_parser("history", help="Show device session history and disconnect analysis")
    p_history.add_argument("device", metavar="ADDR", help="Device Bluetooth address (e.g. AA:BB:CC:DD:EE:FF)")
    p_history.add_argument("-n", "--sessions", type=int, default=5,
                           help="Number of recent sessions to show (default: 5)")
    p_history.add_argument("--json", action="store_true", help="Output as JSON")

    # export
    p_export = sub.add_parser("export", help="Export events to JSONL or CSV")
    p_export.add_argument("--format", default="jsonl", choices=["jsonl", "csv"],
                          help="Output format (default: jsonl)")
    p_export.add_argument("-o", "--output", default=None, metavar="FILE",
                          help="Output file (default: stdout)")
    p_export.add_argument("-l", "--limit", type=int, default=10000,
                          help="Max rows (default: 10000)")
    p_export.add_argument("-s", "--source", default=None, help="Filter by source")
    p_export.add_argument("-d", "--device", default=None, help="Filter by device address")
    p_export.add_argument("--severity", default=None, help="Filter by severity")
    p_export.add_argument("--session-id", default=None, dest="session_id",
                          help="Filter by session ID")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmd_map = {
        "collect": cmd_collect,
        "tail": cmd_tail,
        "status": cmd_status,
        "serve": cmd_serve,
        "query": cmd_query,
        "sessions": cmd_sessions,
        "devices": cmd_devices,
        "replay": cmd_replay,
        "history": cmd_history,
        "export": cmd_export,
    }

    func = cmd_map.get(args.command)
    if not func:
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(func(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
