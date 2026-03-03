"""
blutruth.cli — Command-line interface

Commands:
  collect   Start the collection daemon (foreground)
  status    Show runtime status and collector health
  tail      Stream events in real time (like tail -f)
  devices   List all known devices with event counts
  query     Query stored events with filters

FUTURE: Add 'replay' command to replay a JSONL file through correlation.
FUTURE: Add 'export' command for btsnoop/JSON export of time ranges.
FUTURE (Rust port): clap-based CLI with the same subcommands.
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


async def cmd_collect(args: argparse.Namespace) -> None:
    """Start the collection daemon in the foreground."""
    runtime = Runtime(Path(args.config))
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
    )
    from blutruth.bus import EventBus
    bus = EventBus()
    collectors = [
        HciCollector(bus, config),
        DbusCollector(bus, config),
        DaemonLogCollector(bus, config),
    ]
    for cls in (MgmtApiCollector, PipewireCollector, KernelDriverCollector):
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

    runtime = Runtime(Path(args.config))
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

    print(f"{'Address':20s} {'Name':25s} {'Events':>8s}  {'First Seen':25s}  {'Last Seen':25s}")
    print("-" * 110)
    for d in devices:
        print(
            f"{d['device_addr']:20s} "
            f"{(d['device_name'] or ''):25s} "
            f"{d['event_count']:>8d}  "
            f"{(d['first_seen'] or '')[:25]:25s}  "
            f"{(d['last_seen'] or '')[:25]:25s}"
        )


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
    p_collect.add_argument("--no-hci", action="store_true", help="Disable HCI collector")
    p_collect.add_argument("--no-dbus", action="store_true", help="Disable D-Bus collector")
    p_collect.add_argument("--no-daemon", action="store_true", help="Disable daemon log collector")

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

    # devices
    sub.add_parser("devices", help="List known devices from database")

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
        "devices": cmd_devices,
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
