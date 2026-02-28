"""
blutruth.runtime — Orchestration layer

Wires everything together: collectors → event bus → storage sinks + correlation.
Handles startup, shutdown, privilege checks, and config hot reload.

FUTURE (daemon split): This becomes the core of bt-diagd.
FUTURE (Rust port): tokio runtime with the same lifecycle.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import List, Optional

from blutruth.bus import EventBus
from blutruth.collectors import Collector, HciCollector, DbusCollector, DaemonLogCollector
from blutruth.config import Config
from blutruth.correlation.engine import CorrelationEngine
from blutruth.events import Event
from blutruth.storage.jsonl import JsonlSink
from blutruth.storage.sqlite import SqliteSink


class Runtime:
    """
    Single-process runtime that manages all bluTruth components.

    Structured internally as if it were a daemon (event bus, storage writers,
    collector plugins) so splitting into separate processes later requires
    moving modules, not rewriting them.

    FUTURE (daemon split):
    - Collectors move into bt-diagd (long-lived daemon)
    - HTTP API becomes a client connecting to bt-diagd via IPC
    - Event bus replaced with unix socket + framed JSON or gRPC
    """

    def __init__(self, config_path: Path) -> None:
        self.config = Config(config_path)
        self.config.load()

        self.bus = EventBus()

        self.sqlite = SqliteSink(
            Path(self.config.get("storage", "sqlite_path")),
            batch_size=100,
            flush_interval_s=0.25,
        )
        self.jsonl = JsonlSink(
            Path(self.config.get("storage", "jsonl_path")),
        )

        self.correlation = CorrelationEngine(self.bus, self.config, self.sqlite)
        self.collectors: List[Collector] = []

        self._writer_task: Optional[asyncio.Task] = None
        self._config_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        """Start all components in dependency order."""
        # 1. Storage first (must be ready before events flow)
        await self.sqlite.start()
        await self.jsonl.start()

        # 2. Writer task (drains bus → storage)
        self._writer_task = asyncio.create_task(self._writer_loop())

        # 3. Privilege check
        await self._check_privileges()

        # 4. Register collectors
        # FUTURE: Dynamic plugin discovery from a directory / entrypoints
        self.collectors = [
            HciCollector(self.bus, self.config),
            DbusCollector(self.bus, self.config),
            DaemonLogCollector(self.bus, self.config),
        ]

        # 5. Check capabilities and start enabled collectors
        for collector in self.collectors:
            if not collector.enabled():
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    severity="INFO",
                    event_type="COLLECTOR_SKIP",
                    summary=f"Collector '{collector.name}' disabled in config",
                    raw_json={"collector": collector.name},
                ))
                continue

            caps = collector.capabilities()
            if caps.get("requires_root") and os.geteuid() != 0:
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    severity="WARN",
                    event_type="COLLECTOR_SKIP",
                    summary=(
                        f"Collector '{collector.name}' requires root — skipping. "
                        f"Lost visibility: {', '.join(caps.get('optional_root_benefits', []))}"
                    ),
                    raw_json={"collector": collector.name, "capabilities": caps},
                ))
                continue

            try:
                await collector.start()
            except Exception as e:
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    severity="ERROR",
                    event_type="COLLECTOR_ERROR",
                    summary=f"Failed to start collector '{collector.name}': {e}",
                    raw_json={"collector": collector.name, "error": str(e)},
                ))

        # 6. Correlation engine
        await self.correlation.start()

        # 7. Config hot reload watcher
        self._config_task = asyncio.create_task(self._config_watch_loop())

        await self.bus.publish(Event.new(
            source="RUNTIME",
            event_type="RUNTIME_START",
            summary="bluTruth runtime started",
            raw_json={
                "collectors_active": [
                    c.name for c in self.collectors if c.is_running
                ],
                "collectors_disabled": [
                    c.name for c in self.collectors if not c.is_running
                ],
                "storage": {
                    "sqlite": str(self.sqlite.path),
                    "jsonl": str(self.jsonl.path),
                },
                "pid": os.getpid(),
                "uid": os.geteuid(),
            },
        ))

    async def stop(self) -> None:
        """Shutdown in reverse dependency order."""
        self._stop_event.set()

        # Config watcher
        if self._config_task:
            self._config_task.cancel()
            try:
                await self._config_task
            except asyncio.CancelledError:
                pass

        # Correlation
        await self.correlation.stop()

        # Collectors (may need to restore services)
        for collector in reversed(self.collectors):
            try:
                await collector.stop()
            except Exception:
                pass

        # Writer task
        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass

        # Storage (flush remaining)
        await self.sqlite.stop()
        await self.jsonl.stop()

    async def _writer_loop(self) -> None:
        """Drain the event bus into both storage sinks."""
        queue = await self.bus.subscribe(max_queue=10000)
        try:
            while True:
                event = await queue.get()
                # Write to both sinks concurrently
                await asyncio.gather(
                    self.sqlite.write(event),
                    self.jsonl.write(event),
                    return_exceptions=True,
                )
        except asyncio.CancelledError:
            # Drain remaining events before exit
            while not queue.empty():
                try:
                    event = queue.get_nowait()
                    await self.sqlite.write(event)
                    await self.jsonl.write(event)
                except asyncio.QueueEmpty:
                    break
        finally:
            await self.bus.unsubscribe(queue)

    async def _config_watch_loop(self) -> None:
        """
        Poll config file for changes and restart affected collectors.

        FUTURE: Replace with inotify/watchdog for efficiency.
        FUTURE: Compute diffs and only restart affected collectors.
        """
        while not self._stop_event.is_set():
            await asyncio.sleep(1.0)

            if not self.config.load():
                continue

            await self.bus.publish(Event.new(
                source="RUNTIME",
                event_type="CONFIG_RELOAD",
                summary="Configuration reloaded",
                raw_json={"config_path": str(self.config.path)},
                tags=["config"],
            ))

            # If collector config changed, restart them
            if self.config.collectors_changed():
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    event_type="CONFIG_RELOAD",
                    summary="Collector configuration changed — restarting collectors",
                    raw_json={},
                    tags=["config"],
                ))
                for collector in self.collectors:
                    try:
                        await collector.stop()
                    except Exception:
                        pass
                for collector in self.collectors:
                    if collector.enabled():
                        try:
                            await collector.start()
                        except Exception as e:
                            await self.bus.publish(Event.new(
                                source="RUNTIME",
                                severity="ERROR",
                                event_type="COLLECTOR_ERROR",
                                summary=f"Failed to restart '{collector.name}': {e}",
                                raw_json={"collector": collector.name, "error": str(e)},
                            ))

    async def _check_privileges(self) -> None:
        """Emit a notice about privilege level and what's available."""
        uid = os.geteuid()
        if uid != 0:
            await self.bus.publish(Event.new(
                source="RUNTIME",
                severity="WARN",
                event_type="PRIVILEGE_NOTICE",
                summary="Running without root — some diagnostics may be limited",
                raw_json={
                    "uid": uid,
                    "hint": "Run as root for full visibility (kernel traces, advanced bluetoothd mode)",
                },
                tags=["privileges"],
            ))

    @property
    def stats(self) -> dict:
        return {
            "bus": self.bus.stats,
            "sqlite": self.sqlite.stats,
            "jsonl": self.jsonl.stats,
            "correlation": self.correlation.stats,
            "collectors": {
                c.name: {"running": c.is_running, "enabled": c.enabled()}
                for c in self.collectors
            },
        }
