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
from blutruth.collectors import (
    Collector,
    HciCollector,
    DbusCollector,
    DaemonLogCollector,
    MgmtApiCollector,
    PipewireCollector,
    KernelDriverCollector,
    SysfsCollector,
    UdevCollector,
    UbertoothCollector,
    BleSnifferCollector,
    EbpfCollector,
    L2pingCollector,
    BatteryCollector,
)
from blutruth.config import Config
from blutruth.correlation.engine import CorrelationEngine
from blutruth.correlation.rules import RuleEngine, load_rule_paths
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

    def __init__(
        self,
        config_path: Path,
        force_disabled: Optional[set] = None,
        session_name: Optional[str] = None,
    ) -> None:
        self.config = Config(config_path)
        self.config.load()
        self._force_disabled: set = force_disabled or set()
        self._session_name: Optional[str] = session_name

        self.bus = EventBus()

        retention_days = int(self.config.get("storage", "retention_days", default=0))
        self.sqlite = SqliteSink(
            Path(self.config.get("storage", "sqlite_path")),
            batch_size=100,
            flush_interval_s=0.25,
            retention_days=retention_days,
        )
        self.jsonl = JsonlSink(
            Path(self.config.get("storage", "jsonl_path")),
        )

        self.correlation = CorrelationEngine(self.bus, self.config, self.sqlite)
        self.rules = RuleEngine(self.bus, self.config)
        self.collectors: List[Collector] = []

        self._writer_task: Optional[asyncio.Task] = None
        self._config_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._session_id: Optional[int] = None

    async def start(self) -> None:
        """Start all components in dependency order."""
        # 1. Storage first (must be ready before events flow)
        await self.sqlite.start()
        await self.jsonl.start()

        # 2. Session — create before events start flowing so all events get stamped
        import datetime as _dt
        session_name = self._session_name or (
            f"collect {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} pid={os.getpid()}"
        )
        self._session_id = await self.sqlite.create_session(session_name)

        # 3. Writer task (drains bus → storage)
        self._writer_task = asyncio.create_task(self._writer_loop())

        # 5. Privilege check
        await self._check_privileges()

        # 6. Register collectors
        # FUTURE: Dynamic plugin discovery from a directory / entrypoints
        self.collectors = [
            HciCollector(self.bus, self.config),
            DbusCollector(self.bus, self.config),
            DaemonLogCollector(self.bus, self.config),
        ]
        # Optional collectors — gracefully absent if import/tool unavailable
        _optional = (
            MgmtApiCollector,
            PipewireCollector,
            KernelDriverCollector,
            SysfsCollector,
            UdevCollector,
            UbertoothCollector,
            BleSnifferCollector,
            EbpfCollector,
            L2pingCollector,
            BatteryCollector,
        )
        for cls in _optional:
            if cls is not None:
                self.collectors.append(cls(self.bus, self.config))

        # 7. Check capabilities and start enabled collectors
        for collector in self.collectors:
            if collector.name in self._force_disabled:
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    severity="INFO",
                    event_type="COLLECTOR_SKIP",
                    summary=f"Collector '{collector.name}' disabled via CLI flag",
                    raw_json={"collector": collector.name},
                ))
                continue
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

        # 8. Correlation engine + pattern rules
        await self.correlation.start()

        rule_paths = load_rule_paths(self.config)
        n_rules = self.rules.load_rules(rule_paths)
        if n_rules > 0:
            await self.rules.start()
            await self.bus.publish(Event.new(
                source="RUNTIME",
                event_type="RULES_LOADED",
                summary=f"Pattern rule engine started: {n_rules} rules from {len(rule_paths)} files",
                raw_json={"rules": n_rules, "rule_files": [str(p) for p in rule_paths]},
            ))

        # 9. Config hot reload watcher
        self._config_task = asyncio.create_task(self._config_watch_loop())

        await self.bus.publish(Event.new(
            source="RUNTIME",
            event_type="RUNTIME_START",
            summary="bluTruth runtime started",
            raw_json={
                "session_id": self._session_id,
                "session_name": session_name,
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

        # Pattern rules
        await self.rules.stop()

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

        # Close session before storage flushes the final events
        if self._session_id:
            await self.sqlite.end_session(self._session_id)

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
        Watch config file for changes and restart affected collectors.

        Uses watchfiles (inotify/kqueue/FSEvents) when available, falls back to
        1-second polling. Either way, config.load() mtime-guards against
        unnecessary reloads.

        FUTURE: Compute diffs and only restart affected collectors.
        """
        try:
            from watchfiles import awatch as _awatch
            async for _ in _awatch(str(self.config.path), stop_event=self._stop_event):
                if not self.config.load():
                    continue
                await self._on_config_changed()
        except ImportError:
            pass  # fall through to polling
        except Exception:
            pass  # watchfiles failed (e.g., path doesn't exist yet) — fall through

        # Polling fallback
        while not self._stop_event.is_set():
            await asyncio.sleep(1.0)
            if not self.config.load():
                continue
            await self._on_config_changed()

    async def _on_config_changed(self) -> None:
        """Handle a detected config change."""
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
            "session_id": self._session_id,
            "bus": self.bus.stats,
            "sqlite": self.sqlite.stats,
            "jsonl": self.jsonl.stats,
            "correlation": self.correlation.stats,
            "rules": self.rules.stats,
            "collectors": {
                c.name: {"running": c.is_running, "enabled": c.enabled()}
                for c in self.collectors
            },
        }
