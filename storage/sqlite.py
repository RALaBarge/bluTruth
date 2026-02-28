"""
blutruth.storage.sqlite — SQLite event store with batched writes

WAL mode for concurrent read/write. Batched inserts for throughput under
heavy btmon output. Target: >1000 inserts/second sustained.

FUTURE (Rust port): rusqlite with the same schema. The database files
produced by Python and Rust must be fully interchangeable.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from blutruth.events import Event


_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    source_version  TEXT,
    parser_version  TEXT,
    ts_mono_us      INTEGER NOT NULL,
    ts_wall         TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    stage           TEXT,
    event_type      TEXT    NOT NULL,
    adapter         TEXT,
    device_addr     TEXT,
    device_name     TEXT,
    summary         TEXT    NOT NULL,
    raw_json        TEXT    NOT NULL,
    raw             TEXT,
    group_id        INTEGER,
    tags_json       TEXT,
    annotations     TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_time        ON events(ts_mono_us);
CREATE INDEX IF NOT EXISTS idx_events_dev_time    ON events(device_addr, ts_mono_us);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source, ts_mono_us);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON events(severity, ts_mono_us);
CREATE INDEX IF NOT EXISTS idx_events_group       ON events(group_id) WHERE group_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_addr  TEXT UNIQUE,
    known_addrs     TEXT,
    name            TEXT,
    class           TEXT,
    manufacturer    TEXT,
    first_seen      TEXT,
    last_seen       TEXT
);

CREATE TABLE IF NOT EXISTS event_groups (
    group_id    INTEGER,
    event_id    INTEGER REFERENCES events(id),
    role        TEXT
);
CREATE INDEX IF NOT EXISTS idx_groups_gid ON event_groups(group_id);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT,
    started_at  TEXT,
    ended_at    TEXT,
    notes       TEXT
);
"""

_INSERT_SQL = """
INSERT INTO events (
    schema_version, source_version, parser_version,
    ts_mono_us, ts_wall, source, severity, stage, event_type,
    adapter, device_addr, device_name,
    summary, raw_json, raw, group_id, tags_json, annotations
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class SqliteSink:
    """
    Async SQLite writer with batched inserts.

    Events are buffered internally and flushed either when the batch
    reaches `batch_size` or every `flush_interval_s` seconds, whichever
    comes first. This avoids per-event commits under heavy load.
    """

    def __init__(
        self,
        path: Path,
        batch_size: int = 100,
        flush_interval_s: float = 0.25,
    ):
        self.path = path
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self._db: Optional[sqlite3.Connection] = None
        self._buffer: List[tuple] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._total_written: int = 0

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # sqlite3 in same thread; we guard with asyncio.Lock
        self._db = sqlite3.connect(
            self.path.as_posix(),
            check_same_thread=False,
            timeout=10.0,
        )
        self._db.execute("PRAGMA journal_mode=WAL;")
        self._db.execute("PRAGMA synchronous=NORMAL;")
        self._db.execute("PRAGMA cache_size=-8000;")  # 8MB
        self._db.executescript(_SCHEMA_DDL)
        self._db.commit()
        self._flush_task = asyncio.create_task(self._periodic_flush())

    async def stop(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        await self._flush()
        if self._db:
            self._db.close()
            self._db = None

    async def write(self, event: Event) -> None:
        row = self._event_to_row(event)
        async with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self.batch_size:
                await self._flush_locked()

    async def _flush(self) -> None:
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Must be called with self._lock held."""
        if not self._buffer or not self._db:
            return
        batch = self._buffer
        self._buffer = []
        # Run the actual DB work in a thread to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_batch_sync, batch)

    def _write_batch_sync(self, batch: List[tuple]) -> None:
        assert self._db is not None
        self._db.executemany(_INSERT_SQL, batch)
        self._db.commit()
        self._total_written += len(batch)

    async def _periodic_flush(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval_s)
            await self._flush()

    # --- Query methods (for CLI, HTTP API, correlation engine) ---

    async def query_recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._query_recent_sync, limit)

    def _query_recent_sync(self, limit: int) -> List[Dict[str, Any]]:
        assert self._db is not None
        cur = self._db.execute(
            "SELECT id, ts_mono_us, ts_wall, source, severity, stage, event_type, "
            "adapter, device_addr, device_name, summary, raw_json, group_id "
            "FROM events ORDER BY ts_mono_us DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "ts_mono_us": r[1],
                "ts_wall": r[2],
                "source": r[3],
                "severity": r[4],
                "stage": r[5],
                "event_type": r[6],
                "adapter": r[7],
                "device_addr": r[8],
                "device_name": r[9],
                "summary": r[10],
                "raw_json": json.loads(r[11]) if r[11] else {},
                "group_id": r[12],
            }
            for r in rows
        ]

    async def query_window(
        self, start_us: int, end_us: int, source: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query events in a time window. Used by correlation engine."""
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._query_window_sync, start_us, end_us, source
        )

    def _query_window_sync(
        self, start_us: int, end_us: int, source: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        assert self._db is not None
        if source:
            cur = self._db.execute(
                "SELECT id, ts_mono_us, source, severity, event_type, device_addr, summary "
                "FROM events WHERE ts_mono_us BETWEEN ? AND ? AND source = ? "
                "ORDER BY ts_mono_us",
                (start_us, end_us, source),
            )
        else:
            cur = self._db.execute(
                "SELECT id, ts_mono_us, source, severity, event_type, device_addr, summary "
                "FROM events WHERE ts_mono_us BETWEEN ? AND ? ORDER BY ts_mono_us",
                (start_us, end_us),
            )
        return [
            {
                "id": r[0], "ts_mono_us": r[1], "source": r[2],
                "severity": r[3], "event_type": r[4],
                "device_addr": r[5], "summary": r[6],
            }
            for r in cur.fetchall()
        ]

    async def set_group_id(self, event_id: int, group_id: int, role: str = "CORRELATED") -> None:
        """Assign a correlation group to an event."""
        if not self._db:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._set_group_sync, event_id, group_id, role
        )

    def _set_group_sync(self, event_id: int, group_id: int, role: str) -> None:
        assert self._db is not None
        self._db.execute(
            "UPDATE events SET group_id = ? WHERE id = ?", (group_id, event_id)
        )
        self._db.execute(
            "INSERT INTO event_groups (group_id, event_id, role) VALUES (?, ?, ?)",
            (group_id, event_id, role),
        )
        self._db.commit()

    async def get_unique_devices(self) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_devices_sync)

    def _get_devices_sync(self) -> List[Dict[str, Any]]:
        assert self._db is not None
        cur = self._db.execute(
            "SELECT device_addr, device_name, "
            "MIN(ts_wall) as first_seen, MAX(ts_wall) as last_seen, "
            "COUNT(*) as event_count "
            "FROM events WHERE device_addr IS NOT NULL "
            "GROUP BY device_addr ORDER BY last_seen DESC"
        )
        return [
            {
                "device_addr": r[0], "device_name": r[1],
                "first_seen": r[2], "last_seen": r[3],
                "event_count": r[4],
            }
            for r in cur.fetchall()
        ]

    @property
    def stats(self) -> dict:
        return {
            "total_written": self._total_written,
            "buffer_size": len(self._buffer),
            "path": str(self.path),
        }

    # --- Internal ---

    @staticmethod
    def _event_to_row(ev: Event) -> tuple:
        return (
            ev.schema_version,
            ev.source_version,
            ev.parser_version,
            ev.ts_mono_us,
            ev.ts_wall,
            ev.source,
            ev.severity,
            ev.stage,
            ev.event_type,
            ev.adapter,
            ev.device_addr,
            ev.device_name,
            ev.summary,
            json.dumps(ev.raw_json, ensure_ascii=False, default=str),
            ev.raw,
            ev.group_id,
            json.dumps(ev.tags, ensure_ascii=False) if ev.tags else None,
            json.dumps(ev.annotations, ensure_ascii=False) if ev.annotations else None,
        )
