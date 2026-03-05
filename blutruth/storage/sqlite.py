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
    summary, raw_json, raw, group_id, tags_json, annotations, session_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        retention_days: int = 0,
    ):
        self.path = path
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.retention_days = retention_days
        self._db: Optional[sqlite3.Connection] = None
        self._buffer: List[tuple] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._retention_task: Optional[asyncio.Task] = None
        self._total_written: int = 0
        self._total_purged: int = 0
        self._active_session_id: Optional[int] = None

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

        # Migration: add session_id column if it doesn't exist yet
        try:
            self._db.execute(
                "ALTER TABLE events ADD COLUMN session_id INTEGER REFERENCES sessions(id) DEFAULT NULL"
            )
            self._db.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists

        self._flush_task = asyncio.create_task(self._periodic_flush())
        if self.retention_days > 0:
            self._retention_task = asyncio.create_task(self._retention_loop())

    async def stop(self) -> None:
        for task in (self._flush_task, self._retention_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._flush_task = None
        self._retention_task = None
        await self._flush()
        if self._db:
            self._db.close()
            self._db = None

    async def write(self, event: Event) -> None:
        row = self._event_to_row(event, self._active_session_id)
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

    async def query_filtered(
        self,
        limit: int = 200,
        source: Optional[str] = None,
        device: Optional[str] = None,
        severity: Optional[str] = None,
        session_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query events with optional filters. Used by CLI query subcommand and web API."""
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._query_filtered_sync, limit, source, device, severity, session_id
        )

    def _query_filtered_sync(
        self,
        limit: int,
        source: Optional[str],
        device: Optional[str],
        severity: Optional[str],
        session_id: Optional[int],
    ) -> List[Dict[str, Any]]:
        assert self._db is not None
        clauses: List[str] = []
        params: List[Any] = []
        if source:
            clauses.append("source = ?")
            params.append(source.upper())
        if device:
            clauses.append("device_addr = ?")
            params.append(device.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cur = self._db.execute(
            f"SELECT id, ts_mono_us, ts_wall, source, severity, stage, event_type, "
            f"adapter, device_addr, device_name, summary, raw_json, group_id "
            f"FROM events {where} ORDER BY ts_mono_us DESC LIMIT ?",
            params,
        )
        return [
            {
                "id": r[0], "ts_mono_us": r[1], "ts_wall": r[2], "source": r[3],
                "severity": r[4], "stage": r[5], "event_type": r[6], "adapter": r[7],
                "device_addr": r[8], "device_name": r[9], "summary": r[10],
                "raw_json": json.loads(r[11]) if r[11] else {},
                "group_id": r[12],
            }
            for r in cur.fetchall()
        ]

    async def query_device_timeline(
        self, device_addr: str, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """All events for a device, chronological order. Used by device detail page."""
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._query_device_timeline_sync, device_addr.upper(), limit
        )

    def _query_device_timeline_sync(self, device_addr: str, limit: int) -> List[Dict[str, Any]]:
        assert self._db is not None
        cur = self._db.execute(
            "SELECT id, ts_mono_us, ts_wall, source, severity, stage, event_type, "
            "device_name, summary, raw_json, group_id "
            "FROM events WHERE device_addr = ? ORDER BY ts_mono_us ASC LIMIT ?",
            (device_addr, limit),
        )
        return [
            {
                "id": r[0], "ts_mono_us": r[1], "ts_wall": r[2], "source": r[3],
                "severity": r[4], "stage": r[5], "event_type": r[6],
                "device_name": r[7], "summary": r[8],
                "raw_json": json.loads(r[9]) if r[9] else {},
                "group_id": r[10],
            }
            for r in cur.fetchall()
        ]

    async def query_device_info(self, device_addr: str) -> Optional[Dict[str, Any]]:
        """Summary row for a single device."""
        if not self._db:
            return None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._query_device_info_sync, device_addr.upper()
        )

    def _query_device_info_sync(self, device_addr: str) -> Optional[Dict[str, Any]]:
        assert self._db is not None
        cur = self._db.execute(
            "SELECT device_addr, device_name, "
            "MIN(ts_wall) as first_seen, MAX(ts_wall) as last_seen, COUNT(*) as event_count "
            "FROM events WHERE device_addr = ? GROUP BY device_addr",
            (device_addr,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "device_addr": row[0], "device_name": row[1],
            "first_seen": row[2], "last_seen": row[3], "event_count": row[4],
        }

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

    # --- Session management ---

    async def create_session(self, name: str, notes: str = "") -> int:
        """Create a new session and set it as active. Returns the session id."""
        if not self._db:
            return 0
        loop = asyncio.get_running_loop()
        session_id = await loop.run_in_executor(None, self._create_session_sync, name, notes)
        self._active_session_id = session_id
        return session_id

    def _create_session_sync(self, name: str, notes: str) -> int:
        assert self._db is not None
        import datetime as _dt
        cur = self._db.execute(
            "INSERT INTO sessions (name, started_at, notes) VALUES (?, ?, ?)",
            (name, _dt.datetime.now(_dt.timezone.utc).isoformat(), notes),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    async def end_session(self, session_id: int, notes: Optional[str] = None) -> None:
        """Mark a session as ended."""
        if not self._db:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._end_session_sync, session_id, notes)
        if self._active_session_id == session_id:
            self._active_session_id = None

    def _end_session_sync(self, session_id: int, notes: Optional[str]) -> None:
        assert self._db is not None
        import datetime as _dt
        if notes is not None:
            self._db.execute(
                "UPDATE sessions SET ended_at = ?, notes = ? WHERE id = ?",
                (_dt.datetime.now(_dt.timezone.utc).isoformat(), notes, session_id),
            )
        else:
            self._db.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (_dt.datetime.now(_dt.timezone.utc).isoformat(), session_id),
            )
        self._db.commit()

    async def get_sessions(self) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_sessions_sync)

    def _get_sessions_sync(self) -> List[Dict[str, Any]]:
        assert self._db is not None
        cur = self._db.execute(
            "SELECT s.id, s.name, s.started_at, s.ended_at, s.notes, "
            "COUNT(e.id) as event_count "
            "FROM sessions s "
            "LEFT JOIN events e ON e.session_id = s.id "
            "GROUP BY s.id ORDER BY s.started_at DESC"
        )
        return [
            {
                "id": r[0], "name": r[1], "started_at": r[2],
                "ended_at": r[3], "notes": r[4], "event_count": r[5],
            }
            for r in cur.fetchall()
        ]

    # --- Retention ---

    async def _retention_loop(self) -> None:
        """Purge events older than retention_days on startup and every 6 hours."""
        while True:
            deleted = await self._purge_old_events()
            if deleted:
                self._total_purged += deleted
            await asyncio.sleep(6 * 3600)

    async def _purge_old_events(self) -> int:
        if not self._db or self.retention_days <= 0:
            return 0
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._purge_sync, self.retention_days)

    def _purge_sync(self, days: int) -> int:
        assert self._db is not None
        cur = self._db.execute(
            "DELETE FROM events WHERE ts_wall < datetime('now', ?)",
            (f"-{days} days",),
        )
        # Clean up orphaned event_groups rows
        self._db.execute(
            "DELETE FROM event_groups WHERE event_id NOT IN (SELECT id FROM events)"
        )
        self._db.commit()
        return cur.rowcount

    @property
    def stats(self) -> dict:
        return {
            "total_written": self._total_written,
            "total_purged": self._total_purged,
            "buffer_size": len(self._buffer),
            "path": str(self.path),
            "active_session_id": self._active_session_id,
            "retention_days": self.retention_days,
        }

    # --- Internal ---

    @staticmethod
    def _event_to_row(ev: Event, session_id: Optional[int] = None) -> tuple:
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
            session_id,
        )
