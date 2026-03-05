"""
blutruth.analysis.history — Per-device historical session comparison

Queries the SQLite database for past sessions that included a given device
and computes:
  - Disconnect count per session + reason breakdown
  - Session duration (first seen → last seen for that device)
  - Most common disconnect reasons across sessions
  - Anomalous sessions (unusually high disconnect rate vs. device baseline)

CLI usage:
  blutruth history AA:BB:CC:DD:EE:FF
  blutruth history AA:BB:CC:DD:EE:FF --sessions 10
  blutruth history AA:BB:CC:DD:EE:FF --json

Output shows per-session summary + aggregate statistics:

  Device: AA:BB:CC:DD:EE:FF  (Sony WH-1000XM4 / Sony Corp)
  ─────────────────────────────────────────────────────────
  Session 12 │ 2026-03-04 14:23 → 15:47 (1h24m) │ 2 disconnects │ normal
  Session 11 │ 2026-03-03 09:15 → 10:02 (47m)   │ 1 disconnect  │ normal
  Session 10 │ 2026-03-02 22:01 → 22:04 (3m)    │ 8 disconnects │ ANOMALOUS ← high rate

  Top disconnect reasons (last 5 sessions):
    0x08 CONNECTION_TIMEOUT         ×7  — RF dropout suspected
    0x13 REMOTE_USER_TERMINATED     ×3  — Normal (device turned off)
    0x16 CONNECTION_TERMINATED_BY   ×1  — Local host disconnected
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from blutruth.enrichment.hci_codes import decode_hci_error_short
from blutruth.enrichment.oui import enrich_oui


# ─── Data classes ─────────────────────────────────────────────────────────────

class DeviceSession:
    """Summary of a device's activity within one collection session."""

    def __init__(
        self,
        session_id: int,
        session_name: str,
        session_started_at: str,
        session_ended_at: Optional[str],
        first_seen: str,
        last_seen: str,
        event_count: int,
        disconnect_count: int,
        disconnect_reasons: Dict[str, int],  # reason_name → count
        severity_counts: Dict[str, int],     # severity → count
    ) -> None:
        self.session_id = session_id
        self.session_name = session_name
        self.session_started_at = session_started_at
        self.session_ended_at = session_ended_at
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.event_count = event_count
        self.disconnect_count = disconnect_count
        self.disconnect_reasons = disconnect_reasons
        self.severity_counts = severity_counts

    @property
    def duration_minutes(self) -> Optional[float]:
        try:
            from datetime import datetime, timezone
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            def _parse(s: str):
                for f in (fmt, "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return datetime.strptime(s[:26], f[:len(s)])
                    except ValueError:
                        continue
                return None
            t0 = _parse(self.first_seen)
            t1 = _parse(self.last_seen)
            if t0 and t1:
                return abs((t1 - t0).total_seconds()) / 60
        except Exception:
            pass
        return None


class DeviceHistory:
    """Aggregate history for a single device across multiple sessions."""

    def __init__(
        self,
        device_addr: str,
        device_name: Optional[str],
        manufacturer: Optional[str],
        sessions: List[DeviceSession],
    ) -> None:
        self.device_addr = device_addr
        self.device_name = device_name
        self.manufacturer = manufacturer
        self.sessions = sessions

    @property
    def total_disconnects(self) -> int:
        return sum(s.disconnect_count for s in self.sessions)

    @property
    def avg_disconnects_per_session(self) -> float:
        if not self.sessions:
            return 0.0
        return self.total_disconnects / len(self.sessions)

    @property
    def top_disconnect_reasons(self) -> List[tuple]:
        """Returns [(reason_name, count), ...] sorted by count descending."""
        total: Counter = Counter()
        for s in self.sessions:
            total.update(s.disconnect_reasons)
        return total.most_common()

    def anomalous_sessions(self, threshold_multiplier: float = 3.0) -> List[DeviceSession]:
        """Sessions with disconnect_count > threshold_multiplier × average."""
        avg = self.avg_disconnects_per_session
        if avg < 1.0:
            # Low baseline — flag anything with 3+ disconnects
            return [s for s in self.sessions if s.disconnect_count >= 3]
        return [s for s in self.sessions
                if s.disconnect_count > avg * threshold_multiplier]


# ─── Query functions ───────────────────────────────────────────────────────────

def query_device_sessions_sync(
    db: sqlite3.Connection,
    device_addr: str,
    num_sessions: int = 5,
) -> DeviceHistory:
    """
    Query historical sessions for a device. Returns a DeviceHistory.
    Must be called from a non-async context or via run_in_executor.
    """
    addr = device_addr.upper()

    # Get basic device info
    cur = db.execute(
        "SELECT device_name FROM events WHERE device_addr = ? LIMIT 1",
        (addr,),
    )
    row = cur.fetchone()
    device_name = row[0] if row else None
    manufacturer = enrich_oui(addr)

    # Get sessions that contain events for this device (most recent first)
    cur = db.execute(
        """
        SELECT DISTINCT e.session_id
        FROM events e
        WHERE e.device_addr = ?
          AND e.session_id IS NOT NULL
        ORDER BY e.session_id DESC
        LIMIT ?
        """,
        (addr, num_sessions),
    )
    session_ids = [r[0] for r in cur.fetchall()]

    if not session_ids:
        return DeviceHistory(addr, device_name, manufacturer, [])

    sessions: List[DeviceSession] = []
    for sid in session_ids:
        session_row = db.execute(
            "SELECT id, name, started_at, ended_at FROM sessions WHERE id = ?",
            (sid,),
        ).fetchone()
        if not session_row:
            continue

        # Get device event summary for this session
        summary = db.execute(
            """
            SELECT
                MIN(ts_wall) as first_seen,
                MAX(ts_wall) as last_seen,
                COUNT(*) as event_count
            FROM events
            WHERE device_addr = ? AND session_id = ?
            """,
            (addr, sid),
        ).fetchone()

        if not summary or not summary[0]:
            continue

        # Count disconnects
        disc_rows = db.execute(
            """
            SELECT raw_json
            FROM events
            WHERE device_addr = ?
              AND session_id = ?
              AND event_type = 'DISCONNECT'
            """,
            (addr, sid),
        ).fetchall()

        disconnect_reasons: Counter = Counter()
        for (raw_str,) in disc_rows:
            try:
                raw = json.loads(raw_str) if raw_str else {}
                reason_name = raw.get("reason_name") or raw.get("reason") or "UNKNOWN"
                disconnect_reasons[str(reason_name)] += 1
            except Exception:
                disconnect_reasons["UNKNOWN"] += 1

        # Severity breakdown
        sev_rows = db.execute(
            """
            SELECT severity, COUNT(*) as cnt
            FROM events
            WHERE device_addr = ? AND session_id = ?
            GROUP BY severity
            """,
            (addr, sid),
        ).fetchall()
        severity_counts = {r[0]: r[1] for r in sev_rows}

        sessions.append(DeviceSession(
            session_id=session_row[0],
            session_name=session_row[1] or f"Session {session_row[0]}",
            session_started_at=session_row[2] or "",
            session_ended_at=session_row[3],
            first_seen=summary[0],
            last_seen=summary[1],
            event_count=summary[2],
            disconnect_count=len(disc_rows),
            disconnect_reasons=dict(disconnect_reasons),
            severity_counts=severity_counts,
        ))

    return DeviceHistory(addr, device_name, manufacturer, sessions)


async def query_device_history(
    db_path: Path,
    device_addr: str,
    num_sessions: int = 5,
) -> DeviceHistory:
    """
    Async wrapper: open the database, query history, close.
    Use this from async code (CLI, web handlers).
    """
    loop = asyncio.get_running_loop()
    db = sqlite3.connect(db_path.as_posix(), check_same_thread=False, timeout=5.0)
    try:
        result = await loop.run_in_executor(
            None, query_device_sessions_sync, db, device_addr, num_sessions
        )
    finally:
        db.close()
    return result


# ─── Formatting ───────────────────────────────────────────────────────────────

def format_history(history: DeviceHistory, anomaly_threshold: float = 3.0) -> str:
    """
    Return a human-readable multi-line summary of device history.
    Used by the 'history' CLI subcommand.
    """
    lines: List[str] = []

    # Header
    name_part = f"  ({history.device_name})" if history.device_name else ""
    mfr_part = f" / {history.manufacturer}" if history.manufacturer else ""
    lines.append(f"Device: {history.device_addr}{name_part}{mfr_part}")
    lines.append("─" * 60)

    if not history.sessions:
        lines.append("  No session history found for this device.")
        return "\n".join(lines)

    anomalous = set(s.session_id for s in history.anomalous_sessions(anomaly_threshold))

    for s in history.sessions:
        dur = s.duration_minutes
        dur_str = _format_duration(dur) if dur is not None else "?"
        ts_short = s.first_seen[:16] if s.first_seen else "?"

        disc_str = f"{s.disconnect_count} disconnect" + ("s" if s.disconnect_count != 1 else "")
        anomaly_flag = "  ← ANOMALOUS (high disconnect rate)" if s.session_id in anomalous else ""
        severity_str = ""
        if s.severity_counts.get("ERROR", 0) or s.severity_counts.get("SUSPICIOUS", 0):
            errs = s.severity_counts.get("ERROR", 0)
            susp = s.severity_counts.get("SUSPICIOUS", 0)
            parts = []
            if errs:
                parts.append(f"{errs} error{'s' if errs != 1 else ''}")
            if susp:
                parts.append(f"{susp} suspicious")
            severity_str = "  [" + ", ".join(parts) + "]"

        lines.append(
            f"  Session {s.session_id:4d} │ {ts_short} ({dur_str}) │ "
            f"{disc_str}{severity_str}{anomaly_flag}"
        )

        # Show reason breakdown if any disconnects
        if s.disconnect_reasons:
            for reason, count in sorted(s.disconnect_reasons.items(),
                                        key=lambda x: -x[1]):
                lines.append(f"              └─ {reason:40s} ×{count}")

    lines.append("")
    lines.append(f"  Sessions shown: {len(history.sessions)}")
    lines.append(f"  Total disconnects: {history.total_disconnects}")
    lines.append(f"  Avg disconnects/session: {history.avg_disconnects_per_session:.1f}")

    top = history.top_disconnect_reasons
    if top:
        lines.append("")
        lines.append("  Top disconnect reasons:")
        for reason, count in top[:5]:
            lines.append(f"    {reason:42s} ×{count}")

    return "\n".join(lines)


def _format_duration(minutes: float) -> str:
    if minutes < 1:
        return f"{int(minutes * 60)}s"
    if minutes < 60:
        return f"{int(minutes)}m"
    h = int(minutes // 60)
    m = int(minutes % 60)
    return f"{h}h{m:02d}m"
