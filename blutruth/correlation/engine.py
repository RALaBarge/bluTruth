"""
blutruth.correlation.engine — Cross-source event correlation

The core differentiator. Links related events from different sources
within configurable time windows to create unified diagnostic views.

Runs as a background async task, periodically scanning recent uncorrelated
events and grouping them by device address and time proximity.

FUTURE: Load correlation rules from YAML rule packs.
FUTURE: Anomaly detection patterns (KNOB, BIAS, SSP downgrade, etc.)
FUTURE (Rust port): Same algorithm, same group_id assignments.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.config import Config
from blutruth.events import Event
from blutruth.storage.sqlite import SqliteSink


class CorrelationEngine:
    """
    Background correlation pass.

    Strategy:
    1. Every `batch_interval_s` seconds, query recent uncorrelated events
    2. Group events by (device_addr, time_window)
    3. If a group spans multiple sources, assign a shared group_id
    4. Write group_id back to SQLite

    This is intentionally simple — rule-based correlation is Phase 2.
    The time-window approach catches the most important correlations
    (HCI disconnect + D-Bus Connected:false + daemon log entry) without
    needing explicit rule definitions.
    """

    def __init__(
        self,
        bus: EventBus,
        config: Config,
        sqlite: SqliteSink,
    ) -> None:
        self.bus = bus
        self.config = config
        self.sqlite = sqlite
        self._task: Optional[asyncio.Task] = None
        self._next_group_id: int = 1
        self._last_processed_us: int = 0
        self._total_groups_created: int = 0
        self._total_events_correlated: int = 0

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        await self.bus.publish(Event.new(
            source="RUNTIME",
            event_type="CORRELATION_START",
            summary="Correlation engine started",
            raw_json={
                "time_window_ms": self.config.get("correlation", "time_window_ms", default=100),
                "batch_interval_s": self.config.get("correlation", "batch_interval_s", default=2.0),
            },
        ))

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        """Periodic correlation pass."""
        while True:
            interval = self.config.get("correlation", "batch_interval_s", default=2.0)
            await asyncio.sleep(interval)

            try:
                await self._correlate_pass()
            except Exception as e:
                await self.bus.publish(Event.new(
                    source="RUNTIME",
                    severity="WARN",
                    event_type="CORRELATION_ERROR",
                    summary=f"Correlation pass error: {e}",
                    raw_json={"error": str(e)},
                ))

    async def _correlate_pass(self) -> None:
        """One pass: find uncorrelated events and group them."""
        window_ms = self.config.get("correlation", "time_window_ms", default=100)
        window_us = window_ms * 1000

        # Query recent events that haven't been correlated yet.
        # Overlap by 2× the correlation window to catch out-of-order events
        # that arrived after the watermark advanced past their timestamp.
        lookback_us = 5_000_000
        overlap_us = window_us * 2
        now_us = Event._boot_us()
        start_us = max(self._last_processed_us - overlap_us, now_us - lookback_us)

        events = await self.sqlite.query_window(start_us, now_us)
        if not events:
            return

        # Filter to uncorrelated events only (group_id not in the query result
        # since query_window doesn't return group_id for the lightweight query,
        # we'll need to check)
        # FUTURE: Add group_id filter to query_window

        # Group by device_addr
        by_device: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            addr = ev.get("device_addr")
            if addr:
                by_device[addr].append(ev)

        # For each device, find time-clustered events from multiple sources
        for addr, device_events in by_device.items():
            if len(device_events) < 2:
                continue

            # Sort by time
            device_events.sort(key=lambda e: e["ts_mono_us"])

            # Sliding window: cluster events within window_us of each other
            clusters = self._cluster_events(device_events, window_us)

            for cluster in clusters:
                # Only correlate if the cluster spans multiple sources
                sources = set(ev["source"] for ev in cluster)
                if len(sources) < 2:
                    continue

                group_id = self._next_group_id
                self._next_group_id += 1
                self._total_groups_created += 1

                # Assign group_id to all events in the cluster
                primary_set = False
                for ev in cluster:
                    role = "PRIMARY" if not primary_set else "CORRELATED"
                    primary_set = True
                    await self.sqlite.set_group_id(ev["id"], group_id, role)
                    self._total_events_correlated += 1

        # Advance watermark
        if events:
            self._last_processed_us = max(ev["ts_mono_us"] for ev in events)

    @staticmethod
    def _cluster_events(
        sorted_events: List[Dict[str, Any]], window_us: int
    ) -> List[List[Dict[str, Any]]]:
        """Group time-proximate events into clusters."""
        if not sorted_events:
            return []

        clusters = []
        current_cluster = [sorted_events[0]]

        for ev in sorted_events[1:]:
            # Check if this event is within window of the last event in cluster
            if ev["ts_mono_us"] - current_cluster[-1]["ts_mono_us"] <= window_us:
                current_cluster.append(ev)
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [ev]

        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        return clusters

    @property
    def stats(self) -> dict:
        return {
            "total_groups_created": self._total_groups_created,
            "total_events_correlated": self._total_events_correlated,
            "next_group_id": self._next_group_id,
        }
