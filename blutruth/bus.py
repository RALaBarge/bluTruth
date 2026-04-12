"""
blutruth.bus — In-process async event bus

All collectors publish events here. Subscribers (storage writers, correlation
engine, SSE stream, CLI tail) each get their own queue.

FUTURE (daemon split): Replace with IPC (unix socket + framed JSON, or gRPC).
FUTURE (Rust port): tokio::sync::broadcast channel.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import List

from blutruth.events import Event

logger = logging.getLogger("blutruth.bus")

# Warn every N drops (not every single one — would flood logs)
_DROP_WARN_INTERVAL = 100


class EventBus:
    """Fan-out pub/sub. Publishers call publish(); subscribers get independent queues."""

    def __init__(self) -> None:
        self._subscribers: List[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()
        self._total_published: int = 0
        self._total_dropped: int = 0
        self._last_drop_warn: int = 0

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers. Best-effort: drops if a subscriber is slow."""
        async with self._lock:
            self._total_published += 1
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    self._total_dropped += 1
                    if self._total_dropped - self._last_drop_warn >= _DROP_WARN_INTERVAL:
                        self._last_drop_warn = self._total_dropped
                        logger.warning(
                            "EventBus dropped %d events total "
                            "(%d published, %d subscribers) — "
                            "slow subscriber cannot keep up",
                            self._total_dropped,
                            self._total_published,
                            len(self._subscribers),
                        )

    async def subscribe(self, max_queue: int = 5000) -> asyncio.Queue[Event]:
        """Create a new subscription queue."""
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue)
        async with self._lock:
            self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        """Remove a subscription queue."""
        async with self._lock:
            with contextlib.suppress(ValueError):
                self._subscribers.remove(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def stats(self) -> dict:
        return {
            "subscribers": self.subscriber_count,
            "total_published": self._total_published,
            "total_dropped": self._total_dropped,
        }
