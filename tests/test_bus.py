"""
Tests for blutruth.bus — EventBus pub/sub mechanics.
"""
from __future__ import annotations

import asyncio

import pytest

from blutruth.bus import EventBus
from blutruth.events import Event


def _make_event(summary: str = "test") -> Event:
    return Event.new(source="RUNTIME", event_type="GENERIC", summary=summary, raw_json={})


# ---------------------------------------------------------------------------
# Subscribe / publish basics
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subscribe_returns_queue():
    bus = EventBus()
    q = await bus.subscribe()
    assert isinstance(q, asyncio.Queue)
    await bus.unsubscribe(q)


@pytest.mark.asyncio
async def test_publish_delivers_to_subscriber():
    bus = EventBus()
    q = await bus.subscribe()
    ev = _make_event("hello")

    await bus.publish(ev)

    received = await asyncio.wait_for(q.get(), timeout=1.0)
    assert received.event_id == ev.event_id
    await bus.unsubscribe(q)


@pytest.mark.asyncio
async def test_publish_fan_out_multiple_subscribers():
    bus = EventBus()
    q1 = await bus.subscribe()
    q2 = await bus.subscribe()
    ev = _make_event("fan-out")

    await bus.publish(ev)

    r1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    r2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert r1.event_id == ev.event_id
    assert r2.event_id == ev.event_id

    await bus.unsubscribe(q1)
    await bus.unsubscribe(q2)


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    bus = EventBus()
    q = await bus.subscribe()
    await bus.unsubscribe(q)

    # After unsubscribing, publish should not deliver to this queue
    await bus.publish(_make_event())

    assert q.empty()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stats_initial_state():
    bus = EventBus()
    s = bus.stats
    assert s["subscribers"] == 0
    assert s["total_published"] == 0
    assert s["total_dropped"] == 0


@pytest.mark.asyncio
async def test_stats_published_increments():
    bus = EventBus()
    q = await bus.subscribe()
    await bus.publish(_make_event())
    await bus.publish(_make_event())

    assert bus.stats["total_published"] == 2
    await bus.unsubscribe(q)


@pytest.mark.asyncio
async def test_stats_subscribers_count():
    bus = EventBus()
    q1 = await bus.subscribe()
    q2 = await bus.subscribe()
    assert bus.stats["subscribers"] == 2

    await bus.unsubscribe(q1)
    assert bus.stats["subscribers"] == 1

    await bus.unsubscribe(q2)
    assert bus.stats["subscribers"] == 0


# ---------------------------------------------------------------------------
# Drop behavior (best-effort)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_queue_drops_events():
    bus = EventBus()
    # Very small queue
    q = await bus.subscribe(max_queue=2)

    # Fill queue without consuming
    for _ in range(5):
        await bus.publish(_make_event())

    # Queue should be full but not more than max_queue
    assert q.qsize() <= 2
    assert bus.stats["total_dropped"] > 0
    await bus.unsubscribe(q)


@pytest.mark.asyncio
async def test_drop_does_not_crash_other_subscribers():
    bus = EventBus()
    q_small = await bus.subscribe(max_queue=1)
    q_large = await bus.subscribe(max_queue=100)

    for _ in range(10):
        await bus.publish(_make_event())

    # Large queue should have received all 10
    assert q_large.qsize() == 10
    await bus.unsubscribe(q_small)
    await bus.unsubscribe(q_large)


# ---------------------------------------------------------------------------
# No subscribers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_with_no_subscribers_does_not_raise():
    bus = EventBus()
    await bus.publish(_make_event())  # should not raise
    assert bus.stats["total_published"] == 1
