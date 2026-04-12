"""
Tests for blutruth.storage — SqliteSink and JsonlSink.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from blutruth.events import Event
from blutruth.storage.sqlite import SqliteSink
from blutruth.storage.jsonl import JsonlSink


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> Event:
    defaults = dict(
        source="HCI",
        summary="test event",
        raw_json={"test": True},
        event_type="TEST",
        severity="INFO",
    )
    defaults.update(overrides)
    return Event.new(**defaults)


# ---------------------------------------------------------------------------
# SqliteSink
# ---------------------------------------------------------------------------

@pytest.fixture
def sqlite_path(tmp_path):
    return tmp_path / "test_events.db"


@pytest.fixture
async def sqlite(sqlite_path):
    sink = SqliteSink(sqlite_path, batch_size=1, flush_interval_s=0.1)
    await sink.start()
    yield sink
    await sink.stop()


@pytest.mark.asyncio
async def test_sqlite_start_creates_db(sqlite_path):
    sink = SqliteSink(sqlite_path, batch_size=1, flush_interval_s=0.1)
    await sink.start()
    assert sqlite_path.exists()
    await sink.stop()


@pytest.mark.asyncio
async def test_sqlite_write_and_query(sqlite):
    ev = _make_event(device_addr="AA:BB:CC:DD:EE:FF")
    await sqlite.write(ev)
    await sqlite._flush()

    # Query all recent events
    now_us = Event._boot_us()
    results = await sqlite.query_window(0, now_us + 1_000_000)
    assert len(results) >= 1
    found = [r for r in results if r["device_addr"] == "AA:BB:CC:DD:EE:FF"]
    assert len(found) == 1


@pytest.mark.asyncio
async def test_sqlite_multiple_writes(sqlite):
    for i in range(10):
        ev = _make_event(summary=f"event {i}", device_addr="11:22:33:44:55:66")
        await sqlite.write(ev)
    await sqlite._flush()

    now_us = Event._boot_us()
    results = await sqlite.query_window(0, now_us + 1_000_000)
    device_events = [r for r in results if r["device_addr"] == "11:22:33:44:55:66"]
    assert len(device_events) == 10


@pytest.mark.asyncio
async def test_sqlite_session_lifecycle(sqlite):
    session_id = await sqlite.create_session("test session")
    assert isinstance(session_id, int)
    assert session_id > 0

    await sqlite.end_session(session_id)


@pytest.mark.asyncio
async def test_sqlite_set_group_id(sqlite):
    ev = _make_event(device_addr="AA:BB:CC:DD:EE:FF")
    await sqlite.write(ev)
    await sqlite._flush()

    now_us = Event._boot_us()
    results = await sqlite.query_window(0, now_us + 1_000_000)
    assert len(results) >= 1

    event_id = results[0]["id"]
    await sqlite.set_group_id(event_id, 42, "PRIMARY")


@pytest.mark.asyncio
async def test_sqlite_stats(sqlite):
    stats = sqlite.stats
    assert "total_written" in stats


@pytest.mark.asyncio
async def test_sqlite_roll(sqlite_path):
    sink = SqliteSink(sqlite_path, batch_size=1, flush_interval_s=0.1)
    await sink.start()
    ev = _make_event()
    await sink.write(ev)
    await sink._flush()

    backup = await sink.roll("test_backup")
    assert backup.exists()
    assert sqlite_path.exists()  # new db created
    await sink.stop()


@pytest.mark.asyncio
async def test_sqlite_delete(tmp_path):
    path = tmp_path / "delete_test.db"
    sink = SqliteSink(path, batch_size=1, flush_interval_s=0.1)
    await sink.start()
    ev = _make_event()
    await sink.write(ev)
    await sink._flush()
    assert path.exists()

    await sink.delete()
    # After delete, sink should reinitialize
    await sink.start()
    await sink.stop()


# ---------------------------------------------------------------------------
# JsonlSink
# ---------------------------------------------------------------------------

@pytest.fixture
def jsonl_path(tmp_path):
    return tmp_path / "test_events.jsonl"


@pytest.fixture
async def jsonl(jsonl_path):
    sink = JsonlSink(jsonl_path)
    await sink.start()
    yield sink
    await sink.stop()


@pytest.mark.asyncio
async def test_jsonl_start_creates_file(jsonl_path):
    sink = JsonlSink(jsonl_path)
    await sink.start()
    assert jsonl_path.exists()
    await sink.stop()


@pytest.mark.asyncio
async def test_jsonl_write_event(jsonl):
    ev = _make_event(summary="jsonl test")
    await jsonl.write(ev)
    pass  # JSONL is line-buffered, writes are immediate

    lines = jsonl.path.read_text().strip().split("\n")
    assert len(lines) >= 1
    data = json.loads(lines[-1])
    assert data["summary"] == "jsonl test"


@pytest.mark.asyncio
async def test_jsonl_multiple_writes(jsonl):
    for i in range(5):
        ev = _make_event(summary=f"line {i}")
        await jsonl.write(ev)
    pass  # JSONL is line-buffered, writes are immediate

    lines = jsonl.path.read_text().strip().split("\n")
    assert len(lines) == 5


@pytest.mark.asyncio
async def test_jsonl_valid_json_per_line(jsonl):
    for i in range(3):
        await jsonl.write(_make_event(summary=f"json {i}"))
    pass  # JSONL is line-buffered, writes are immediate

    for line in jsonl.path.read_text().strip().split("\n"):
        data = json.loads(line)  # should not raise
        assert "summary" in data
        assert "source" in data


@pytest.mark.asyncio
async def test_jsonl_stats(jsonl):
    stats = jsonl.stats
    assert "total_written" in stats


@pytest.mark.asyncio
async def test_jsonl_roll(jsonl_path):
    sink = JsonlSink(jsonl_path)
    await sink.start()
    await sink.write(_make_event())

    backup = await sink.roll("test_backup")
    assert backup.exists()
    await sink.stop()
