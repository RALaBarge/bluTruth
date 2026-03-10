"""
Shared test fixtures and helpers.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List

import pytest

from blutruth.events import Event


class MockBus:
    """Minimal EventBus substitute that collects published events."""

    def __init__(self) -> None:
        self.events: List[Event] = []

    async def publish(self, event: Event) -> None:
        self.events.append(event)

    def last(self) -> Event:
        return self.events[-1]

    def clear(self) -> None:
        self.events.clear()


@pytest.fixture
def mock_bus() -> MockBus:
    return MockBus()


@pytest.fixture
def default_config():
    """Config instance loaded purely from DEFAULT_CONFIG (no file I/O)."""
    from blutruth.config import Config
    return Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
