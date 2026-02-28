"""
blutruth.collectors.base — Collector plugin interface

Every data source implements this ABC. The capabilities() method declares
what the collector needs (root, debugfs, exclusive resources) so the runtime
can check prerequisites and warn about degraded visibility.

FUTURE: Dynamic plugin discovery from a directory / entrypoints.
FUTURE (Rust port): trait Collector with the same method signatures.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.config import Config


class Collector(ABC):
    """Base interface for all diagnostic stream collectors."""

    name: str = "base"
    description: str = "Base collector"
    version: str = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        self.bus = bus
        self.config = config
        self._running = False

    @abstractmethod
    async def start(self) -> None:
        """Begin collecting events and publishing to the bus."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop collecting and clean up resources."""
        ...

    def enabled(self) -> bool:
        """Check config to see if this collector is turned on."""
        return bool(self.config.get("collectors", self.name, "enabled", default=True))

    def capabilities(self) -> Dict[str, Any]:
        """Declare requirements and provisions.

        The runtime uses this to:
        - Skip collectors whose prerequisites aren't met
        - Warn the user about lost visibility
        - Manage exclusive resources (e.g., btmon monitor socket)
        - Order startup based on dependencies
        """
        return {
            "requires_root": False,
            "requires_debugfs": False,
            "exclusive_resource": None,     # e.g., "hci_monitor_socket"
            "optional_root_benefits": [],   # human-readable strings
            "provides": [],                 # source tags this collector emits
            "depends_on": [],               # other collector names needed first
        }

    @property
    def source_version_tag(self) -> str:
        return f"{self.name}-collector-{self.version}"

    @property
    def is_running(self) -> bool:
        return self._running
