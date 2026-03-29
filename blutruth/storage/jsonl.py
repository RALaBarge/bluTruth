"""
blutruth.storage.jsonl — Append-only JSONL flight recorder

One JSON object per line. Never modified, only appended.
The "truth log" — portable, shareable, parseable with jq/Python/Rust/anything.
Attach to a bug report. Survives schema migrations.

FUTURE (Rust port): serde_json + BufWriter with the same line format.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import IO, Optional

from blutruth.events import Event


class JsonlSink:
    """Async-safe JSONL writer. Append-only, line-buffered."""

    def __init__(self, path: Path):
        self.path = path
        self._fp: Optional[IO[str]] = None
        self._total_written: int = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = open(self.path, "a", buffering=1, encoding="utf-8")

    async def stop(self) -> None:
        if self._fp:
            self._fp.flush()
            self._fp.close()
            self._fp = None

    async def write(self, event: Event) -> None:
        if not self._fp:
            return
        line = event.to_json() + "\n"
        async with self._lock:
            self._fp.write(line)
            self._total_written += 1

    async def roll(self, ts: str) -> Path:
        """Flush, close, rename current JSONL to a timestamped backup, then reopen fresh."""
        await self.stop()
        backup = self.path.with_name(f"{self.path.stem}.{ts}.jsonl")
        self.path.rename(backup)
        self._total_written = 0
        await self.start()
        return backup

    async def delete(self) -> None:
        """Close and delete the JSONL file, then reopen fresh."""
        await self.stop()
        if self.path.exists():
            self.path.unlink()
        self._total_written = 0
        await self.start()

    @property
    def stats(self) -> dict:
        size_bytes = 0
        if self.path.exists():
            size_bytes = self.path.stat().st_size
        return {
            "total_written": self._total_written,
            "size_bytes": size_bytes,
            "path": str(self.path),
        }
