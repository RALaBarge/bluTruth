"""
blutruth.collectors.ebpf — eBPF kernel tracepoint collector

Attaches eBPF programs to kernel Bluetooth tracepoints for zero-overhead
in-kernel event capture. Unlike dmesg or ftrace (polling/text parsing),
eBPF programs run inside the kernel and push structured data directly to
userspace ring buffers.

Tracepoints targeted:
  bluetooth:hci_cmd_send        — HCI command leaving the host
  bluetooth:hci_evt_recv        — HCI event arriving from controller
  bluetooth:hci_send_frame      — ACL/SCO frame sent
  bluetooth:hci_recv_frame      — ACL/SCO frame received
  net:net_dev_xmit             — Network layer BT traffic (for PAN profiles)

  (Enumerate available BT tracepoints: perf list 'bluetooth:*')

What this adds over HCI collector:
  - Events are timestamped inside the kernel (CLOCK_MONOTONIC, nanosecond)
  - Zero-copy path — data never hits userspace text parsing
  - Can instrument kernel internals that btmon doesn't surface
  - Can track per-CPU execution context (which process triggered the event)

Requirements:
  - Linux kernel 5.8+ with BPF ring buffer support
  - CAP_BPF capability or root
  - BPF filesystem mounted at /sys/fs/bpf
  - Python: bcc (BPF Compiler Collection) or bpftools

Current status: MOCK MODE
  eBPF implementation requires bcc or bpftools and root. Neither has been
  implemented yet. This collector emits a startup notice and optionally
  generates synthetic kernel-level timing events for UI/pipeline testing.

  Enable mock data generation:
    collectors:
      ebpf:
        enabled: true
        mock_data: true         # emit synthetic eBPF-style events

FUTURE: Implement via bcc.BPF (Python bindings to LLVM/BPF compiler).
FUTURE: Implement via bpftrace one-liners (simpler, less flexible).
FUTURE: Ring buffer reader for high-frequency ACL events.
FUTURE (Rust port): aya crate — pure Rust eBPF without LLVM dependency.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any, Dict, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event


_BPF_FS = Path("/sys/fs/bpf")
_TRACEPOINTS = Path("/sys/kernel/debug/tracing/events/bluetooth")


class EbpfCollector(Collector):
    name = "ebpf"
    description = "Kernel BT tracepoints via eBPF [MOCK]"
    version = "0.1.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": True,    # CAP_BPF or root
            "requires_debugfs": True,
            "exclusive_resource": None,
            "optional_root_benefits": [
                "Nanosecond-precision kernel-side timestamps",
                "In-kernel ACL frame accounting without btmon overhead",
                "Per-process BT syscall attribution",
            ],
            "provides": ["EBPF_KERNEL"],
            "depends_on": [],
        }

    def enabled(self) -> bool:
        return bool(self.config.get("collectors", "ebpf", "enabled", default=False))

    async def start(self) -> None:
        if not self.enabled():
            return

        # Diagnose prerequisites
        has_root      = os.geteuid() == 0
        has_bpffs     = _BPF_FS.exists()
        has_tracepoints = _TRACEPOINTS.exists()

        try:
            import bcc  # noqa: F401
            has_bcc = True
        except ImportError:
            has_bcc = False

        prereqs = {
            "root":           has_root,
            "bpf_filesystem": has_bpffs,
            "bt_tracepoints": has_tracepoints,
            "bcc_installed":  has_bcc,
        }
        missing = [k for k, v in prereqs.items() if not v]

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            severity="WARN",
            event_type="COLLECTOR_MOCK",
            summary=(
                "eBPF collector: running in mock mode — "
                + (f"missing prerequisites: {', '.join(missing)}"
                   if missing
                   else "eBPF parsing not yet implemented")
            ),
            raw_json={
                "status": "mock",
                "prerequisites": prereqs,
                "missing": missing,
                "implementation_status": "not_yet_implemented",
                "targeted_tracepoints": [
                    "bluetooth:hci_cmd_send",
                    "bluetooth:hci_evt_recv",
                    "bluetooth:hci_send_frame",
                    "bluetooth:hci_recv_frame",
                ],
                "future_implementation": {
                    "python": "bcc.BPF (pip install bcc)",
                    "rust": "aya crate (https://aya-rs.dev/)",
                    "alternative": "bpftrace bluetooth:* scripts",
                },
            },
            source_version=self.source_version_tag,
        ))

        mock_data = bool(self.config.get("collectors", "ebpf", "mock_data", default=False))
        if mock_data:
            self._running = True
            self._task = asyncio.create_task(self._mock_loop())
            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                event_type="COLLECTOR_START",
                summary="eBPF mock data generator started",
                raw_json={"mode": "mock"},
                source_version=self.source_version_tag,
            ))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _mock_loop(self) -> None:
        """Emit periodic synthetic kernel-level timing events."""
        import random
        import time

        mock_pids = [
            (1234, "bluetoothd"),
            (5678, "pipewire"),
            (9012, "spotify"),
        ]

        mock_events = [
            ("HCI_CMD_SEND", "DEBUG", None,         "hci_cmd_send: ogf=0x01 ocf=0x{ocf:04x} pid={pid} ({comm})"),
            ("HCI_EVT_RECV", "DEBUG", None,         "hci_evt_recv: evt=0x{evt:02x} latency_us={lat}μs"),
            ("HCI_SEND",     "DEBUG", "DATA",        "hci_send_frame: ACL {nbytes}B pid={pid} ({comm})"),
            ("HCI_RECV",     "DEBUG", "DATA",        "hci_recv_frame: ACL {nbytes}B latency_us={lat}μs"),
            ("HCI_CMD_SEND", "WARN",  "HANDSHAKE",  "hci_cmd_send: ogf=0x01 ocf=0x0011 DISCONNECT_REQUEST"),
        ]

        while self._running:
            await asyncio.sleep(random.uniform(1.5, 5.0))
            if not self._running:
                break

            ev_type, sev, stage, summary_tmpl = random.choice(mock_events)
            pid, comm = random.choice(mock_pids)
            ocf = random.randint(0, 0x3FF)
            evt = random.randint(0, 0xFF)
            lat = random.randint(50, 800)
            nbytes = random.choice([27, 54, 251, 512])
            ts_ns = int(time.monotonic() * 1_000_000_000)
            summary = summary_tmpl.format(pid=pid, comm=comm, ocf=ocf, evt=evt, lat=lat, nbytes=nbytes)

            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                severity=sev,
                stage=stage,
                event_type=ev_type,
                summary=f"[MOCK] {summary}",
                raw_json={
                    "mock": True,
                    "ts_kernel_ns": ts_ns,
                    "pid": pid,
                    "comm": comm,
                    "tracepoint": f"bluetooth:{ev_type.lower()}",
                },
                tags=["mock", "kernel"],
                source_version=self.source_version_tag,
            ))
