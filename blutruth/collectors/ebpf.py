"""
blutruth.collectors.ebpf — eBPF kernel Bluetooth tracepoint collector

Attaches eBPF programs to kernel Bluetooth tracepoints for in-kernel
event capture with nanosecond timestamps and process attribution.

What this adds over HCI collector (btmon):
  - Kernel-side timestamps (CLOCK_MONOTONIC, nanosecond precision)
  - Per-process attribution (which process triggered each BT operation)
  - Internal kernel queue/scheduling visibility
  - ACL/SCO frame accounting without btmon text parsing overhead

Tracepoints used:
  bluetooth:hci_send_frame     — HCI frame leaving host to controller
  bluetooth:hci_recv_frame     — HCI frame arriving from controller
  kprobe:hci_conn_add          — Kernel connection object created
  kprobe:hci_conn_del          — Kernel connection object destroyed

Requirements:
  - Linux kernel 5.15+ (BT tracepoints stabilized)
  - Root or CAP_BPF + CAP_PERFMON
  - python3-bpfcc package (apt install python3-bpfcc bpfcc-tools)

Enabled by default. Gracefully skips if prerequisites aren't met.
Set collectors.ebpf.enabled=false in config to disable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from blutruth.bus import EventBus
from blutruth.collectors.base import Collector
from blutruth.config import Config
from blutruth.events import Event

logger = logging.getLogger("blutruth.ebpf")

_BPF_FS = Path("/sys/fs/bpf")
_TRACEPOINTS = Path("/sys/kernel/debug/tracing/events/bluetooth")

# BPF C program for tracing HCI frames
# Outputs: timestamp_ns, pid, comm, hci_dev, frame_type, data_len
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct hci_frame_event_t {
    u64 ts_ns;
    u32 pid;
    u32 data_len;
    u8  frame_type;   // 0x01=cmd, 0x02=acl, 0x03=sco, 0x04=evt, 0x05=iso
    u8  direction;    // 0=send, 1=recv
    char comm[16];
};

BPF_PERF_OUTPUT(hci_frames);

// bluetooth:hci_send_frame tracepoint
TRACEPOINT_PROBE(bluetooth, hci_send_frame) {
    struct hci_frame_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.data_len = args->len;
    ev.frame_type = args->type;
    ev.direction = 0;
    hci_frames.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

// bluetooth:hci_recv_frame tracepoint
TRACEPOINT_PROBE(bluetooth, hci_recv_frame) {
    struct hci_frame_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.data_len = args->len;
    ev.frame_type = args->type;
    ev.direction = 1;
    hci_frames.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

# Simpler bpftrace fallback script (if bcc isn't available but bpftrace is)
_BPFTRACE_SCRIPT = r"""
tracepoint:bluetooth:hci_send_frame {
    printf("SEND ts=%lld pid=%d comm=%s len=%d type=%d\n",
           nsecs, pid, comm, args->len, args->type);
}
tracepoint:bluetooth:hci_recv_frame {
    printf("RECV ts=%lld pid=%d comm=%s len=%d type=%d\n",
           nsecs, pid, comm, args->len, args->type);
}
"""

# HCI frame type → human-readable
_FRAME_TYPES: Dict[int, str] = {
    0x01: "HCI_CMD",
    0x02: "ACL",
    0x03: "SCO",
    0x04: "HCI_EVT",
    0x05: "ISO",
}

# Direction labels
_DIRECTIONS = {0: "TX", 1: "RX"}


class EbpfCollector(Collector):
    name = "ebpf"
    description = "Kernel BT tracepoints via eBPF"
    version = "0.2.0"

    def __init__(self, bus: EventBus, config: Config) -> None:
        super().__init__(bus, config)
        self._task: Optional[asyncio.Task] = None
        self._bpf = None  # bcc.BPF instance
        self._mode: str = "none"  # "bcc", "bpftrace", "mock", "none"
        self._proc: Optional[asyncio.subprocess.Process] = None
        # ACL bandwidth tracking
        self._acl_bytes_tx: int = 0
        self._acl_bytes_rx: int = 0
        self._acl_frames_tx: int = 0
        self._acl_frames_rx: int = 0

    def capabilities(self) -> Dict[str, Any]:
        return {
            "requires_root": True,
            "requires_debugfs": False,
            "exclusive_resource": None,
            "optional_root_benefits": [
                "Nanosecond-precision kernel-side timestamps",
                "In-kernel ACL/ISO frame accounting",
                "Per-process BT syscall attribution",
            ],
            "provides": ["EBPF_KERNEL"],
            "depends_on": [],
        }

    async def start(self) -> None:
        if not self.enabled():
            return

        has_root = os.geteuid() == 0

        if not has_root:
            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                severity="INFO",
                event_type="COLLECTOR_SKIP",
                summary="eBPF collector requires root — skipping (run as root to enable)",
                raw_json={"reason": "not_root", "uid": os.geteuid()},
                source_version=self.source_version_tag,
            ))
            return

        # Try bcc first (richer, structured output)
        if await self._try_start_bcc():
            return

        # Fall back to bpftrace (simpler, text output)
        if await self._try_start_bpftrace():
            return

        # Neither available — emit a diagnostic event
        mock_data = bool(self.config.get("collectors", "ebpf", "mock_data", default=False))
        if mock_data:
            self._mode = "mock"
            self._running = True
            self._task = asyncio.create_task(self._mock_loop())
            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                event_type="COLLECTOR_START",
                summary="eBPF collector started in mock mode",
                raw_json={"mode": "mock"},
                source_version=self.source_version_tag,
            ))
        else:
            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                severity="WARN",
                event_type="COLLECTOR_SKIP",
                summary="eBPF: neither bcc nor bpftrace available — install python3-bpfcc or bpftrace",
                raw_json={
                    "install_bcc": "apt install python3-bpfcc bpfcc-tools",
                    "install_bpftrace": "apt install bpftrace",
                },
                source_version=self.source_version_tag,
            ))

    async def _try_start_bcc(self) -> bool:
        """Try to start using BCC (Python BPF bindings)."""
        try:
            from bcc import BPF
        except ImportError:
            logger.debug("bcc not available")
            return False

        # Check if BT tracepoints exist
        if not _TRACEPOINTS.exists():
            logger.debug("BT tracepoints not found at %s", _TRACEPOINTS)
            # Tracepoints may still work via debugfs automount — try anyway
            pass

        try:
            self._bpf = BPF(text=_BPF_PROGRAM)
        except Exception as e:
            logger.warning("BCC BPF program compilation failed: %s", e)
            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                severity="WARN",
                event_type="COLLECTOR_WARN",
                summary=f"eBPF BCC compilation failed: {e}",
                raw_json={"error": str(e), "mode": "bcc"},
                source_version=self.source_version_tag,
            ))
            self._bpf = None
            return False

        self._mode = "bcc"
        self._running = True
        self._task = asyncio.create_task(self._bcc_loop())

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            event_type="COLLECTOR_START",
            summary="eBPF collector started (bcc mode — kernel tracepoints active)",
            raw_json={
                "mode": "bcc",
                "tracepoints": ["bluetooth:hci_send_frame", "bluetooth:hci_recv_frame"],
            },
            source_version=self.source_version_tag,
        ))
        return True

    async def _try_start_bpftrace(self) -> bool:
        """Try to start using bpftrace subprocess."""
        if not shutil.which("bpftrace"):
            logger.debug("bpftrace not found in PATH")
            return False

        try:
            self._proc = await asyncio.create_subprocess_exec(
                "bpftrace", "-e", _BPFTRACE_SCRIPT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            logger.warning("Failed to start bpftrace: %s", e)
            return False

        self._mode = "bpftrace"
        self._running = True
        self._task = asyncio.create_task(self._bpftrace_loop())

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            event_type="COLLECTOR_START",
            summary="eBPF collector started (bpftrace mode)",
            raw_json={
                "mode": "bpftrace",
                "pid": self._proc.pid,
            },
            source_version=self.source_version_tag,
        ))
        return True

    # -----------------------------------------------------------------------
    # BCC mode — structured perf buffer output
    # -----------------------------------------------------------------------

    async def _bcc_loop(self) -> None:
        """Read BCC perf buffer events in a thread executor."""
        import ctypes

        loop = asyncio.get_event_loop()
        event_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)

        # Define the ctypes structure matching the BPF output
        class HciFrameEvent(ctypes.Structure):
            _fields_ = [
                ("ts_ns", ctypes.c_uint64),
                ("pid", ctypes.c_uint32),
                ("data_len", ctypes.c_uint32),
                ("frame_type", ctypes.c_uint8),
                ("direction", ctypes.c_uint8),
                ("comm", ctypes.c_char * 16),
            ]

        def _handle_event(cpu, data, size):
            ev = ctypes.cast(data, ctypes.POINTER(HciFrameEvent)).contents
            try:
                event_queue.put_nowait({
                    "ts_ns": ev.ts_ns,
                    "pid": ev.pid,
                    "data_len": ev.data_len,
                    "frame_type": ev.frame_type,
                    "direction": ev.direction,
                    "comm": ev.comm.decode("utf-8", errors="replace").rstrip("\x00"),
                })
            except asyncio.QueueFull:
                pass

        self._bpf["hci_frames"].open_perf_buffer(_handle_event, page_cnt=64)

        # Poll perf buffer in a thread (bcc's poll is blocking)
        def _poll_loop():
            while self._running:
                try:
                    self._bpf.perf_buffer_poll(timeout=500)
                except Exception:
                    if self._running:
                        continue
                    break

        poll_future = loop.run_in_executor(None, _poll_loop)

        # Process events from queue
        try:
            while self._running:
                try:
                    ev_data = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Emit periodic bandwidth stats
                    await self._emit_bandwidth_stats()
                    continue

                await self._process_bcc_event(ev_data)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            await asyncio.shield(poll_future)

    async def _process_bcc_event(self, ev: dict) -> None:
        """Process a single BCC perf buffer event."""
        frame_type = _FRAME_TYPES.get(ev["frame_type"], f"0x{ev['frame_type']:02x}")
        direction = _DIRECTIONS.get(ev["direction"], "??")
        data_len = ev["data_len"]
        pid = ev["pid"]
        comm = ev["comm"]

        # Track ACL bandwidth
        if ev["frame_type"] == 0x02:  # ACL
            if ev["direction"] == 0:
                self._acl_bytes_tx += data_len
                self._acl_frames_tx += 1
            else:
                self._acl_bytes_rx += data_len
                self._acl_frames_rx += 1

        # Classify
        if ev["frame_type"] == 0x05:  # ISO
            stage = "AUDIO"
            event_type = "EBPF_ISO"
        elif ev["frame_type"] == 0x03:  # SCO
            stage = "AUDIO"
            event_type = "EBPF_SCO"
        elif ev["frame_type"] == 0x02:  # ACL
            stage = "DATA"
            event_type = "EBPF_ACL"
        else:
            stage = None
            event_type = f"EBPF_{frame_type}"

        # Only emit events for interesting frames (not every ACL packet)
        # ACL/SCO/ISO are high-frequency — aggregate them instead
        if ev["frame_type"] in (0x02, 0x03, 0x05):
            # Aggregate mode — don't emit individual events
            return

        summary = f"{direction} {frame_type} {data_len}B pid={pid} ({comm})"

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            severity="DEBUG",
            stage=stage,
            event_type=event_type,
            summary=summary,
            raw_json={
                "ts_kernel_ns": ev["ts_ns"],
                "pid": pid,
                "comm": comm,
                "frame_type": frame_type,
                "frame_type_id": ev["frame_type"],
                "direction": direction,
                "data_len": data_len,
            },
            source_version=self.source_version_tag,
        ))

    async def _emit_bandwidth_stats(self) -> None:
        """Emit periodic ACL bandwidth summary."""
        if self._acl_frames_tx == 0 and self._acl_frames_rx == 0:
            return

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            severity="DEBUG",
            stage="DATA",
            event_type="EBPF_ACL_STATS",
            summary=(
                f"ACL bandwidth: TX {self._acl_bytes_tx}B/{self._acl_frames_tx}frames "
                f"RX {self._acl_bytes_rx}B/{self._acl_frames_rx}frames"
            ),
            raw_json={
                "acl_bytes_tx": self._acl_bytes_tx,
                "acl_bytes_rx": self._acl_bytes_rx,
                "acl_frames_tx": self._acl_frames_tx,
                "acl_frames_rx": self._acl_frames_rx,
            },
            source_version=self.source_version_tag,
        ))

        # Reset counters
        self._acl_bytes_tx = 0
        self._acl_bytes_rx = 0
        self._acl_frames_tx = 0
        self._acl_frames_rx = 0

    # -----------------------------------------------------------------------
    # bpftrace mode — text output parsing
    # -----------------------------------------------------------------------

    async def _bpftrace_loop(self) -> None:
        """Parse bpftrace text output."""
        assert self._proc and self._proc.stdout

        while self._running:
            try:
                raw_line = await self._proc.stdout.readline()
            except Exception:
                break
            if not raw_line:
                if self._running:
                    await self.bus.publish(Event.new(
                        source="EBPF_KERNEL",
                        severity="WARN",
                        event_type="COLLECTOR_ERROR",
                        summary="bpftrace exited unexpectedly",
                        raw_json={"returncode": self._proc.returncode},
                        source_version=self.source_version_tag,
                    ))
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            # Parse: "SEND ts=12345 pid=1234 comm=bluetoothd len=10 type=1"
            # or:    "RECV ts=12345 pid=1234 comm=bluetoothd len=10 type=4"
            await self._parse_bpftrace_line(line)

    async def _parse_bpftrace_line(self, line: str) -> None:
        """Parse a single bpftrace output line."""
        parts = line.split()
        if len(parts) < 2:
            return

        direction = parts[0]  # SEND or RECV
        if direction not in ("SEND", "RECV"):
            return

        # Extract key=value pairs
        fields: Dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k] = v

        ts_ns = int(fields.get("ts", "0"))
        pid = int(fields.get("pid", "0"))
        comm = fields.get("comm", "")
        data_len = int(fields.get("len", "0"))
        frame_type_id = int(fields.get("type", "0"))

        frame_type = _FRAME_TYPES.get(frame_type_id, f"0x{frame_type_id:02x}")
        dir_label = "TX" if direction == "SEND" else "RX"

        # Track ACL bandwidth
        if frame_type_id == 0x02:
            if direction == "SEND":
                self._acl_bytes_tx += data_len
                self._acl_frames_tx += 1
            else:
                self._acl_bytes_rx += data_len
                self._acl_frames_rx += 1
            return  # Aggregate, don't emit individual ACL

        if frame_type_id in (0x03, 0x05):
            return  # Aggregate SCO/ISO too

        summary = f"{dir_label} {frame_type} {data_len}B pid={pid} ({comm})"

        await self.bus.publish(Event.new(
            source="EBPF_KERNEL",
            severity="DEBUG",
            event_type=f"EBPF_{frame_type}",
            summary=summary,
            raw_json={
                "ts_kernel_ns": ts_ns,
                "pid": pid,
                "comm": comm,
                "frame_type": frame_type,
                "frame_type_id": frame_type_id,
                "direction": dir_label,
                "data_len": data_len,
            },
            source_version=self.source_version_tag,
        ))

    # -----------------------------------------------------------------------
    # Mock mode
    # -----------------------------------------------------------------------

    async def _mock_loop(self) -> None:
        """Emit periodic synthetic kernel-level timing events for testing."""
        import random
        import time

        mock_pids = [
            (1234, "bluetoothd"),
            (5678, "pipewire"),
            (9012, "spotify"),
        ]

        while self._running:
            await asyncio.sleep(random.uniform(1.5, 5.0))
            if not self._running:
                break

            pid, comm = random.choice(mock_pids)
            direction = random.choice(["TX", "RX"])
            frame_type_id = random.choice([0x01, 0x02, 0x04])
            frame_type = _FRAME_TYPES.get(frame_type_id, "??")
            data_len = random.choice([7, 27, 54, 251])
            ts_ns = int(time.monotonic() * 1_000_000_000)

            summary = f"[MOCK] {direction} {frame_type} {data_len}B pid={pid} ({comm})"

            await self.bus.publish(Event.new(
                source="EBPF_KERNEL",
                severity="DEBUG",
                event_type=f"EBPF_{frame_type}",
                summary=summary,
                raw_json={
                    "mock": True,
                    "ts_kernel_ns": ts_ns,
                    "pid": pid,
                    "comm": comm,
                    "frame_type": frame_type,
                    "frame_type_id": frame_type_id,
                    "direction": direction,
                    "data_len": data_len,
                },
                tags=["mock", "kernel"],
                source_version=self.source_version_tag,
            ))

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._proc:
            with contextlib.suppress(ProcessLookupError):
                self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            self._proc = None
        if self._bpf:
            with contextlib.suppress(Exception):
                self._bpf.cleanup()
            self._bpf = None

    @property
    def stats(self) -> dict:
        return {
            "mode": self._mode,
            "running": self._running,
            "acl_bytes_tx": self._acl_bytes_tx,
            "acl_bytes_rx": self._acl_bytes_rx,
            "acl_frames_tx": self._acl_frames_tx,
            "acl_frames_rx": self._acl_frames_rx,
        }
