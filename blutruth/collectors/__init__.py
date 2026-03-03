"""
blutruth.collectors — Diagnostic stream collector plugins

Each collector captures one observability stream and publishes normalized
events to the shared event bus.

Collectors:
  HCI       — btmon HCI frame capture
  D-Bus     — org.bluez signal monitor
  Daemon    — bluetoothd log capture (journalctl / managed mode)
  Mgmt API  — kernel management socket (btmgmt + sysfs)
  PipeWire  — audio pipeline monitor (pw-dump / pactl fallback)
  Kernel    — driver layer (dmesg + ftrace + module state)
"""

from __future__ import annotations

from .base import Collector
from .daemon_log import DaemonLogCollector
from .dbus_monitor import DbusCollector
from .hci import HciCollector

# Optional collectors: keep import-time robust even if a collector grows extra deps
# later or is not supported on the current host.
MgmtApiCollector = None
PipewireCollector = None
KernelDriverCollector = None

try:
    from .mgmt_api import MgmtApiCollector  # type: ignore[assignment]
except Exception:
    pass

try:
    from .pipewire import PipewireCollector  # type: ignore[assignment]
except Exception:
    pass

try:
    from .kernel_driver import KernelDriverCollector  # type: ignore[assignment]
except Exception:
    pass

__all__ = [
    "Collector",
    "HciCollector",
    "DbusCollector",
    "DaemonLogCollector",
    "MgmtApiCollector",
    "PipewireCollector",
    "KernelDriverCollector",
]
