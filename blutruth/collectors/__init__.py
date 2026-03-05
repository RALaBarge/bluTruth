"""
blutruth.collectors — Diagnostic stream collector plugins

Each collector captures one observability stream and publishes normalized
events to the shared event bus.

Collectors (by stack layer, top to bottom):
  BleSnifferCollector   — BLE air-level packets (nRF Sniffer / btlejack) [MOCK until hardware]
  UbertoothCollector    — Classic BT air-level frames (Ubertooth One) [MOCK until hardware]
  EbpfCollector         — Kernel tracepoints via eBPF [MOCK until implemented]
  KernelDriverCollector — Driver layer: dmesg + ftrace + module state
  SysfsCollector        — Adapter state + rfkill via /sys/class/bluetooth
  UdevCollector         — Bluetooth hotplug events via udevadm monitor
  MgmtApiCollector      — Kernel management socket (btmgmt + sysfs debug)
  HciCollector          — HCI frame capture via btmon
  DbusCollector         — org.bluez D-Bus signal monitor
  DaemonLogCollector    — bluetoothd log capture (journalctl / managed mode)
  PipewireCollector     — Audio pipeline monitor (pw-dump / pactl fallback)
  L2pingCollector       — Active L2CAP RTT monitor via l2ping
  BatteryCollector      — GATT Battery Service via org.bluez.Battery1
"""

from __future__ import annotations

from .base import Collector
from .daemon_log import DaemonLogCollector
from .dbus_monitor import DbusCollector
from .hci import HciCollector

# Robust optional imports — keep startup clean even if a collector has issues
MgmtApiCollector      = None
PipewireCollector     = None
KernelDriverCollector = None
SysfsCollector        = None
UdevCollector         = None
UbertoothCollector    = None
BleSnifferCollector   = None
EbpfCollector         = None
L2pingCollector       = None
BatteryCollector      = None

try:
    from .mgmt_api import MgmtApiCollector          # type: ignore[assignment]
except Exception:
    pass

try:
    from .pipewire import PipewireCollector          # type: ignore[assignment]
except Exception:
    pass

try:
    from .kernel_driver import KernelDriverCollector # type: ignore[assignment]
except Exception:
    pass

try:
    from .sysfs import SysfsCollector               # type: ignore[assignment]
except Exception:
    pass

try:
    from .udev import UdevCollector                 # type: ignore[assignment]
except Exception:
    pass

try:
    from .ubertooth import UbertoothCollector       # type: ignore[assignment]
except Exception:
    pass

try:
    from .ble_sniffer import BleSnifferCollector    # type: ignore[assignment]
except Exception:
    pass

try:
    from .ebpf import EbpfCollector                 # type: ignore[assignment]
except Exception:
    pass

try:
    from .l2ping import L2pingCollector             # type: ignore[assignment]
except Exception:
    pass

try:
    from .battery import BatteryCollector           # type: ignore[assignment]
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
    "SysfsCollector",
    "UdevCollector",
    "UbertoothCollector",
    "BleSnifferCollector",
    "EbpfCollector",
    "L2pingCollector",
    "BatteryCollector",
]
