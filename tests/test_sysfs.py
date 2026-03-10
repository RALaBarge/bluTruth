"""
Tests for blutruth.collectors.sysfs — USB device finding, rfkill, USB severity.

Uses tmp_path to build mock sysfs trees — no system files read.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blutruth.collectors.sysfs import (
    _find_usb_device,
    _rfkill_blocked,
    _rfkill_snapshot,
    _usb_snapshot,
    _USB_STATUS_SEVERITY,
)


# ---------------------------------------------------------------------------
# _USB_STATUS_SEVERITY mapping
# ---------------------------------------------------------------------------

def test_usb_severity_active_is_info():
    assert _USB_STATUS_SEVERITY["active"] == "INFO"


def test_usb_severity_suspended_is_warn():
    assert _USB_STATUS_SEVERITY["suspended"] == "WARN"


def test_usb_severity_error_is_error():
    assert _USB_STATUS_SEVERITY["error"] == "ERROR"


def test_usb_severity_unsupported_is_debug():
    assert _USB_STATUS_SEVERITY["unsupported"] == "DEBUG"


# ---------------------------------------------------------------------------
# _find_usb_device — with mock sysfs tree
# ---------------------------------------------------------------------------

def _make_hci_with_usb(tmp_path: Path) -> tuple[Path, Path]:
    """
    Create a minimal mock sysfs tree where the USB interface is a subdirectory
    of the USB device, so walking up the tree from the interface finds idVendor.

      tmp_path/
        usb_dev/           ← USB device root (has idVendor)
          idVendor
          idProduct
          power/runtime_status
          iface/           ← USB interface (no idVendor here)
        hci0/
          device -> usb_dev/iface  (symlink)
    """
    # USB device dir (has idVendor)
    usb_dev = tmp_path / "usb_dev"
    usb_dev.mkdir()
    (usb_dev / "idVendor").write_text("0bda")
    (usb_dev / "idProduct").write_text("b00a")
    (usb_dev / "manufacturer").write_text("Realtek")
    (usb_dev / "product").write_text("Bluetooth Adapter")
    (usb_dev / "bMaxPower").write_text("500mA")
    power_dir = usb_dev / "power"
    power_dir.mkdir()
    (power_dir / "runtime_status").write_text("active")
    (power_dir / "control").write_text("auto")

    # USB interface is a child of the device dir (mirrors real sysfs layout)
    usb_iface = usb_dev / "iface"
    usb_iface.mkdir()

    # hci0 with device symlink → interface
    hci_path = tmp_path / "hci0"
    hci_path.mkdir()
    (hci_path / "device").symlink_to(usb_iface.resolve())

    return hci_path, usb_dev


def test_find_usb_device_finds_parent_with_idvendor(tmp_path: Path):
    hci_path, usb_dev = _make_hci_with_usb(tmp_path)
    found = _find_usb_device(hci_path)
    assert found is not None
    assert found == usb_dev.resolve()


def test_find_usb_device_reads_idvendor(tmp_path: Path):
    hci_path, usb_dev = _make_hci_with_usb(tmp_path)
    found = _find_usb_device(hci_path)
    assert (found / "idVendor").read_text() == "0bda"


def test_find_usb_device_no_device_symlink(tmp_path: Path):
    hci_path = tmp_path / "hci0"
    hci_path.mkdir()
    # No 'device' symlink
    assert _find_usb_device(hci_path) is None


def test_find_usb_device_uart_adapter_returns_none(tmp_path: Path):
    """Non-USB adapter: device symlink exists but no idVendor up the tree."""
    hci_path = tmp_path / "hci0"
    hci_path.mkdir()

    # Simulate a UART adapter's sysfs node (no idVendor anywhere)
    uart_path = tmp_path / "devices" / "uart_bt"
    uart_path.mkdir(parents=True)
    (uart_path / "type").write_text("uart")
    (hci_path / "device").symlink_to(uart_path.resolve())

    assert _find_usb_device(hci_path) is None


# ---------------------------------------------------------------------------
# _usb_snapshot — reads USB sysfs files
# ---------------------------------------------------------------------------

def test_usb_snapshot_reads_all_files(tmp_path: Path):
    _, usb_dev = _make_hci_with_usb(tmp_path)
    snap = _usb_snapshot(usb_dev)

    assert snap.get("idVendor") == "0bda"
    assert snap.get("idProduct") == "b00a"
    assert snap.get("manufacturer") == "Realtek"
    assert snap.get("bMaxPower") == "500mA"
    assert snap.get("power_runtime_status") == "active"
    assert snap.get("power_control") == "auto"


def test_usb_snapshot_missing_files_return_none(tmp_path: Path):
    bare_dir = tmp_path / "usb_bare"
    bare_dir.mkdir()
    snap = _usb_snapshot(bare_dir)
    # All keys present but values are None for missing files
    assert snap.get("idVendor") is None
    assert snap.get("power_runtime_status") is None


# ---------------------------------------------------------------------------
# _rfkill_blocked
# ---------------------------------------------------------------------------

def test_rfkill_blocked_soft_block():
    nodes = [{"node": "rfkill0", "soft": "1", "hard": "0"}]
    assert _rfkill_blocked(nodes) is True


def test_rfkill_blocked_hard_block():
    nodes = [{"node": "rfkill0", "soft": "0", "hard": "1"}]
    assert _rfkill_blocked(nodes) is True


def test_rfkill_blocked_unblocked():
    nodes = [{"node": "rfkill0", "soft": "0", "hard": "0"}]
    assert _rfkill_blocked(nodes) is False


def test_rfkill_blocked_empty_list():
    assert _rfkill_blocked([]) is False


def test_rfkill_blocked_any_node_triggers():
    nodes = [
        {"node": "rfkill0", "soft": "0", "hard": "0"},
        {"node": "rfkill1", "soft": "1", "hard": "0"},
    ]
    assert _rfkill_blocked(nodes) is True
