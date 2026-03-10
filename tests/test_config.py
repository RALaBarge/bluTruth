"""
Tests for blutruth.config — Config.get() dot-path traversal and defaults.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blutruth.config import Config, DEFAULT_CONFIG, _deep_merge


# ---------------------------------------------------------------------------
# Config.get() — uses DEFAULT_CONFIG pre-loaded without file I/O
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg():
    return Config(Path("/tmp/_blutruth_test_nonexistent_config.yaml"))


def test_config_get_top_level(cfg):
    host = cfg.get("listen", "host")
    assert host == "127.0.0.1"


def test_config_get_nested(cfg):
    enabled = cfg.get("collectors", "hci", "enabled")
    assert enabled is True


def test_config_get_numeric(cfg):
    port = cfg.get("listen", "port")
    assert port == 8484


def test_config_get_float(cfg):
    poll_s = cfg.get("collectors", "mgmt", "sysfs_poll_s")
    assert isinstance(poll_s, float)
    assert poll_s > 0


def test_config_get_rssi_warn_default(cfg):
    warn = cfg.get("collectors", "hci", "rssi_warn_dbm")
    assert warn == -75


def test_config_get_rssi_error_default(cfg):
    error = cfg.get("collectors", "hci", "rssi_error_dbm")
    assert error == -85


def test_config_get_missing_key_returns_none(cfg):
    result = cfg.get("collectors", "hci", "nonexistent_key")
    assert result is None


def test_config_get_missing_key_with_default(cfg):
    result = cfg.get("collectors", "hci", "nonexistent_key", default=42)
    assert result == 42


def test_config_get_missing_top_level_with_default(cfg):
    result = cfg.get("no_such_section", default="fallback")
    assert result == "fallback"


def test_config_get_missing_middle_key_with_default(cfg):
    result = cfg.get("collectors", "nonexistent_collector", "enabled", default=False)
    assert result is False


def test_config_get_storage_path(cfg):
    path = cfg.get("storage", "sqlite_path")
    assert path is not None
    assert "blutruth" in path
    assert "events.db" in path


def test_config_get_retention_days(cfg):
    days = cfg.get("storage", "retention_days")
    assert days == 30


def test_config_get_correlation_window(cfg):
    window = cfg.get("correlation", "time_window_ms")
    assert window == 100


def test_config_get_all_collectors_enabled_by_default(cfg):
    # All collectors except advanced_bluetoothd should be enabled by default
    expected_enabled = [
        "hci", "dbus", "journalctl", "mgmt", "pipewire",
        "kernel_trace", "sysfs", "udev", "ubertooth", "ble_sniffer",
        "ebpf", "l2ping", "battery",
    ]
    for name in expected_enabled:
        enabled = cfg.get("collectors", name, "enabled")
        assert enabled is True, f"Expected {name} to be enabled by default"


def test_config_advanced_bluetoothd_disabled_by_default(cfg):
    enabled = cfg.get("collectors", "advanced_bluetoothd", "enabled")
    assert enabled is False


# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------

def test_deep_merge_overrides_leaf():
    base = {"a": {"b": 1, "c": 2}}
    override = {"a": {"b": 99}}
    result = _deep_merge(base, override)
    assert result["a"]["b"] == 99
    assert result["a"]["c"] == 2  # untouched


def test_deep_merge_adds_new_key():
    base = {"a": {"b": 1}}
    override = {"a": {"c": 3}}
    result = _deep_merge(base, override)
    assert result["a"]["b"] == 1
    assert result["a"]["c"] == 3


def test_deep_merge_does_not_mutate_base():
    base = {"a": {"b": 1}}
    override = {"a": {"b": 99}}
    _deep_merge(base, override)
    assert base["a"]["b"] == 1  # original unchanged


def test_deep_merge_replaces_non_dict_with_value():
    base = {"a": {"b": {"nested": 1}}}
    override = {"a": {"b": "string"}}  # override dict with scalar
    result = _deep_merge(base, override)
    assert result["a"]["b"] == "string"


def test_deep_merge_empty_override():
    base = {"a": 1, "b": 2}
    result = _deep_merge(base, {})
    assert result == base


def test_deep_merge_empty_base():
    override = {"a": 1}
    result = _deep_merge({}, override)
    assert result == override
