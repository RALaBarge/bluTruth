"""
blutruth.config — YAML configuration with hot reload

Config is polled for changes every 1s. On change, only affected collectors
restart; the event bus, storage, and correlation engine continue uninterrupted.

Fields that are PARSED but not yet implemented (reserved for future milestones):
  storage.retention_days      — Tier 2: periodic DELETE of old events; DB grows forever today
  correlation.rules_path      — Tier 3: YAML semantic rule-pack; only time-window grouping today

Fields that are fully implemented:
  listen.*                    — host/port for 'serve' command
  storage.sqlite_path / jsonl_path
  collectors.*                — per-collector enabled + options, hot-reloaded
  correlation.time_window_ms / batch_interval_s
  ui.max_rows                 — JS MAX_EVENTS cap in the live UI
  ui.fallback_refresh_seconds — noscript meta-refresh interval
  ui.live_mode_default        — whether SSE auto-connects on page load
  security.local_only         — warns when binding non-loopback with local_only=true

FUTURE: Replace polling with inotify/watchdog for efficiency.
FUTURE (Rust port): serde_yaml with notify crate for file watching.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "listen": {
        "host": "127.0.0.1",
        "port": 8484,
    },
    "storage": {
        "sqlite_path": "~/.blutruth/events.db",
        "jsonl_path": "~/.blutruth/events.jsonl",
        "retention_days": 30,
    },
    "collectors": {
        "hci": {
            "enabled": True,
            "rssi_warn_dbm": -75,   # WARN when active-connection RSSI drops below this
            "rssi_error_dbm": -85,  # ERROR when active-connection RSSI drops below this
        },
        "dbus": {
            "enabled": True,
        },
        "journalctl": {
            "enabled": True,
            "unit": "bluetooth",
            "format": "json",
        },
        "mgmt": {
            "enabled": True,    # requires root — skipped gracefully if non-root
            "sysfs_poll_s": 5.0,
        },
        "pipewire": {
            "enabled": True,    # no root required
        },
        "kernel_trace": {
            "enabled": True,    # requires root + debugfs — skipped gracefully if non-root
            "ftrace": False,    # opt-in: enables bluetooth tracepoints in tracefs
            "module_poll_s": 10.0,
        },
        "advanced_bluetoothd": {
            "enabled": False,   # managed debug daemon, opt-in only — requires deliberate setup
            "bluetoothd_path": "/usr/lib/bluetooth/bluetoothd",
        },
        "sysfs": {
            "enabled": True,    # no root, no deps — always on
            "poll_s": 2.0,
        },
        "udev": {
            "enabled": True,    # no root, no deps — always on
        },
        "ubertooth": {
            "enabled": True,    # no hardware → WARN + no-op; set mock_data=True to test
            "mock_data": False,
        },
        "ble_sniffer": {
            "enabled": True,    # no hardware → WARN + no-op; set mock_data=True to test
            "mock_data": False,
        },
        "ebpf": {
            "enabled": True,    # requires root + CAP_BPF — skipped gracefully if non-root
            "mock_data": False,
        },
        "l2ping": {
            "enabled": True,    # no root — active RTT measurement
            "poll_interval_s": 30,
            "ping_count": 5,
            "ping_timeout_s": 2,
            "rtt_warn_ms": 50,
            "rtt_error_ms": 150,
        },
        "battery": {
            "enabled": True,    # no root — polls org.bluez.Battery1 via D-Bus
            "poll_interval_s": 60,
            "low_battery_warn": 20,
            "low_battery_error": 10,
        },
    },
    "correlation": {
        "time_window_ms": 100,
        "rules_path": "~/.blutruth/rules/",
        "batch_interval_s": 2.0,
    },
    "ui": {
        "live_mode_default": True,
        "fallback_refresh_seconds": 2,
        "max_rows": 500,
    },
    "security": {
        "local_only": True,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override into base, returning a new dict."""
    result = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _expand_paths(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Expand ~ in path-valued config fields."""
    for section_key in ("storage",):
        section = cfg.get(section_key, {})
        for k, v in section.items():
            if isinstance(v, str) and "~" in v:
                section[k] = str(Path(v).expanduser())
    rules = cfg.get("correlation", {}).get("rules_path")
    if isinstance(rules, str) and "~" in rules:
        cfg["correlation"]["rules_path"] = str(Path(rules).expanduser())
    return cfg


class Config:
    """
    YAML config with change detection for hot reload.

    Usage:
        cfg = Config(Path("~/.blutruth/config.yaml"))
        cfg.load()           # initial load (creates default if missing)
        if cfg.load():       # subsequent calls return True if changed
            # restart affected collectors
    """

    def __init__(self, path: Path):
        self.path = path.expanduser()
        self._mtime: float = 0.0
        self.data: Dict[str, Any] = _expand_paths(copy.deepcopy(DEFAULT_CONFIG))
        self._prev_collectors: Optional[Dict[str, Any]] = None

    def load(self) -> bool:
        """Load config from disk. Returns True if config changed."""
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False, default_flow_style=False)
            )

        mtime = self.path.stat().st_mtime
        if mtime <= self._mtime:
            return False

        raw = yaml.safe_load(self.path.read_text()) or {}
        self._prev_collectors = copy.deepcopy(self.data.get("collectors"))
        self.data = _expand_paths(_deep_merge(DEFAULT_CONFIG, raw))
        self._mtime = mtime
        return True

    def collectors_changed(self) -> bool:
        """Check if collector config differs from previous load."""
        if self._prev_collectors is None:
            return False
        return self._prev_collectors != self.data.get("collectors")

    def get(self, *keys: str, default: Any = None) -> Any:
        """Dot-path access: cfg.get("collectors", "hci", "enabled")"""
        node = self.data
        for k in keys:
            if isinstance(node, dict):
                node = node.get(k)
            else:
                return default
            if node is None:
                return default
        return node
