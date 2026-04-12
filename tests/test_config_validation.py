"""
Tests for config validation.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from blutruth.config import Config


def _make_config(tmp_path, overrides: dict) -> Config:
    """Create a Config with custom overrides written to a temp YAML file."""
    cfg_path = tmp_path / "test_config.yaml"
    cfg_path.write_text(yaml.safe_dump(overrides, sort_keys=False))
    cfg = Config(cfg_path)
    cfg.load()
    return cfg


def test_valid_config_no_warnings(tmp_path):
    cfg = _make_config(tmp_path, {})
    warnings = cfg.validate()
    assert warnings == []


def test_negative_time_window(tmp_path):
    cfg = _make_config(tmp_path, {"correlation": {"time_window_ms": -10}})
    warnings = cfg.validate()
    assert any("time_window_ms" in w for w in warnings)


def test_zero_batch_interval(tmp_path):
    cfg = _make_config(tmp_path, {"correlation": {"batch_interval_s": 0}})
    warnings = cfg.validate()
    assert any("batch_interval_s" in w for w in warnings)


def test_invalid_port(tmp_path):
    cfg = _make_config(tmp_path, {"listen": {"port": 99999}})
    warnings = cfg.validate()
    assert any("port" in w for w in warnings)


def test_negative_retention_days(tmp_path):
    cfg = _make_config(tmp_path, {"storage": {"retention_days": -5}})
    warnings = cfg.validate()
    assert any("retention_days" in w for w in warnings)


def test_zero_retention_days_is_valid(tmp_path):
    cfg = _make_config(tmp_path, {"storage": {"retention_days": 0}})
    warnings = cfg.validate()
    assert not any("retention_days" in w for w in warnings)


def test_negative_collector_poll(tmp_path):
    cfg = _make_config(tmp_path, {
        "collectors": {"sysfs": {"poll_s": -1}},
    })
    warnings = cfg.validate()
    assert any("poll_s" in w for w in warnings)


def test_string_port_rejected(tmp_path):
    cfg = _make_config(tmp_path, {"listen": {"port": "not_a_port"}})
    warnings = cfg.validate()
    assert any("port" in w for w in warnings)


def test_negative_size_warn(tmp_path):
    cfg = _make_config(tmp_path, {"storage": {"size_warn_mb": -100}})
    warnings = cfg.validate()
    assert any("size_warn_mb" in w for w in warnings)
