"""
Tests for blutruth.collectors.dbus_monitor — pure helper functions.
"""
from __future__ import annotations

import pytest

from blutruth.collectors.dbus_monitor import (
    _path_to_addr,
    _decode_a2dp_codec,
    _classify_property_change,
    _safe_serialize,
    _format_changed_props,
)


# ---------------------------------------------------------------------------
# _path_to_addr
# ---------------------------------------------------------------------------

def test_path_to_addr_device_path():
    adapter, addr = _path_to_addr("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
    assert adapter == "hci0"
    assert addr == "AA:BB:CC:DD:EE:FF"


def test_path_to_addr_lowercase_device():
    adapter, addr = _path_to_addr("/org/bluez/hci0/dev_aa_bb_cc_dd_ee_ff")
    assert addr == "AA:BB:CC:DD:EE:FF"


def test_path_to_addr_hci1():
    adapter, addr = _path_to_addr("/org/bluez/hci1/dev_11_22_33_44_55_66")
    assert adapter == "hci1"
    assert addr == "11:22:33:44:55:66"


def test_path_to_addr_adapter_only_path():
    adapter, addr = _path_to_addr("/org/bluez/hci0")
    assert adapter == "hci0"
    assert addr is None


def test_path_to_addr_adapter_media_path():
    # Path with sub-object (e.g. MediaTransport)
    adapter, addr = _path_to_addr("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/fd1")
    assert adapter == "hci0"
    assert addr == "AA:BB:CC:DD:EE:FF"


def test_path_to_addr_unrelated_path():
    adapter, addr = _path_to_addr("/org/freedesktop/NetworkManager")
    assert adapter is None
    assert addr is None


def test_path_to_addr_empty_string():
    adapter, addr = _path_to_addr("")
    assert adapter is None
    assert addr is None


def test_path_to_addr_none():
    adapter, addr = _path_to_addr(None)
    assert adapter is None
    assert addr is None


# ---------------------------------------------------------------------------
# _decode_a2dp_codec
# ---------------------------------------------------------------------------

def test_decode_sbc():
    assert _decode_a2dp_codec(0x00) == "SBC"


def test_decode_mp3():
    assert _decode_a2dp_codec(0x01) == "MP3"


def test_decode_aac():
    assert _decode_a2dp_codec(0x02) == "AAC"


def test_decode_atrac():
    assert _decode_a2dp_codec(0x03) == "ATRAC"


def test_decode_vendor():
    assert "Vendor" in _decode_a2dp_codec(0xFF)


def test_decode_unknown_byte():
    result = _decode_a2dp_codec(0x42)
    assert result is not None
    assert "Unknown" in result or "0x42" in result


def test_decode_string_input():
    # Should handle string "0" → SBC
    assert _decode_a2dp_codec("0") == "SBC"


def test_decode_invalid_input():
    assert _decode_a2dp_codec(None) is None
    assert _decode_a2dp_codec("not-a-number") is None


# ---------------------------------------------------------------------------
# _classify_property_change
# ---------------------------------------------------------------------------

def test_classify_connected_true():
    severity, stage = _classify_property_change("org.bluez.Device1", {"Connected": True})
    assert severity == "INFO"
    assert stage == "CONNECTION"


def test_classify_connected_false():
    severity, stage = _classify_property_change("org.bluez.Device1", {"Connected": False})
    assert severity == "WARN"
    assert stage == "CONNECTION"


def test_classify_services_resolved():
    severity, stage = _classify_property_change("org.bluez.Device1", {"ServicesResolved": True})
    assert severity == "INFO"
    assert stage == "HANDSHAKE"


def test_classify_paired():
    severity, stage = _classify_property_change("org.bluez.Device1", {"Paired": True})
    assert severity == "INFO"
    assert stage == "HANDSHAKE"


def test_classify_rssi():
    severity, stage = _classify_property_change("org.bluez.Device1", {"RSSI": -60})
    assert severity == "DEBUG"
    assert stage == "DISCOVERY"


def test_classify_adapter_powered():
    severity, stage = _classify_property_change("org.bluez.Adapter1", {"Powered": False})
    assert severity == "WARN"


def test_classify_adapter_discovering():
    severity, stage = _classify_property_change("org.bluez.Adapter1", {"Discovering": True})
    assert severity == "INFO"
    assert stage == "DISCOVERY"


def test_classify_media_transport_state():
    severity, stage = _classify_property_change("org.bluez.MediaTransport1", {"State": "active"})
    assert severity == "INFO"
    assert stage == "AUDIO"


def test_classify_media_transport_codec():
    severity, stage = _classify_property_change("org.bluez.MediaTransport1", {"Codec": 0x00})
    assert severity == "INFO"
    assert stage == "AUDIO"


def test_classify_unknown_interface():
    severity, stage = _classify_property_change("org.some.Other", {"Foo": "bar"})
    assert severity == "INFO"


# ---------------------------------------------------------------------------
# _safe_serialize
# ---------------------------------------------------------------------------

def test_safe_serialize_primitives():
    assert _safe_serialize(42) == 42
    assert _safe_serialize("hello") == "hello"
    assert _safe_serialize(3.14) == 3.14
    assert _safe_serialize(True) is True
    assert _safe_serialize(None) is None


def test_safe_serialize_bytes_to_hex():
    result = _safe_serialize(b"\xde\xad\xbe\xef")
    assert result == "deadbeef"


def test_safe_serialize_list():
    result = _safe_serialize([1, "two", b"\xff"])
    assert result == [1, "two", "ff"]


def test_safe_serialize_dict():
    result = _safe_serialize({"a": 1, "b": b"\x00"})
    assert result == {"a": 1, "b": "00"}


def test_safe_serialize_nested():
    result = _safe_serialize({"outer": {"inner": [b"\x01", 2]}})
    assert result == {"outer": {"inner": ["01", 2]}}


def test_safe_serialize_variant_like():
    """Objects with .value attribute (dbus-next Variants)."""
    class FakeVariant:
        def __init__(self, val):
            self.value = val

    result = _safe_serialize(FakeVariant(42))
    assert result == 42


def test_safe_serialize_nested_variant():
    class FakeVariant:
        def __init__(self, val):
            self.value = val

    result = _safe_serialize({"codec": FakeVariant(0x02)})
    assert result == {"codec": 2}


def test_safe_serialize_unknown_type_falls_back_to_str():
    class Weird:
        def __str__(self):
            return "weird_value"

    result = _safe_serialize(Weird())
    assert result == "weird_value"


# ---------------------------------------------------------------------------
# _format_changed_props
# ---------------------------------------------------------------------------

def test_format_changed_props_basic():
    result = _format_changed_props({"Connected": True})
    assert "Connected" in result
    assert "True" in result


def test_format_changed_props_caps_at_five():
    props = {f"Key{i}": i for i in range(10)}
    result = _format_changed_props(props)
    # Should not exceed 5 entries
    assert result.count(":") <= 5


def test_format_changed_props_variant_unwrapped():
    class FakeVariant:
        def __init__(self, val):
            self.value = val

    result = _format_changed_props({"State": FakeVariant("active")})
    assert "active" in result
