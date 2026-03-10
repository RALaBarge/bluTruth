"""
Tests for blutruth.collectors.hci — regex extraction and _emit_event logic.

Tests pure regex patterns directly (no mock needed) plus _emit_event
end-to-end for the handle→addr mapping, KNOB detection, and RSSI escalation.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# Import the regex patterns directly from the module
from blutruth.collectors.hci import (
    _RSSI_RE,
    _REASON_RE,
    _HANDLE_RE,
    _KEY_SIZE_RE,
    _IO_CAP_RE,
    _ADDR_RE,
    HciCollector,
)
from blutruth.config import Config
from tests.conftest import MockBus


def _make_collector() -> tuple[HciCollector, MockBus]:
    bus = MockBus()
    cfg = Config(Path("/tmp/_blutruth_test_nonexistent.yaml"))
    collector = HciCollector(bus, cfg)
    return collector, bus


# ---------------------------------------------------------------------------
# Regex: _RSSI_RE
# ---------------------------------------------------------------------------

def test_rssi_re_matches_standard_format():
    m = _RSSI_RE.search("        RSSI: -60 dBm (0xc4)")
    assert m is not None
    assert m.group(1) == "-60"


def test_rssi_re_matches_positive_rssi():
    m = _RSSI_RE.search("RSSI: 5 dBm")
    assert m is not None
    assert m.group(1) == "5"


def test_rssi_re_matches_zero():
    m = _RSSI_RE.search("RSSI: 0 dBm")
    assert m is not None
    assert m.group(1) == "0"


def test_rssi_re_case_insensitive():
    m = _RSSI_RE.search("rssi: -70 dbm")
    assert m is not None
    assert m.group(1) == "-70"


def test_rssi_re_no_match_without_dbm():
    assert _RSSI_RE.search("RSSI: -60") is None


# ---------------------------------------------------------------------------
# Regex: _REASON_RE
# ---------------------------------------------------------------------------

def test_reason_re_connection_timeout():
    m = _REASON_RE.search("        Reason: Connection Timeout (0x08)")
    assert m is not None
    assert m.group(1) == "Connection Timeout"
    assert m.group(2) == "08"


def test_reason_re_lmp_timeout():
    m = _REASON_RE.search("        Reason: LMP Response Timeout / LL Response Timeout (0x22)")
    assert m is not None
    assert m.group(2) == "22"


def test_reason_re_remote_user_terminated():
    m = _REASON_RE.search("        Reason: Remote User Terminated Connection (0x13)")
    assert m is not None
    assert m.group(1) == "Remote User Terminated Connection"
    assert int(m.group(2), 16) == 0x13


def test_reason_re_case_insensitive():
    m = _REASON_RE.search("reason: Connection Timeout (0x08)")
    assert m is not None


def test_reason_re_no_match_without_hex():
    assert _REASON_RE.search("Reason: Connection Timeout") is None


# ---------------------------------------------------------------------------
# Regex: _HANDLE_RE
# ---------------------------------------------------------------------------

def test_handle_re_matches_standard():
    m = _HANDLE_RE.search("        Handle: 256")
    assert m is not None
    assert m.group(1) == "256"


def test_handle_re_matches_zero():
    m = _HANDLE_RE.search("Handle: 0")
    assert m is not None
    assert m.group(1) == "0"


def test_handle_re_requires_word_boundary():
    # "Handle" must be at word start — "XHandle: 5" should not match
    assert _HANDLE_RE.search("XHandle: 5") is None


def test_handle_re_no_match_without_colon():
    assert _HANDLE_RE.search("Handle 256") is None


# ---------------------------------------------------------------------------
# Regex: _KEY_SIZE_RE
# ---------------------------------------------------------------------------

def test_key_size_re_matches_standard():
    m = _KEY_SIZE_RE.search("        Key size: 16")
    assert m is not None
    assert m.group(1) == "16"


def test_key_size_re_matches_lowercase():
    m = _KEY_SIZE_RE.search("key size: 7")
    assert m is not None
    assert m.group(1) == "7"


def test_key_size_re_matches_mixed_case():
    m = _KEY_SIZE_RE.search("Key Size: 10")
    assert m is not None
    assert m.group(1) == "10"


def test_key_size_re_matches_low_value():
    m = _KEY_SIZE_RE.search("Key size: 1")
    assert m is not None
    assert int(m.group(1)) == 1


def test_key_size_re_no_match_without_size():
    assert _KEY_SIZE_RE.search("Keysize: 16") is None


# ---------------------------------------------------------------------------
# Regex: _IO_CAP_RE
# ---------------------------------------------------------------------------

def test_io_cap_re_matches_display_yes_no():
    text = "        Capability: DisplayYesNo (0x01)"
    m = _IO_CAP_RE.search(text)
    assert m is not None
    assert m.group(1) == "DisplayYesNo"
    assert m.group(2) == "01"


def test_io_cap_re_matches_no_input_no_output():
    text = "        Capability: NoInputNoOutput (0x03)"
    m = _IO_CAP_RE.search(text)
    assert m is not None
    assert m.group(1) == "NoInputNoOutput"


def test_io_cap_re_matches_keyboard_only():
    text = "        Capability: KeyboardOnly (0x02)"
    m = _IO_CAP_RE.search(text)
    assert m is not None
    assert m.group(1) == "KeyboardOnly"


def test_io_cap_re_no_match_without_indent():
    # Must have leading whitespace
    text = "Capability: DisplayYesNo (0x01)"
    assert _IO_CAP_RE.search(text) is None


def test_io_cap_re_multiline():
    text = (
        "> HCI Event: IO Capability Response (0x32) [hci0]\n"
        "        Address: AA:BB:CC:DD:EE:FF\n"
        "        Capability: KeyboardDisplay (0x04)\n"
    )
    m = _IO_CAP_RE.search(text)
    assert m is not None
    assert m.group(1) == "KeyboardDisplay"


# ---------------------------------------------------------------------------
# Regex: _ADDR_RE
# ---------------------------------------------------------------------------

def test_addr_re_matches_standard_mac():
    m = _ADDR_RE.search("Address: AA:BB:CC:DD:EE:FF (Unknown)")
    assert m is not None
    assert m.group(1) == "AA:BB:CC:DD:EE:FF"


def test_addr_re_matches_lowercase_mac():
    m = _ADDR_RE.search("bd_addr: aa:bb:cc:dd:ee:ff")
    assert m is not None


def test_addr_re_no_match_on_short_addr():
    assert _ADDR_RE.search("AA:BB:CC:DD:EE") is None


# ---------------------------------------------------------------------------
# HciCollector._emit_event: handle→addr mapping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_handle_addr_populated_on_connection_complete():
    collector, bus = _make_collector()

    # Simulate a Connection Complete event with a known address
    block = [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Status: Success (0x00)",
        "        Handle: 256",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
        "        Link Type: ACL (0x01)",
    ]
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", block)

    assert collector._handle_addr.get(256) == "AA:BB:CC:DD:EE:FF"


@pytest.mark.asyncio
async def test_handle_addr_resolved_on_handle_only_event():
    collector, bus = _make_collector()

    # First: populate the mapping via Connection Complete
    conn_block = [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Status: Success (0x00)",
        "        Handle: 256",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
    ]
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", conn_block)
    bus.clear()

    # Second: Disconnection Complete has Handle but no Address
    disc_block = [
        "> HCI Event: Disconnection Complete (0x05) [hci0]",
        "        Status: Success (0x00)",
        "        Handle: 256",
        "        Reason: Connection Timeout (0x08)",
    ]
    await collector._emit_event(">", "HCI Event: Disconnection Complete (0x05)", disc_block)

    assert len(bus.events) == 1
    ev = bus.events[0]
    assert ev.device_addr == "AA:BB:CC:DD:EE:FF"


@pytest.mark.asyncio
async def test_handle_addr_evicted_on_disconnection():
    collector, bus = _make_collector()

    # Populate mapping
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Handle: 256",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
    ])
    assert 256 in collector._handle_addr

    # Disconnection should evict
    await collector._emit_event(">", "HCI Event: Disconnection Complete (0x05)", [
        "> HCI Event: Disconnection Complete (0x05) [hci0]",
        "        Handle: 256",
        "        Reason: Connection Timeout (0x08)",
    ])
    assert 256 not in collector._handle_addr


@pytest.mark.asyncio
async def test_handle_addr_independent_per_handle():
    collector, bus = _make_collector()

    # Two different connections
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Handle: 100",
        "        Address: 11:22:33:44:55:66 (Unknown)",
    ])
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Handle: 200",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
    ])

    assert collector._handle_addr.get(100) == "11:22:33:44:55:66"
    assert collector._handle_addr.get(200) == "AA:BB:CC:DD:EE:FF"

    # Disconnect handle 100 — handle 200 should remain
    await collector._emit_event(">", "HCI Event: Disconnection Complete (0x05)", [
        "> HCI Event: Disconnection Complete (0x05) [hci0]",
        "        Handle: 100",
        "        Reason: Remote User Terminated Connection (0x13)",
    ])
    assert 100 not in collector._handle_addr
    assert 200 in collector._handle_addr


# ---------------------------------------------------------------------------
# HciCollector._emit_event: KNOB risk detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_knob_no_risk_for_normal_key_size():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Command Complete (0x0e) [hci0]",
        "        Command Opcode: Read Encryption Key Size (0x1408)",
        "        Status: Success (0x00)",
        "        Handle: 10",
        "        Key size: 16",
    ]
    await collector._emit_event(">", "HCI Event: Command Complete (0x0e)", block)

    ev = bus.last()
    assert ev.raw_json.get("key_size") == 16
    assert "knob_risk" not in ev.raw_json


@pytest.mark.asyncio
async def test_knob_possible_for_reduced_key_size():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Command Complete (0x0e) [hci0]",
        "        Command Opcode: Read Encryption Key Size (0x1408)",
        "        Status: Success (0x00)",
        "        Handle: 10",
        "        Key size: 10",
    ]
    await collector._emit_event(">", "HCI Event: Command Complete (0x0e)", block)

    ev = bus.last()
    assert ev.raw_json.get("key_size") == 10
    assert ev.raw_json.get("knob_risk") == "POSSIBLE"


@pytest.mark.asyncio
async def test_knob_high_for_critically_low_key_size():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Command Complete (0x0e) [hci0]",
        "        Command Opcode: Read Encryption Key Size (0x1408)",
        "        Status: Success (0x00)",
        "        Handle: 10",
        "        Key size: 1",
    ]
    await collector._emit_event(">", "HCI Event: Command Complete (0x0e)", block)

    ev = bus.last()
    assert ev.raw_json.get("key_size") == 1
    assert ev.raw_json.get("knob_risk") == "HIGH"
    assert ev.severity == "ERROR"


@pytest.mark.asyncio
async def test_knob_high_boundary_at_six():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Command Complete (0x0e) [hci0]",
        "        Key size: 6",
    ]
    await collector._emit_event(">", "HCI Event: Command Complete (0x0e)", block)

    ev = bus.last()
    assert ev.raw_json.get("knob_risk") == "HIGH"


@pytest.mark.asyncio
async def test_knob_possible_boundary_at_seven():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Command Complete (0x0e) [hci0]",
        "        Key size: 7",
    ]
    await collector._emit_event(">", "HCI Event: Command Complete (0x0e)", block)

    ev = bus.last()
    assert ev.raw_json.get("knob_risk") == "POSSIBLE"


# ---------------------------------------------------------------------------
# HciCollector._emit_event: RSSI extraction and severity escalation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rssi_extracted_into_raw_json():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Read RSSI Return [hci0]",
        "        Handle: 256",
        "        RSSI: -60 dBm (0xc4)",
    ]
    await collector._emit_event(">", "HCI Event: Read RSSI Return", block)

    ev = bus.last()
    assert ev.raw_json.get("rssi_dbm") == -60


@pytest.mark.asyncio
async def test_rssi_escalates_to_warn_below_threshold():
    collector, bus = _make_collector()
    # Default rssi_warn_dbm = -75

    block = [
        "> HCI Event: Read RSSI Return [hci0]",
        "        Handle: 256",
        "        RSSI: -80 dBm",
    ]
    await collector._emit_event(">", "HCI Event: Read RSSI Return", block)

    ev = bus.last()
    assert ev.severity in ("WARN", "ERROR")


@pytest.mark.asyncio
async def test_rssi_escalates_to_error_below_error_threshold():
    collector, bus = _make_collector()
    # Default rssi_error_dbm = -85

    block = [
        "> HCI Event: Read RSSI Return [hci0]",
        "        Handle: 256",
        "        RSSI: -90 dBm",
    ]
    await collector._emit_event(">", "HCI Event: Read RSSI Return", block)

    ev = bus.last()
    assert ev.severity == "ERROR"


@pytest.mark.asyncio
async def test_rssi_no_escalation_for_discovery_events():
    collector, bus = _make_collector()
    # Advertising RSSI (not Read RSSI) — should not escalate severity

    block = [
        "> HCI Event: LE Meta Event (0x3e) [hci0]",
        "        LE Advertising Report",
        "        Address: AA:BB:CC:DD:EE:FF",
        "        RSSI: -95 dBm",
    ]
    await collector._emit_event(">", "HCI Event: LE Meta Event (0x3e)", block)

    ev = bus.last()
    # rssi_dbm should still be extracted
    assert ev.raw_json.get("rssi_dbm") == -95
    # but severity should NOT be ERROR — advertising RSSI being low is normal
    assert ev.severity != "ERROR"


# ---------------------------------------------------------------------------
# HciCollector._emit_event: IO capability extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_io_capability_extracted():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: IO Capability Response (0x32) [hci0]",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
        "        Capability: DisplayYesNo (0x01)",
        "        OOB data: Authentication data not present (0x00)",
    ]
    await collector._emit_event(">", "HCI Event: IO Capability Response (0x32)", block)

    ev = bus.last()
    assert ev.raw_json.get("io_capability") == "DisplayYesNo"


@pytest.mark.asyncio
async def test_io_capability_noio_extracted():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: IO Capability Request (0x31) [hci0]",
        "        Address: 11:22:33:44:55:66 (Unknown)",
        "        Capability: NoInputNoOutput (0x03)",
    ]
    await collector._emit_event(">", "HCI Event: IO Capability Request (0x31)", block)

    ev = bus.last()
    assert ev.raw_json.get("io_capability") == "NoInputNoOutput"


# ---------------------------------------------------------------------------
# HciCollector._emit_event: disconnect reason extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disconnect_reason_extracted():
    collector, bus = _make_collector()

    # Populate handle mapping first
    await collector._emit_event(">", "HCI Event: Connection Complete (0x03)", [
        "> HCI Event: Connection Complete (0x03) [hci0]",
        "        Handle: 256",
        "        Address: AA:BB:CC:DD:EE:FF (Unknown)",
    ])
    bus.clear()

    block = [
        "> HCI Event: Disconnection Complete (0x05) [hci0]",
        "        Status: Success (0x00)",
        "        Handle: 256",
        "        Reason: Connection Timeout (0x08)",
    ]
    await collector._emit_event(">", "HCI Event: Disconnection Complete (0x05)", block)

    ev = bus.last()
    assert ev.raw_json.get("reason_name") == "Connection Timeout"
    assert ev.raw_json.get("reason_code") == "0x08"


@pytest.mark.asyncio
async def test_handle_extracted_into_raw_json():
    collector, bus = _make_collector()

    block = [
        "> HCI Event: Number of Completed Packets (0x13) [hci0]",
        "        Num Handles: 1 (0x01)",
        "        Handle: 512",
    ]
    await collector._emit_event(">", "HCI Event: Number of Completed Packets (0x13)", block)

    ev = bus.last()
    assert ev.raw_json.get("handle") == 512
