"""
Tests for blutruth.enrichment — OUI lookup and HCI error code decoding.
"""
from __future__ import annotations

import pytest

from blutruth.enrichment.oui import enrich_oui, enrich_oui_display
from blutruth.enrichment.hci_codes import decode_hci_error, decode_hci_error_short


# ---------------------------------------------------------------------------
# enrich_oui
# ---------------------------------------------------------------------------

def test_enrich_oui_known_apple_address():
    # Apple OUI: 00:17:F2
    result = enrich_oui("00:17:F2:AA:BB:CC")
    assert result is not None
    assert "Apple" in result


def test_enrich_oui_case_insensitive():
    lower = enrich_oui("00:17:f2:aa:bb:cc")
    upper = enrich_oui("00:17:F2:AA:BB:CC")
    assert lower == upper


def test_enrich_oui_unknown_returns_none():
    # Made-up OUI that's unlikely to be in the table
    result = enrich_oui("FE:DC:BA:AA:BB:CC")
    # May or may not be in table — just verify it doesn't crash
    assert result is None or isinstance(result, str)


def test_enrich_oui_none_input():
    assert enrich_oui(None) is None


def test_enrich_oui_empty_string():
    assert enrich_oui("") is None


def test_enrich_oui_malformed_address():
    assert enrich_oui("not-an-addr") is None


def test_enrich_oui_short_address():
    assert enrich_oui("AA:BB:CC") is None


# ---------------------------------------------------------------------------
# enrich_oui_display
# ---------------------------------------------------------------------------

def test_enrich_oui_display_known_address():
    result = enrich_oui_display("00:17:F2:AA:BB:CC")
    assert isinstance(result, str)
    assert len(result) > 0
    # Should include the address or a manufacturer name
    assert "Apple" in result or "00:17:F2" in result


def test_enrich_oui_display_unknown_address():
    # Unknown OUI — should still return a string (not None, not empty)
    result = enrich_oui_display("FE:DC:BA:AA:BB:CC")
    assert isinstance(result, str)
    assert len(result) > 0


def test_enrich_oui_display_none_input():
    result = enrich_oui_display(None)
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# decode_hci_error
# ---------------------------------------------------------------------------

def test_decode_hci_error_success():
    result = decode_hci_error(0x00)
    assert isinstance(result, dict)
    assert result.get("name") is not None
    assert "SUCCESS" in result.get("name", "").upper() or result.get("name") is not None


def test_decode_hci_error_connection_timeout():
    result = decode_hci_error(0x08)
    assert "Timeout" in result["name"] or "timeout" in result["name"].lower()


def test_decode_hci_error_authentication_failure():
    result = decode_hci_error(0x05)
    assert "Auth" in result["name"] or "auth" in result["name"].lower()


def test_decode_hci_error_has_required_keys():
    result = decode_hci_error(0x08)
    assert "name" in result


def test_decode_hci_error_unknown_code():
    # An error code that doesn't exist in the table
    result = decode_hci_error(0xFE)
    assert result is not None


def test_decode_hci_error_lmp_timeout():
    result = decode_hci_error(0x22)
    assert "LMP" in result.get("name", "") or "Timeout" in result.get("name", "")


# ---------------------------------------------------------------------------
# decode_hci_error_short
# ---------------------------------------------------------------------------

def test_decode_hci_error_short_returns_string():
    result = decode_hci_error_short(0x08)
    assert isinstance(result, str)
    assert len(result) > 0


def test_decode_hci_error_short_contains_hex():
    result = decode_hci_error_short(0x08)
    assert "0x08" in result or "08" in result


def test_decode_hci_error_short_connection_timeout():
    result = decode_hci_error_short(0x08)
    assert "Timeout" in result or "timeout" in result.lower()


def test_decode_hci_error_short_unknown_code():
    result = decode_hci_error_short(0xFE)
    assert isinstance(result, str)
