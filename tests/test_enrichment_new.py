"""
Tests for new enrichment modules: LMP, SMP, GATT UUIDs, USB IDs, A2DP codecs.
"""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# LMP Features
# ---------------------------------------------------------------------------
from blutruth.enrichment.lmp_features import (
    decode_lmp_features, decode_lmp_features_detailed, summarize_capabilities,
)


def test_lmp_page0_basic_features():
    # Bits 0,1,2 = 3-slot, 5-slot, encryption
    features = decode_lmp_features(0x07, page=0)
    assert "3-slot packets" in features
    assert "5-slot packets" in features
    assert "encryption" in features


def test_lmp_page0_le_supported():
    features = decode_lmp_features(1 << 38, page=0)
    assert "LE supported (ctrl)" in features


def test_lmp_page0_ssp():
    features = decode_lmp_features(1 << 51, page=0)
    assert "secure simple pairing" in features


def test_lmp_page1_host_features():
    features = decode_lmp_features(0x0F, page=1)
    assert "SSP (host)" in features
    assert "LE supported (host)" in features


def test_lmp_page_invalid():
    features = decode_lmp_features(0xFF, page=99)
    assert features == []


def test_lmp_zero_value():
    assert decode_lmp_features(0, page=0) == []


def test_lmp_detailed_has_description():
    result = decode_lmp_features_detailed(0x04, page=0)
    assert len(result) == 1
    assert result[0]["name"] == "encryption"
    assert "description" in result[0]


def test_lmp_summarize_capabilities():
    # All features set
    caps = summarize_capabilities(0xFFFFFFFFFFFFFFFF)
    assert caps["encryption"] is True
    assert caps["le_supported"] is True
    assert caps["ssp"] is True

    # No features
    caps0 = summarize_capabilities(0)
    assert caps0["encryption"] is False
    assert caps0["le_supported"] is False


# ---------------------------------------------------------------------------
# SMP Features
# ---------------------------------------------------------------------------
from blutruth.enrichment.smp_features import (
    decode_io_capability, decode_oob_data, decode_auth_req,
    decode_key_dist, predict_pairing_method, assess_security,
)


def test_smp_io_capability_known():
    assert decode_io_capability(0x03) == "NoInputNoOutput"
    assert decode_io_capability(0x01) == "DisplayYesNo"


def test_smp_io_capability_reserved():
    result = decode_io_capability(0x05)
    assert "Reserved" in result


def test_smp_oob_data():
    assert "not available" in decode_oob_data(0x00)
    assert "available" in decode_oob_data(0x01)


def test_smp_auth_req_bonding_mitm_sc():
    flags = decode_auth_req(0x0D)  # bonding(01) + MITM(04) + SC(08) = 0x0D
    assert "bonding" in flags
    assert "MITM" in flags
    assert "SC" in flags


def test_smp_auth_req_no_bonding():
    flags = decode_auth_req(0x00)
    assert "no-bonding" in flags


def test_smp_key_dist():
    keys = decode_key_dist(0x07)  # EncKey + IdKey + Sign
    assert "EncKey" in keys
    assert "IdKey" in keys
    assert "Sign" in keys


def test_smp_key_dist_empty():
    assert decode_key_dist(0x00) == []


def test_smp_pairing_method_just_works():
    assert predict_pairing_method(0x03, 0x03) == "JustWorks"


def test_smp_pairing_method_numeric_comparison():
    # DisplayYesNo + DisplayYesNo with SC
    method = predict_pairing_method(0x01, 0x01, secure_connections=True)
    assert "NumericComparison" in method


def test_smp_pairing_method_no_sc_fallback():
    # DisplayYesNo + DisplayYesNo without SC → JustWorks
    method = predict_pairing_method(0x01, 0x01, secure_connections=False)
    assert method == "JustWorks"


def test_smp_assess_security_high():
    result = assess_security(0x04, 0x0D, secure_connections=True)
    assert result["level"] == "high"
    assert result["mitm_protection"] is True
    assert result["secure_connections"] is True


def test_smp_assess_security_low():
    result = assess_security(0x03, 0x00)
    assert result["level"] == "low"
    assert "JustWorks" in result["assessment"]


# ---------------------------------------------------------------------------
# GATT UUIDs
# ---------------------------------------------------------------------------
from blutruth.enrichment.gatt_uuids import (
    service_name, characteristic_name, descriptor_name,
    uuid_name, is_vendor_uuid,
)


def test_gatt_service_name_short():
    assert service_name("180f") == "Battery Service"


def test_gatt_service_name_full_uuid():
    assert service_name("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service"


def test_gatt_service_name_unknown():
    assert service_name("9999") is None


def test_gatt_char_name():
    assert characteristic_name("2a19") == "Battery Level"
    assert characteristic_name("2a29") == "Manufacturer Name String"


def test_gatt_descriptor_name():
    assert descriptor_name("2902") == "Client Characteristic Configuration"


def test_gatt_uuid_name_service():
    result = uuid_name("180f")
    assert result == ("service", "Battery Service")


def test_gatt_uuid_name_char():
    result = uuid_name("2a19")
    assert result == ("characteristic", "Battery Level")


def test_gatt_uuid_name_unknown():
    assert uuid_name("ffff") is None


def test_gatt_is_vendor_uuid_short():
    assert is_vendor_uuid("fe2c") is True  # Google Fast Pair (0xFE2C >= 0xFD00)
    assert is_vendor_uuid("180f") is False


def test_gatt_is_vendor_uuid_128bit():
    assert is_vendor_uuid("12345678-1234-1234-1234-123456789abc") is True
    assert is_vendor_uuid("0000180f-0000-1000-8000-00805f9b34fb") is False


# ---------------------------------------------------------------------------
# USB IDs
# ---------------------------------------------------------------------------
from blutruth.enrichment.usb_ids import (
    lookup_adapter, known_issues, adapter_summary,
)


def test_usb_lookup_intel_ax200():
    info = lookup_adapter(0x8087, 0x0029)
    assert info is not None
    assert info["vendor"] == "Intel"
    assert "AX200" in info["name"]


def test_usb_lookup_unknown():
    assert lookup_adapter(0xDEAD, 0xBEEF) is None


def test_usb_known_issues_csr():
    issues = known_issues(0x0a12, 0x0001)
    assert len(issues) >= 2  # clone detection + BT 4.0 limitations


def test_usb_known_issues_vendor_wide():
    issues = known_issues(0x0bda, 0x9999)  # unknown Realtek PID
    assert any("firmware" in i["description"].lower() for i in issues)


def test_usb_known_issues_unknown():
    assert known_issues(0xDEAD, 0xBEEF) == []


def test_usb_adapter_summary():
    s = adapter_summary(0x8087, 0x0029)
    assert "Intel" in s
    assert "BT 5.0" in s


def test_usb_adapter_summary_unknown():
    assert adapter_summary(0xDEAD, 0xBEEF) is None


# ---------------------------------------------------------------------------
# A2DP Codecs
# ---------------------------------------------------------------------------
from blutruth.enrichment.a2dp_codecs import (
    decode_codec_id, decode_sbc_config, decode_aac_config,
    decode_ldac_config, decode_aptx_config,
    codec_quality_rank, is_codec_downgrade,
)


def test_a2dp_codec_id_sbc():
    assert decode_codec_id(0x00) == "SBC"


def test_a2dp_codec_id_aac():
    assert decode_codec_id(0x02) == "MPEG-2,4 AAC"


def test_a2dp_codec_id_vendor_aptx():
    assert decode_codec_id(0xFF, 0x004F, 0x0001) == "aptX"


def test_a2dp_codec_id_vendor_ldac():
    assert decode_codec_id(0xFF, 0x012D, 0x00AA) == "LDAC"


def test_a2dp_codec_id_unknown_vendor():
    result = decode_codec_id(0xFF, 0x0000, 0x0000)
    assert "Vendor" in result


def test_a2dp_sbc_config():
    config = decode_sbc_config(bytes.fromhex("21150233"))
    assert config["codec"] == "SBC"
    assert config["sampling_freq"] == "44100 Hz"
    assert config["channel_mode"] == "Joint Stereo"
    assert config["min_bitpool"] == 2
    assert config["max_bitpool"] == 51


def test_a2dp_sbc_config_too_short():
    result = decode_sbc_config(b"\x00")
    assert "error" in result


def test_a2dp_aac_config():
    # Object type 0x80 (MPEG-2 LC), freq 44100 (bit at 0x0100), stereo (0x04)
    config_bytes = bytes([0x80, 0x01, 0x04, 0x00, 0x01, 0x90])  # 400 bps
    config = decode_aac_config(config_bytes)
    assert config["codec"] == "AAC"
    assert "MPEG-2" in config["object_type"]


def test_a2dp_aac_config_too_short():
    result = decode_aac_config(b"\x00\x01")
    assert "error" in result


def test_a2dp_ldac_config():
    config = decode_ldac_config(bytes([0x20, 0x01]))
    assert config["codec"] == "LDAC"
    assert config["sampling_freq"] == "44100 Hz"
    assert config["channel_mode"] == "Stereo"


def test_a2dp_aptx_config():
    config = decode_aptx_config(bytes([0x22]))  # 44100 + stereo
    assert config["codec"] == "aptX"
    assert config["sampling_freq"] == "44100 Hz"


def test_a2dp_aptx_hd_config():
    config = decode_aptx_config(bytes([0x22]), hd=True)
    assert config["codec"] == "aptX HD"
    assert "576" in config["nominal_bitrate"]


def test_a2dp_quality_rank():
    assert codec_quality_rank("LDAC") > codec_quality_rank("SBC")
    assert codec_quality_rank("aptX HD") > codec_quality_rank("aptX")
    assert codec_quality_rank("unknown") == 0


def test_a2dp_is_downgrade():
    assert is_codec_downgrade("LDAC", "SBC") is True
    assert is_codec_downgrade("SBC", "LDAC") is False
    assert is_codec_downgrade("SBC", "SBC") is False
