"""
blutruth.enrichment.a2dp_codecs — A2DP codec configuration decoder

Decodes A2DP codec configuration bytes from AVDTP SEID capability and
configuration exchanges, as well as BlueZ D-Bus MediaTransport1 properties.

Supports: SBC, AAC, aptX, aptX HD, LDAC, LC3 (LE Audio)

Reference:
  - A2DP Spec v1.4, Section 4.3 (Codec Specific Information Elements)
  - Bluetooth SIG Assigned Numbers, Section 6.5 (A2DP)

Usage:
    from blutruth.enrichment.a2dp_codecs import decode_sbc_config, decode_codec_id
    config = decode_sbc_config(bytes.fromhex("21150233"))
    # {"sampling_freq": "44100 Hz", "channel_mode": "Joint Stereo",
    #  "block_length": 16, "subbands": 8, "allocation_method": "Loudness",
    #  "min_bitpool": 2, "max_bitpool": 51}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# A2DP Codec IDs (from AVDTP)
_CODEC_IDS: Dict[int, str] = {
    0x00: "SBC",
    0x01: "MPEG-1,2 Audio (MP3)",
    0x02: "MPEG-2,4 AAC",
    0x03: "ATRAC Family",
    0xFF: "Vendor Specific",
}

# Vendor codec IDs: (vendor_id, codec_id) → name
_VENDOR_CODECS: Dict[tuple, str] = {
    (0x004F, 0x0001): "aptX",
    (0x00D7, 0x0024): "aptX HD",
    (0x012D, 0x00AA): "LDAC",
    (0x00E0, 0x0001): "Samsung Scalable Codec",
    (0x000A, 0x0001): "LC3 (LE Audio)",       # via A2DP extension
    (0x0075, 0x0003): "aptX Adaptive",
    (0x0075, 0x0001): "aptX Low Latency",
}


def decode_codec_id(codec_type: int, vendor_id: int = 0, vendor_codec_id: int = 0) -> str:
    """Decode A2DP codec type byte to human-readable name.

    Args:
        codec_type: AVDTP Media Codec Type (0x00-0xFF).
        vendor_id: For vendor-specific codecs (type 0xFF), the BT SIG company ID.
        vendor_codec_id: For vendor-specific codecs, the vendor's codec ID.
    """
    if codec_type == 0xFF:
        return _VENDOR_CODECS.get(
            (vendor_id, vendor_codec_id),
            f"Vendor (0x{vendor_id:04X}:0x{vendor_codec_id:04X})"
        )
    return _CODEC_IDS.get(codec_type, f"Unknown (0x{codec_type:02X})")


# ============================================================================
# SBC Configuration (A2DP Spec Section 4.3.2)
# ============================================================================

_SBC_SAMPLING_FREQ = {
    0x80: "16000 Hz",
    0x40: "32000 Hz",
    0x20: "44100 Hz",
    0x10: "48000 Hz",
}

_SBC_CHANNEL_MODE = {
    0x08: "Mono",
    0x04: "Dual Channel",
    0x02: "Stereo",
    0x01: "Joint Stereo",
}

_SBC_BLOCK_LENGTH = {
    0x80: 4,
    0x40: 8,
    0x20: 12,
    0x10: 16,
}

_SBC_SUBBANDS = {
    0x08: 4,
    0x04: 8,
}

_SBC_ALLOCATION = {
    0x02: "SNR",
    0x01: "Loudness",
}


def decode_sbc_config(config_bytes: bytes) -> Dict[str, Any]:
    """Decode SBC codec configuration (4 bytes).

    Byte 0: sampling frequency (hi nibble) | channel mode (lo nibble)
    Byte 1: block length (hi nibble) | subbands | allocation method
    Byte 2: minimum bitpool
    Byte 3: maximum bitpool
    """
    if len(config_bytes) < 4:
        return {"error": f"SBC config too short: {len(config_bytes)} bytes (need 4)"}

    b0, b1, min_bp, max_bp = config_bytes[0], config_bytes[1], config_bytes[2], config_bytes[3]

    # For capabilities, multiple bits can be set (indicating support for multiple options)
    # For a selected configuration, exactly one bit is set
    freq = _first_match(b0 & 0xF0, _SBC_SAMPLING_FREQ)
    channel = _first_match(b0 & 0x0F, _SBC_CHANNEL_MODE)
    block = _first_match(b1 & 0xF0, _SBC_BLOCK_LENGTH)
    subbands = _first_match(b1 & 0x0C, _SBC_SUBBANDS)
    alloc = _first_match(b1 & 0x03, _SBC_ALLOCATION)

    result = {
        "codec": "SBC",
        "sampling_freq": freq,
        "channel_mode": channel,
        "block_length": block,
        "subbands": subbands,
        "allocation_method": alloc,
        "min_bitpool": min_bp,
        "max_bitpool": max_bp,
    }

    # Estimate bitrate for Joint Stereo 44.1kHz (most common config)
    if isinstance(block, int) and isinstance(subbands, int) and max_bp:
        # SBC bitrate formula: bitrate = 8 * frame_length * sampling_freq / (subbands * block_length)
        # Simplified: bitrate ≈ sampling_freq * max_bitpool / subbands (rough estimate)
        if freq and "44100" in str(freq):
            est_kbps = round(8 * max_bp * 44100 / (subbands * block * 1000))
            result["estimated_bitrate_kbps"] = est_kbps
            if est_kbps < 200:
                result["quality_note"] = "Low quality (below 200 kbps)"
            elif est_kbps < 328:
                result["quality_note"] = "Standard quality"
            else:
                result["quality_note"] = "High quality SBC"

    return result


# ============================================================================
# AAC Configuration (A2DP Spec Section 4.5.2)
# ============================================================================

_AAC_OBJECT_TYPES = {
    0x80: "MPEG-2 AAC LC",
    0x40: "MPEG-4 AAC LC",
    0x20: "MPEG-4 AAC LTP",
    0x10: "MPEG-4 AAC Scalable",
}

_AAC_SAMPLING_FREQ = {
    # Byte 1 bits
    0x8000: "8000 Hz",
    0x4000: "11025 Hz",
    0x2000: "12000 Hz",
    0x1000: "16000 Hz",
    0x0800: "22050 Hz",
    0x0400: "24000 Hz",
    0x0200: "32000 Hz",
    0x0100: "44100 Hz",
    0x0080: "48000 Hz",
    0x0040: "64000 Hz",
    0x0020: "88200 Hz",
    0x0010: "96000 Hz",
}


def decode_aac_config(config_bytes: bytes) -> Dict[str, Any]:
    """Decode AAC codec configuration (6 bytes).

    Byte 0: object type
    Byte 1-2: sampling frequency (12 bits) + channels (4 bits)
    Byte 3-5: VBR flag + bitrate (23 bits)
    """
    if len(config_bytes) < 6:
        return {"error": f"AAC config too short: {len(config_bytes)} bytes (need 6)"}

    obj_type = _first_match(config_bytes[0], _AAC_OBJECT_TYPES)
    freq_bits = (config_bytes[1] << 8) | (config_bytes[2] & 0xF0)
    freq = _first_match(freq_bits, _AAC_SAMPLING_FREQ)
    channels = config_bytes[2] & 0x0C
    ch_str = {0x08: "1 (Mono)", 0x04: "2 (Stereo)"}.get(channels, f"Unknown ({channels:#x})")

    vbr = bool(config_bytes[3] & 0x80)
    bitrate = ((config_bytes[3] & 0x7F) << 16) | (config_bytes[4] << 8) | config_bytes[5]

    return {
        "codec": "AAC",
        "object_type": obj_type,
        "sampling_freq": freq,
        "channels": ch_str,
        "vbr": vbr,
        "bitrate_bps": bitrate if bitrate > 0 else "not specified",
        "bitrate_kbps": round(bitrate / 1000) if bitrate > 0 else None,
    }


# ============================================================================
# LDAC Configuration
# ============================================================================

_LDAC_SAMPLING_FREQ = {
    0x20: "44100 Hz",
    0x10: "48000 Hz",
    0x08: "88200 Hz",
    0x04: "96000 Hz",
}

_LDAC_CHANNEL_MODE = {
    0x04: "Mono",
    0x02: "Dual Channel",
    0x01: "Stereo",
}


def decode_ldac_config(config_bytes: bytes) -> Dict[str, Any]:
    """Decode LDAC vendor-specific configuration."""
    if len(config_bytes) < 2:
        return {"error": f"LDAC config too short: {len(config_bytes)} bytes"}

    freq = _first_match(config_bytes[0], _LDAC_SAMPLING_FREQ)
    channel = _first_match(config_bytes[1], _LDAC_CHANNEL_MODE)

    return {
        "codec": "LDAC",
        "sampling_freq": freq,
        "channel_mode": channel,
        "quality_note": "Hi-Res codec (up to 990 kbps at 96 kHz)",
    }


# ============================================================================
# aptX / aptX HD
# ============================================================================

_APTX_SAMPLING_FREQ = {
    0x20: "44100 Hz",
    0x10: "48000 Hz",
}

_APTX_CHANNEL_MODE = {
    0x02: "Stereo",
    0x01: "Mono",
}


def decode_aptx_config(config_bytes: bytes, hd: bool = False) -> Dict[str, Any]:
    """Decode aptX or aptX HD configuration."""
    if len(config_bytes) < 1:
        return {"error": "aptX config empty"}

    freq = _first_match(config_bytes[0] & 0xF0, _APTX_SAMPLING_FREQ)
    channel = _first_match(config_bytes[0] & 0x0F, _APTX_CHANNEL_MODE)

    codec_name = "aptX HD" if hd else "aptX"
    bitrate = "576 kbps" if hd else "352 kbps"

    return {
        "codec": codec_name,
        "sampling_freq": freq,
        "channel_mode": channel,
        "nominal_bitrate": bitrate,
        "quality_note": f"{'Hi-Res 24-bit' if hd else 'Low-latency'} codec",
    }


# ============================================================================
# Codec quality comparison
# ============================================================================

# Approximate quality ranking (higher = better audio quality)
_CODEC_QUALITY_RANK: Dict[str, int] = {
    "LDAC": 5,
    "aptX HD": 4,
    "aptX Adaptive": 4,
    "AAC": 3,
    "aptX": 3,
    "aptX Low Latency": 2,
    "SBC": 1,
}


def codec_quality_rank(codec_name: str) -> int:
    """Return quality rank (1-5) for a codec. 0 if unknown."""
    return _CODEC_QUALITY_RANK.get(codec_name, 0)


def is_codec_downgrade(from_codec: str, to_codec: str) -> bool:
    """Check if switching from one codec to another is a downgrade."""
    return codec_quality_rank(from_codec) > codec_quality_rank(to_codec)


# ============================================================================
# Helpers
# ============================================================================

def _first_match(value: int, table: dict) -> Any:
    """Return first matching entry from a bitmask table (highest bit wins)."""
    for mask, name in sorted(table.items(), reverse=True):
        if value & mask:
            return name
    return f"Unknown (0x{value:02X})"
