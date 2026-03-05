"""
blutruth.enrichment.hci_codes — HCI error/reason code decoder

Maps numeric HCI error codes to human-readable names, descriptions,
and likely causes. Applied to Disconnection Complete, Connect Failed,
Authentication Failed, and any other HCI events that carry a status/reason code.

Reference: Bluetooth Core Spec 5.4, Vol 1, Part F — Error Codes

Usage:
    from blutruth.enrichment.hci_codes import decode_hci_error
    info = decode_hci_error(0x08)
    # {"code": "0x08", "name": "CONNECTION_TIMEOUT", "description": "...", "cause": "..."}
"""
from __future__ import annotations

from typing import Optional


# code → (name, description, likely_cause, suggested_action)
_HCI_ERRORS: dict[int, tuple[str, str, str, str]] = {
    0x00: (
        "SUCCESS",
        "Operation completed successfully.",
        "Normal operation.",
        "None needed.",
    ),
    0x01: (
        "UNKNOWN_HCI_COMMAND",
        "Controller does not recognize the HCI command.",
        "Driver/firmware version mismatch. Command sent to wrong controller.",
        "Check driver and firmware versions. Ensure correct HCI channel.",
    ),
    0x02: (
        "UNKNOWN_CONNECTION_IDENTIFIER",
        "Connection handle not recognized by the controller.",
        "Command sent for a connection that no longer exists. Race condition in driver.",
        "Handle connection teardown race conditions. Check driver disconnect sequencing.",
    ),
    0x03: (
        "HARDWARE_FAILURE",
        "Hardware failure in the controller.",
        "Controller firmware crash, USB reset, hardware fault.",
        "Check dmesg for btusb/controller errors. Try unplugging and reinserting adapter.",
    ),
    0x04: (
        "PAGE_TIMEOUT",
        "Remote device did not respond to a page.",
        "Device out of range. Device is off or in deep sleep. Device in non-discoverable mode.",
        "Ensure device is powered on and in range. Check device is discoverable.",
    ),
    0x05: (
        "AUTHENTICATION_FAILURE",
        "Authentication failed — link key or PIN mismatch.",
        "Paired device has a different link key (cleared on one side). Wrong PIN entered.",
        "Remove pairing on both devices and re-pair. Check if device storage was wiped.",
    ),
    0x06: (
        "PIN_OR_KEY_MISSING",
        "Link key or PIN required but not available.",
        "Pairing database inconsistency — device expects key that host doesn't have.",
        "Remove and re-pair device. Clear /var/lib/bluetooth/<adapter>/<device>.",
    ),
    0x07: (
        "MEMORY_CAPACITY_EXCEEDED",
        "Controller ran out of memory resources.",
        "Too many simultaneous connections. Too many pending commands.",
        "Reduce number of active connections. Check for connection leaks.",
    ),
    0x08: (
        "CONNECTION_TIMEOUT",
        "Connection lost due to lack of response from remote device.",
        "Device moved out of range. RF interference. Device went to sleep without disconnecting cleanly.",
        "Check RF environment for interference. Move devices closer. Check device power management settings.",
    ),
    0x09: (
        "CONNECTION_LIMIT_EXCEEDED",
        "Maximum number of allowed connections has been reached.",
        "Controller at capacity. Typical limit is 7 active connections for Classic BT.",
        "Disconnect unused devices before connecting new ones.",
    ),
    0x0A: (
        "SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED",
        "Maximum synchronous connections (SCO/eSCO) exceeded.",
        "Too many concurrent HFP/HSP connections.",
        "Disconnect unused HFP/HSP connections.",
    ),
    0x0B: (
        "ACL_CONNECTION_ALREADY_EXISTS",
        "Attempted to create a connection that already exists.",
        "Duplicate connection attempt. Race condition in connection management.",
        "Check for duplicate connect() calls. Handle connection state properly.",
    ),
    0x0C: (
        "COMMAND_DISALLOWED",
        "Command is not allowed in the current state.",
        "Command sent at wrong time or in wrong state. Device not in correct mode.",
        "Check device state before sending command. Implement proper state machine.",
    ),
    0x0D: (
        "CONNECTION_REJECTED_LIMITED_RESOURCES",
        "Remote device rejected connection due to limited resources.",
        "Remote device at maximum connections. Remote device low on memory.",
        "Try again later. Remote device may need to disconnect other devices first.",
    ),
    0x0E: (
        "CONNECTION_REJECTED_SECURITY_REASONS",
        "Remote device rejected connection for security reasons.",
        "Remote device has security policy that blocks this connection. Untrusted device.",
        "Check device pairing status and trust level on remote device.",
    ),
    0x0F: (
        "CONNECTION_REJECTED_UNACCEPTABLE_BD_ADDR",
        "Remote device rejected connection based on BD_ADDR.",
        "Device has an allowlist/blocklist and your adapter's address is blocked.",
        "Check device pairing restrictions. Some devices only accept previously paired addresses.",
    ),
    0x10: (
        "CONNECTION_ACCEPT_TIMEOUT",
        "Connection accept timed out.",
        "User did not accept connection in time. Application did not call accept() quickly enough.",
        "Increase connection accept timeout. Ensure application handles incoming connections promptly.",
    ),
    0x11: (
        "UNSUPPORTED_FEATURE_OR_PARAMETER",
        "Feature or parameter value not supported.",
        "Requesting a feature the controller doesn't support. Parameter out of valid range.",
        "Check controller capabilities before using feature. Validate parameter ranges.",
    ),
    0x12: (
        "INVALID_HCI_COMMAND_PARAMETERS",
        "Invalid HCI command parameters.",
        "Bug in driver. Parameter values outside allowed range.",
        "Check driver for parameter validation bugs.",
    ),
    0x13: (
        "REMOTE_USER_TERMINATED_CONNECTION",
        "Remote device terminated the connection.",
        "Normal — remote device (headphones, phone, etc.) closed the connection on its end.",
        "Usually benign. If unexpected, check for battery events or device going to sleep.",
    ),
    0x14: (
        "REMOTE_DEVICE_TERMINATED_LOW_RESOURCES",
        "Remote device terminated due to low resources.",
        "Remote device running out of buffer space or memory.",
        "Reduce data throughput. Check if remote device has memory or battery issues.",
    ),
    0x15: (
        "REMOTE_DEVICE_TERMINATED_POWER_OFF",
        "Remote device terminated because it is powering off.",
        "Clean shutdown — device powered off gracefully.",
        "Normal. Device was turned off.",
    ),
    0x16: (
        "CONNECTION_TERMINATED_BY_LOCAL_HOST",
        "Local host terminated the connection.",
        "Normal — local software (bluetoothd, application) closed the connection.",
        "Check which process initiated the disconnect. May indicate application crash.",
    ),
    0x17: (
        "REPEATED_ATTEMPTS",
        "Too many repeated attempts.",
        "Pairing or authentication being retried too aggressively.",
        "Implement backoff between connection attempts.",
    ),
    0x18: (
        "PAIRING_NOT_ALLOWED",
        "Pairing is not allowed.",
        "Device has pairing disabled. Device is not in pairing mode.",
        "Put device in pairing mode. Check device pairing settings.",
    ),
    0x19: (
        "UNKNOWN_LMP_PDU",
        "Unknown LMP protocol data unit.",
        "Firmware version mismatch. Bug in remote device's Bluetooth implementation.",
        "Update firmware on both devices. Check BT version compatibility.",
    ),
    0x1A: (
        "UNSUPPORTED_REMOTE_FEATURE",
        "Remote device does not support requested feature.",
        "Attempting to use a BT feature the remote device doesn't implement.",
        "Check remote device's supported features before using advanced features.",
    ),
    0x1B: (
        "SCO_OFFSET_REJECTED",
        "Remote device rejected synchronous connection offset.",
        "Timing negotiation failure for SCO/HFP connection.",
        "Retry SCO connection. May indicate interference or timing issues.",
    ),
    0x1C: (
        "SCO_INTERVAL_REJECTED",
        "Remote device rejected synchronous connection interval.",
        "eSCO/SCO interval negotiation failure.",
        "Try different SCO parameters. Check for other active connections using SCO slots.",
    ),
    0x1D: (
        "SCO_AIR_MODE_REJECTED",
        "Remote device rejected synchronous connection air mode.",
        "Codec negotiation failure for HFP/HSP.",
        "Check which codecs are supported. Try falling back to CVSD.",
    ),
    0x1E: (
        "INVALID_LMP_PARAMETERS",
        "Invalid LMP parameters or LL parameters.",
        "Bug in remote device's BT stack. Protocol violation.",
        "Update remote device firmware. File bug if persistent.",
    ),
    0x1F: (
        "UNSPECIFIED_ERROR",
        "Unspecified error.",
        "Controller encountered an error it couldn't classify.",
        "Check dmesg and controller logs for more context.",
    ),
    0x20: (
        "UNSUPPORTED_LMP_PARAMETER",
        "Unsupported LMP or LL parameter value.",
        "Remote device doesn't support the parameter value. Compatibility issue.",
        "Fall back to more conservative parameters.",
    ),
    0x21: (
        "ROLE_CHANGE_NOT_ALLOWED",
        "Role change not allowed.",
        "Attempted to switch master/slave roles but remote device denied it.",
        "Some devices don't support role switching. Don't attempt role change.",
    ),
    0x22: (
        "LMP_RESPONSE_TIMEOUT",
        "LMP response timeout — remote device stopped responding.",
        "Device went out of range. Device firmware hang. Severe RF interference.",
        "Check RF environment. Device may need power cycle. Check for firmware issues.",
    ),
    0x23: (
        "LMP_ERROR_TRANSACTION_COLLISION",
        "LMP transaction collision.",
        "Both sides initiated LMP transaction simultaneously. Normal race condition.",
        "Usually resolves automatically. If persistent, indicates protocol implementation bug.",
    ),
    0x24: (
        "LMP_PDU_NOT_ALLOWED",
        "LMP PDU not allowed.",
        "LMP command sent in wrong connection state.",
        "Check state machine logic.",
    ),
    0x25: (
        "ENCRYPTION_MODE_NOT_ACCEPTABLE",
        "Encryption mode not acceptable to remote device.",
        "Security policy mismatch. Remote device requires stronger encryption.",
        "Check encryption settings. Both devices need compatible encryption requirements.",
    ),
    0x26: (
        "LINK_KEY_CANNOT_BE_CHANGED",
        "Link key cannot be changed.",
        "Attempt to change link key when not allowed.",
        "Normal in some pairing scenarios. Usually recoverable.",
    ),
    0x27: (
        "REQUESTED_QOS_NOT_SUPPORTED",
        "Requested QoS not supported.",
        "Quality of service parameters not achievable.",
        "Fall back to default QoS settings.",
    ),
    0x28: (
        "INSTANT_PASSED",
        "Instant in LMP command has already passed.",
        "Timing synchronization issue. BT clock drift.",
        "Retry operation. If persistent, may indicate clock synchronization problem.",
    ),
    0x29: (
        "PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED",
        "Pairing with unit key not supported.",
        "Remote device only supports legacy pairing method not supported locally.",
        "Update device firmware if possible.",
    ),
    0x2A: (
        "DIFFERENT_TRANSACTION_COLLISION",
        "Different transaction collision.",
        "Transaction collision that could not be resolved.",
        "Retry. Usually transient.",
    ),
    0x2C: (
        "QOS_UNACCEPTABLE_PARAMETER",
        "QoS unacceptable parameter.",
        "QoS negotiation failure.",
        "Use default QoS settings.",
    ),
    0x2D: (
        "QOS_REJECTED",
        "QoS rejected by remote device.",
        "Remote device cannot meet QoS requirements.",
        "Reduce QoS requirements or use default.",
    ),
    0x2E: (
        "CHANNEL_CLASSIFICATION_NOT_SUPPORTED",
        "Channel classification not supported.",
        "AFH channel classification not supported by remote.",
        "Normal compatibility issue. AFH will not be used.",
    ),
    0x2F: (
        "INSUFFICIENT_SECURITY",
        "Insufficient security.",
        "Connection attempt with security level below remote device's requirement.",
        "Enable encryption. Ensure SSP is enabled. Check security level settings.",
    ),
    0x30: (
        "PARAMETER_OUT_OF_MANDATORY_RANGE",
        "Parameter out of mandatory range.",
        "Parameter value outside spec-mandated range.",
        "Check parameter values against spec. Update driver if values seem correct.",
    ),
    0x32: (
        "ROLE_SWITCH_PENDING",
        "Role switch pending.",
        "Role switch in progress — command cannot be handled now.",
        "Retry command after role switch completes.",
    ),
    0x34: (
        "RESERVED_SLOT_VIOLATION",
        "Reserved slot violation.",
        "Packet sent in a reserved slot.",
        "Timing issue. Usually transient.",
    ),
    0x35: (
        "ROLE_SWITCH_FAILED",
        "Role switch failed.",
        "Master/slave role switch attempt failed.",
        "Remote device may not support role switching. Don't retry.",
    ),
    0x36: (
        "EXTENDED_INQUIRY_RESPONSE_TOO_LARGE",
        "Extended inquiry response too large.",
        "EIR data exceeds 240 bytes.",
        "Reduce EIR data size.",
    ),
    0x37: (
        "SECURE_SIMPLE_PAIRING_NOT_SUPPORTED",
        "Secure Simple Pairing not supported by host.",
        "Remote device requires SSP but host has it disabled.",
        "Enable SSP in bluetoothd configuration.",
    ),
    0x38: (
        "HOST_BUSY_PAIRING",
        "Host busy with pairing.",
        "Another pairing procedure is in progress.",
        "Wait for current pairing to complete before initiating another.",
    ),
    0x39: (
        "CONNECTION_REJECTED_NO_SUITABLE_CHANNEL",
        "Connection rejected — no suitable channel found.",
        "No channel available that meets requirements. Possible interference.",
        "Check RF environment. Wait and retry.",
    ),
    0x3A: (
        "CONTROLLER_BUSY",
        "Controller busy.",
        "Controller cannot accept the command at this time.",
        "Wait and retry. Reduce number of concurrent operations.",
    ),
    0x3B: (
        "UNACCEPTABLE_CONNECTION_PARAMETERS",
        "Unacceptable connection parameters.",
        "Connection interval/latency/timeout outside acceptable range.",
        "Adjust BLE connection parameters to values both sides accept.",
    ),
    0x3C: (
        "ADVERTISING_TIMEOUT",
        "Directed advertising timed out.",
        "Directed advertising completed without a connection being established.",
        "Check if target device is available and listening.",
    ),
    0x3D: (
        "CONNECTION_TERMINATED_MIC_FAILURE",
        "Connection terminated due to MIC failure.",
        "Message integrity check failed — encryption key may be compromised. Possible MITM attack.",
        "Re-pair device. If persistent, investigate possible security attack.",
    ),
    0x3E: (
        "CONNECTION_FAILED_TO_BE_ESTABLISHED",
        "Connection failed to be established.",
        "Connection procedure started but could not complete. Device busy, out of range, or key mismatch.",
        "Check device availability and pairing status. Re-pair if key mismatch suspected.",
    ),
    0x3F: (
        "MAC_CONNECTION_FAILED",
        "MAC of the 802.11 MWS coexistence failed.",
        "WiFi/BT coexistence issue.",
        "Check WiFi/BT coexistence settings. Move WiFi to 5GHz if possible.",
    ),
    0x40: (
        "COARSE_CLOCK_ADJUSTMENT_REJECTED",
        "Coarse clock adjustment rejected but will try to adjust using clock dragging.",
        "Clock adjustment negotiation. Usually self-resolving.",
        "Usually transient. Monitor for persistence.",
    ),
    0x41: (
        "TYPE0_SUBMAP_NOT_DEFINED",
        "Type0 submap not defined.",
        "CSB (Connectionless Slave Broadcast) issue.",
        "Check CSB configuration.",
    ),
    0x42: (
        "UNKNOWN_ADVERTISING_IDENTIFIER",
        "Unknown advertising identifier.",
        "Extended advertising set ID not found.",
        "Ensure advertising set is created before referencing it.",
    ),
    0x43: (
        "LIMIT_REACHED",
        "Advertising or synchronization limit reached.",
        "Maximum number of advertising sets or periodic sync handles reached.",
        "Remove unused advertising sets or sync handles.",
    ),
    0x44: (
        "OPERATION_CANCELLED_BY_HOST",
        "Operation cancelled by host.",
        "Host cancelled an ongoing operation.",
        "Normal if intentional. Investigate if unexpected.",
    ),
    0x45: (
        "PACKET_TOO_LONG",
        "Packet too long.",
        "Data packet exceeds controller's buffer size.",
        "Reduce packet size or check MTU negotiation.",
    ),
}


def decode_hci_error(code: int) -> dict:
    """
    Return a dict with name, description, likely cause, and suggested action
    for an HCI error/reason code.

    Args:
        code: Integer HCI error code (e.g., 0x08 = 8)

    Returns:
        {
            "code":    "0x08",
            "name":    "CONNECTION_TIMEOUT",
            "description": "...",
            "cause":   "...",
            "action":  "...",
        }
    """
    entry = _HCI_ERRORS.get(code)
    if entry:
        name, description, cause, action = entry
    else:
        name        = f"UNKNOWN_0x{code:02X}"
        description = f"Unknown HCI error code 0x{code:02X}."
        cause       = "Vendor-specific or reserved error code."
        action      = "Consult controller vendor documentation."

    return {
        "code":        f"0x{code:02X}",
        "name":        name,
        "description": description,
        "cause":       cause,
        "action":      action,
    }


def decode_hci_error_short(code: int) -> str:
    """Return 'CODE_NAME (0xNN)' string for logging."""
    entry = _HCI_ERRORS.get(code)
    name = entry[0] if entry else f"UNKNOWN"
    return f"{name} (0x{code:02X})"
