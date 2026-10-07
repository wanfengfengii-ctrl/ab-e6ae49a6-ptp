"""Minimal PTPv2 (IEEE 1588-2008) parser for two-step time-transfer messages.

Only the four message types that make up an end-to-end delay-request exchange
are supported: Sync, Follow_Up, Delay_Req and Delay_Resp.  The parser is
strict: the captured datagram must be exactly one PTP message whose
``messageLength`` field matches the captured byte count.
"""

from __future__ import annotations

from dataclasses import dataclass

HEADER_LENGTH = 34
PTP_VERSION = 2
NANOS_PER_SECOND = 1_000_000_000

SYNC = 0x0
DELAY_REQ = 0x1
FOLLOW_UP = 0x8
DELAY_RESP = 0x9

MESSAGE_TYPE_NAMES = {
    SYNC: "Sync",
    DELAY_REQ: "Delay_Req",
    FOLLOW_UP: "Follow_Up",
    DELAY_RESP: "Delay_Resp",
}

# Smallest valid datagram per message type (header + fixed body, no TLVs).
MIN_MESSAGE_LENGTH = {
    SYNC: 44,  # header + originTimestamp
    DELAY_REQ: 44,  # header + originTimestamp
    FOLLOW_UP: 44,  # header + preciseOriginTimestamp
    DELAY_RESP: 54,  # header + receiveTimestamp + requestingPortIdentity
}


class PacketError(Exception):
    """A captured datagram could not be parsed as a supported PTPv2 message."""

    code = "MALFORMED_PACKET"


class MalformedPacket(PacketError):
    code = "MALFORMED_PACKET"


class UnsupportedMessageType(PacketError):
    code = "UNSUPPORTED_MESSAGE_TYPE"


@dataclass(frozen=True)
class PtpMessage:
    message_type: int
    type_name: str
    correction: int  # signed correctionField, units of 2**-16 ns
    source_port_identity: bytes  # 10 bytes: 8-byte clock identity + 2-byte port
    sequence_id: int  # 16-bit sequence number
    timestamp_ns: int  # origin / preciseOrigin / receive timestamp, in ns
    requesting_port_identity: bytes | None  # Delay_Resp only, else None


def format_port_identity(identity: bytes) -> str:
    """Render a 10-byte port identity as ``<clock-identity-hex>:<port>``."""
    clock = identity[:8].hex()
    port = int.from_bytes(identity[8:10], "big")
    return f"{clock}:{port}"


def _parse_timestamp_ns(data: bytes, offset: int) -> int:
    seconds = int.from_bytes(data[offset : offset + 6], "big")
    nanos = int.from_bytes(data[offset + 6 : offset + 10], "big")
    if nanos >= NANOS_PER_SECOND:
        raise MalformedPacket(
            f"timestamp nanoseconds field {nanos} is out of range"
        )
    return seconds * NANOS_PER_SECOND + nanos


def parse_message(data: bytes) -> PtpMessage:
    """Parse one captured datagram into a :class:`PtpMessage`.

    Raises :class:`MalformedPacket` for structurally invalid datagrams and
    :class:`UnsupportedMessageType` for well-formed PTP messages that are not
    part of a delay-request exchange.
    """
    if len(data) < HEADER_LENGTH:
        raise MalformedPacket(
            f"datagram of {len(data)} bytes is shorter than the 34-byte PTP header"
        )
    version = data[1] & 0x0F
    if version != PTP_VERSION:
        raise MalformedPacket(f"expected PTP version 2, found {version}")
    message_type = data[0] & 0x0F
    if message_type not in MESSAGE_TYPE_NAMES:
        raise UnsupportedMessageType(
            f"messageType 0x{message_type:X} is not part of a delay-request exchange"
        )
    declared_length = int.from_bytes(data[2:4], "big")
    if declared_length != len(data):
        raise MalformedPacket(
            f"messageLength field {declared_length} does not match captured "
            f"length {len(data)}"
        )
    minimum = MIN_MESSAGE_LENGTH[message_type]
    if len(data) < minimum:
        raise MalformedPacket(
            f"{MESSAGE_TYPE_NAMES[message_type]} needs at least {minimum} "
            f"bytes, got {len(data)}"
        )
    correction = int.from_bytes(data[8:16], "big", signed=True)
    source = bytes(data[20:30])
    sequence_id = int.from_bytes(data[30:32], "big")
    timestamp_ns = _parse_timestamp_ns(data, HEADER_LENGTH)
    requesting = None
    if message_type == DELAY_RESP:
        requesting = bytes(data[44:54])
    return PtpMessage(
        message_type=message_type,
        type_name=MESSAGE_TYPE_NAMES[message_type],
        correction=correction,
        source_port_identity=source,
        sequence_id=sequence_id,
        timestamp_ns=timestamp_ns,
        requesting_port_identity=requesting,
    )
