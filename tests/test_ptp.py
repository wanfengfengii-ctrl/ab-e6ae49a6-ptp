import pytest

from app.ptp import (
    DELAY_RESP,
    FOLLOW_UP,
    SYNC,
    MalformedPacket,
    UnsupportedMessageType,
    format_port_identity,
    parse_message,
)
from tests.builders import (
    MASTER_IDENTITY,
    SLAVE_IDENTITY,
    build_message,
)


def test_parse_sync_fields():
    packet = build_message(SYNC, sequence_id=7, correction=-5, timestamp_ns=123)
    msg = parse_message(packet)
    assert msg.message_type == SYNC
    assert msg.type_name == "Sync"
    assert msg.correction == -5
    assert msg.sequence_id == 7
    assert msg.source_port_identity == MASTER_IDENTITY
    assert msg.timestamp_ns == 123
    assert msg.requesting_port_identity is None


def test_parse_delay_resp_requesting_identity():
    packet = build_message(
        DELAY_RESP, sequence_id=9, correction=65536, timestamp_ns=10**12 + 5
    )
    msg = parse_message(packet)
    assert msg.message_type == DELAY_RESP
    assert msg.correction == 65536
    assert msg.timestamp_ns == 10**12 + 5
    assert msg.requesting_port_identity == SLAVE_IDENTITY


def test_parse_timestamp_splits_seconds_and_nanos():
    packet = build_message(FOLLOW_UP, timestamp_ns=123 * 10**9 + 456)
    assert parse_message(packet).timestamp_ns == 123 * 10**9 + 456


def test_format_port_identity():
    assert format_port_identity(MASTER_IDENTITY) == "0011223344556677:2"
    assert format_port_identity(SLAVE_IDENTITY) == "aabbccddeeff0011:1"


def test_truncated_datagram_rejected():
    with pytest.raises(MalformedPacket):
        parse_message(b"\x00" * 20)


def test_wrong_version_rejected():
    packet = bytearray(build_message(SYNC))
    packet[1] = 0x03
    with pytest.raises(MalformedPacket):
        parse_message(bytes(packet))


def test_unsupported_message_type_rejected():
    packet = bytearray(build_message(SYNC))
    packet[0] = 0x0B  # Announce
    with pytest.raises(UnsupportedMessageType) as excinfo:
        parse_message(bytes(packet))
    assert excinfo.value.code == "UNSUPPORTED_MESSAGE_TYPE"


def test_message_length_mismatch_rejected():
    packet = bytearray(build_message(SYNC))
    packet[2:4] = (44).to_bytes(2, "big")
    packet.extend(b"\x00")  # captured 45 bytes, header still says 44
    with pytest.raises(MalformedPacket):
        parse_message(bytes(packet))


def test_truncated_body_rejected():
    packet = build_message(SYNC)[:40]
    with pytest.raises(MalformedPacket):
        parse_message(packet)


def test_nanoseconds_out_of_range_rejected():
    packet = bytearray(build_message(SYNC))
    packet[40:44] = (1_000_000_000).to_bytes(4, "big")
    with pytest.raises(MalformedPacket):
        parse_message(bytes(packet))


def test_correction_field_is_signed():
    packet = build_message(SYNC, correction=-(2**62))
    assert parse_message(packet).correction == -(2**62)
