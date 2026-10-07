"""Craft PTPv2 datagrams and capture items for tests and the smoke check."""

from __future__ import annotations

import base64

from app.ptp import DELAY_REQ, DELAY_RESP, FOLLOW_UP, SYNC

MASTER_CLOCK_IDENTITY = bytes.fromhex("0011223344556677")
SLAVE_CLOCK_IDENTITY = bytes.fromhex("aabbccddeeff0011")
MASTER_PORT = 2
SLAVE_PORT = 1
MASTER_IDENTITY = MASTER_CLOCK_IDENTITY + MASTER_PORT.to_bytes(2, "big")
SLAVE_IDENTITY = SLAVE_CLOCK_IDENTITY + SLAVE_PORT.to_bytes(2, "big")

_CONTROL_FIELD = {SYNC: 0, DELAY_REQ: 1, FOLLOW_UP: 2, DELAY_RESP: 3}
_TWO_STEP_FLAG = 0x0200


def build_message(
    message_type: int,
    *,
    source: bytes = MASTER_IDENTITY,
    sequence_id: int = 1,
    correction: int = 0,
    timestamp_ns: int = 0,
    requesting: bytes | None = None,
    domain: int = 0,
) -> bytes:
    seconds, nanos = divmod(timestamp_ns, 1_000_000_000)
    body = seconds.to_bytes(6, "big") + nanos.to_bytes(4, "big")
    if message_type == DELAY_RESP:
        body += requesting if requesting is not None else SLAVE_IDENTITY
    header = b"".join(
        [
            bytes([message_type & 0x0F, 0x02]),
            (34 + len(body)).to_bytes(2, "big"),
            bytes([domain, 0]),
            _TWO_STEP_FLAG.to_bytes(2, "big"),
            correction.to_bytes(8, "big", signed=True),
            b"\x00" * 4,
            source,
            sequence_id.to_bytes(2, "big"),
            bytes([_CONTROL_FIELD.get(message_type, 0), 0x7F]),
        ]
    )
    return header + body


def capture_item(packet: bytes, direction: str, local_time_ns: int) -> dict:
    return {
        "packet": base64.b64encode(packet).decode("ascii"),
        "direction": direction,
        "localTimeNs": local_time_ns,
    }


def exchange_captures(
    *,
    sequence_id: int,
    t1: int = 1_000_500_000_000,
    t2: int | None = None,
    t3: int | None = None,
    t4: int | None = None,
    corrections: tuple[int, int, int, int] = (0, 0, 0, 0),
    master: bytes = MASTER_IDENTITY,
    slave: bytes = SLAVE_IDENTITY,
) -> list[dict]:
    """Build the four capture items of a complete two-step exchange.

    Defaults describe a symmetric link: forward and backward deltas are both
    1000 ns, so the offset is zero and the mean path delay is 1000 ns.
    """
    t2 = t1 + 1_000 if t2 is None else t2
    t3 = t2 + 1_000 if t3 is None else t3
    t4 = t3 + 1_000 if t4 is None else t4
    c_sync, c_follow_up, c_delay_req, c_delay_resp = corrections
    return [
        capture_item(
            build_message(
                SYNC,
                source=master,
                sequence_id=sequence_id,
                correction=c_sync,
                timestamp_ns=t1,
            ),
            "rx",
            t2,
        ),
        capture_item(
            build_message(
                FOLLOW_UP,
                source=master,
                sequence_id=sequence_id,
                correction=c_follow_up,
                timestamp_ns=t1,
            ),
            "rx",
            t2 + 10,
        ),
        capture_item(
            build_message(
                DELAY_REQ,
                source=slave,
                sequence_id=sequence_id,
                correction=c_delay_req,
                timestamp_ns=t3,
            ),
            "tx",
            t3,
        ),
        capture_item(
            build_message(
                DELAY_RESP,
                source=master,
                sequence_id=sequence_id,
                correction=c_delay_resp,
                timestamp_ns=t4,
                requesting=slave,
            ),
            "rx",
            t3 + 10,
        ),
    ]
