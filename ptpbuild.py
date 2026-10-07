"""Minimal IEEE 1588-2008 PTPv2 message builder used by tests and smoke checks.

This is deliberately small: it emits exactly the header plus the body fields
the auditor parses, and allows every field to be tampered with for negative
tests.
"""

from __future__ import annotations

import base64
from typing import Optional

SYNC = 0x0
DELAY_REQ = 0x1
FOLLOW_UP = 0x8
DELAY_RESP = 0x9

# controlField values from the standard (informational)
_CONTROL = {
    SYNC: 0x00,
    DELAY_REQ: 0x01,
    FOLLOW_UP: 0x02,
    DELAY_RESP: 0x03,
}

_HEADER_LEN = 34


def port_identity(clock: bytes | int, port: int = 1) -> tuple[bytes, int]:
    if isinstance(clock, int):
        clock = clock.to_bytes(8, "big")
    if len(clock) != 8:
        raise ValueError("clockIdentity must be 8 bytes")
    return clock, port


def _timestamp(ns: int) -> bytes:
    seconds, nanos = divmod(ns, 1_000_000_000)
    return seconds.to_bytes(6, "big") + nanos.to_bytes(4, "big")


def build_message(
    msg_type: int,
    seq: int,
    source: tuple[bytes, int],
    *,
    correction: int = 0,
    domain: int = 0,
    origin_ns: Optional[int] = None,
    receive_ns: Optional[int] = None,
    requesting: Optional[tuple[bytes, int]] = None,
    version: int = 2,
    declared_length: Optional[int] = None,
    extra: bytes = b"",
    flags: Optional[int] = None,
) -> bytes:
    """Return a raw PTPv2 message."""
    clock, port = source
    body = b""
    if msg_type == FOLLOW_UP:
        if origin_ns is None:
            raise ValueError("Follow_Up needs origin_ns (t1)")
        body = _timestamp(origin_ns)
    elif msg_type == DELAY_RESP:
        if receive_ns is None or requesting is None:
            raise ValueError("Delay_Resp needs receive_ns (t4) and requesting")
        req_clock, req_port = requesting
        body = _timestamp(receive_ns) + req_clock + req_port.to_bytes(2, "big")

    length = declared_length if declared_length is not None else (
        _HEADER_LEN + len(body) + len(extra)
    )
    hdr = bytearray(_HEADER_LEN)
    hdr[0] = msg_type & 0x0F
    hdr[1] = version & 0x0F
    hdr[2:4] = length.to_bytes(2, "big")
    hdr[4] = domain
    # twoStepFlag is bit 1 of the first flagField byte (byte 6).
    if flags is None:
        flags = 0x02 if msg_type in (SYNC, FOLLOW_UP) else 0
    hdr[6] = flags & 0xFF
    hdr[8:16] = correction.to_bytes(8, "big", signed=True)
    hdr[20:28] = clock
    hdr[28:30] = port.to_bytes(2, "big")
    hdr[30:32] = seq.to_bytes(2, "big")
    hdr[32] = _CONTROL.get(msg_type, 0)
    hdr[33] = 0x7F  # logMessageInterval, irrelevant to the audit
    return bytes(hdr) + body + extra


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def exchange_captures(
    seq: int = 7,
    master: tuple[bytes, int] | None = None,
    slave: tuple[bytes, int] | None = None,
    *,
    t1_ns: int = 0,
    t2_ns: int = 1_000_000_000,
    t3_ns: int = 2_000_000_000,
    t4_ns: int = 3_000_000_000,
    corrections: tuple[int, int, int, int] = (0, 0, 0, 0),
    domain: int = 0,
) -> list[dict]:
    """Four capture records forming one complete, valid exchange."""
    if master is None:
        master = port_identity(0x0011223344556677, 1)
    if slave is None:
        slave = port_identity(0xAABBCCDDEEFF0011, 2)
    c_sync, c_follow, c_dreq, c_dresp = corrections
    return [
        {
            "packet": b64(
                build_message(SYNC, seq, master, correction=c_sync, domain=domain)
            ),
            "direction": "in",
            "localTimestampNs": t2_ns,
        },
        {
            "packet": b64(
                build_message(
                    FOLLOW_UP,
                    seq,
                    master,
                    correction=c_follow,
                    origin_ns=t1_ns,
                    domain=domain,
                )
            ),
            "direction": "in",
            "localTimestampNs": t1_ns,
        },
        {
            "packet": b64(
                build_message(
                    DELAY_REQ, seq, slave, correction=c_dreq, domain=domain
                )
            ),
            "direction": "out",
            "localTimestampNs": t3_ns,
        },
        {
            "packet": b64(
                build_message(
                    DELAY_RESP,
                    seq,
                    master,
                    correction=c_dresp,
                    receive_ns=t4_ns,
                    requesting=slave,
                    domain=domain,
                )
            ),
            "direction": "in",
            "localTimestampNs": t4_ns,
        },
    ]
