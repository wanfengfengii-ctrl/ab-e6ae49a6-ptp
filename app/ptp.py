"""PTPv2 (IEEE 1588-2008) message parsing and two-step exchange auditing.

Only the four messages of an end-to-end delay four-step exchange are accepted:
Sync (0x0), Follow_Up (0x8), Delay_Req (0x1), Delay_Resp (0x9).

Pairing model
-------------
A completed exchange is identified by
``(masterPortIdentity, slavePortIdentity, sequenceId)``:

* Sync / Follow_Up name the master in the header ``sourcePortIdentity`` and
  form a master-side stream keyed by ``(master, sequenceId)``;
* Delay_Req names the slave (requesting clock) in the header
  ``sourcePortIdentity`` and is held pending by ``(slave, sequenceId)``;
* Delay_Resp names the master in the header and the slave in its body
  ``requestingPortIdentity``; it closes exactly one
  ``(master, slave, sequenceId)`` exchange. A Sync/Follow_Up stream may be
  answered by several slave ports (multicast semantics); the Delay_Resp header
  disambiguates multiple masters answering one slave's Delay_Req.

Capture-stage ordering is strictly
``Sync -> Follow_Up -> Delay_Req -> Delay_Resp``. Byte-for-byte retransmissions
of an already seen message key are allowed and ignored; any other reuse of a
key is a conflict. A reused 16-bit sequenceId within one batch therefore
collides with different bytes and is rejected: rollover aliasing cannot mask
anomalies.

Timing / correction convention (fixed by the audit contract)
-------------------------------------------------------------
``t1`` is the Follow_Up ``preciseOriginTimestamp``, ``t4`` is the
Delay_Resp ``receiveTimestamp`` (embedded nanosecond timestamps); ``t2`` is
the local capture timestamp of the inbound Sync, ``t3`` the local capture
timestamp of the outbound Delay_Req.

``C`` is the *signed* sum of the four ``correctionField`` values (PTP units of
1/65536 ns). With ``A = t2 - t1`` and ``B = t4 - t3`` (integer nanoseconds)::

    offsetFromMasterNumerator = (A - B) * 65536 + C
    meanPathDelayNumerator    = (A + B) * 65536 - C

Both numerators are integer units of the fixed denominator 131072 ns
(= 2 * 65536). A negative path-delay numerator is rejected.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

DENOMINATOR_NS = 131_072
HALF_NS_UNITS = DENOMINATOR_NS // 2  # 65536
PTP_VERSION = 2
HEADER_LEN = 34
MAX_CAPTURES = 1000
UINT64_MAX = (1 << 64) - 1


class MsgType(IntEnum):
    SYNC = 0x0
    DELAY_REQ = 0x1
    FOLLOW_UP = 0x8
    DELAY_RESP = 0x9


class AuditError(Exception):
    """Raised for any audit rejection; ``index`` is the 0-based capture item.

    ``status`` is the HTTP status the API layer uses; ``code`` is the stable,
    machine-readable error identifier.
    """

    def __init__(self, code: str, message: str, index: int, status: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.index = index
        self.status = status


@dataclass(frozen=True)
class PortId:
    clock_identity: bytes  # 8 bytes, EUI-64
    port_number: int

    def as_json(self) -> dict:
        return {
            "clockIdentity": self.clock_identity.hex().upper(),
            "portNumber": self.port_number,
        }


@dataclass
class ParsedMessage:
    msg_type: MsgType
    sequence_id: int
    source: PortId
    correction: int
    domain: int
    raw: bytes
    embedded_ns: Optional[int] = None  # t1 for Follow_Up, t4 for Delay_Resp
    requesting: Optional[PortId] = None  # Delay_Resp body only


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _u16(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "big", signed=False)


def _i64(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 8], "big", signed=True)


def _timestamp_ns(buf: bytes, off: int) -> int:
    seconds = int.from_bytes(buf[off : off + 6], "big", signed=False)
    nanos = int.from_bytes(buf[off + 6 : off + 10], "big", signed=False)
    if nanos >= 1_000_000_000:
        raise ValueError("timestamp nanosecond field out of range")
    return seconds * 1_000_000_000 + nanos


def decode_packet(b64_text: str, index: int) -> bytes:
    if not isinstance(b64_text, str):
        raise AuditError(
            "INVALID_REQUEST", "packet must be a base64 string", index, 400
        )
    try:
        data = base64.b64decode(b64_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuditError(
            "INVALID_BASE64", f"packet is not valid base64: {exc}", index, 400
        ) from exc
    if not data:
        raise AuditError(
            "MALFORMED_PACKET", "decoded packet is empty", index, 400
        )
    return data


def parse_message(data: bytes, index: int) -> ParsedMessage:
    """Validate and parse the audit-relevant fields of one PTPv2 message."""
    if len(data) < HEADER_LEN:
        raise AuditError(
            "MALFORMED_PACKET",
            f"packet shorter than the {HEADER_LEN}-byte PTP header "
            f"(got {len(data)} bytes)",
            index,
            400,
        )

    version = data[1] & 0x0F
    if version != PTP_VERSION:
        raise AuditError(
            "MALFORMED_PACKET",
            f"unsupported PTP version {version}; only version 2 is supported",
            index,
            400,
        )

    declared_len = _u16(data, 2)
    if declared_len != len(data):
        raise AuditError(
            "MALFORMED_PACKET",
            f"header messageLength {declared_len} does not match captured "
            f"length {len(data)}",
            index,
            400,
        )

    type_value = data[0] & 0x0F
    try:
        msg_type = MsgType(type_value)
    except ValueError:
        raise AuditError(
            "UNSUPPORTED_MESSAGE_TYPE",
            f"messageType 0x{type_value:X} is not one of Sync, Follow_Up, "
            "Delay_Req or Delay_Resp",
            index,
        ) from None

    if msg_type is MsgType.FOLLOW_UP and len(data) < 44:
        raise AuditError(
            "MALFORMED_PACKET",
            "Follow_Up is too short to carry preciseOriginTimestamp",
            index,
            400,
        )
    if msg_type is MsgType.DELAY_RESP and len(data) < 54:
        raise AuditError(
            "MALFORMED_PACKET",
            "Delay_Resp is too short to carry receiveTimestamp and "
            "requestingPortIdentity",
            index,
            400,
        )

    source = PortId(
        clock_identity=bytes(data[20:28]), port_number=_u16(data, 28)
    )

    # In a two-step exchange the Sync message must carry the twoStepFlag
    # (flagField byte 6, bit 0x02); otherwise its timestamp is embedded and a
    # Follow_Up pairing is invalid.
    two_step = bool(data[6] & 0x02)
    if msg_type is MsgType.SYNC and not two_step:
        raise AuditError(
            "NON_TWO_STEP_MESSAGE",
            "Sync has twoStepFlag clear; only two-step exchanges "
            "(Sync + Follow_Up) are audited",
            index,
        )
    embedded_ns: Optional[int] = None
    requesting: Optional[PortId] = None
    try:
        if msg_type is MsgType.FOLLOW_UP:
            embedded_ns = _timestamp_ns(data, 34)
        elif msg_type is MsgType.DELAY_RESP:
            # Body: receiveTimestamp(10 bytes) then requestingPortIdentity(10)
            embedded_ns = _timestamp_ns(data, 34)
            requesting = PortId(
                clock_identity=bytes(data[44:52]),
                port_number=_u16(data, 52),
            )
    except ValueError as exc:
        raise AuditError(
            "MALFORMED_PACKET", f"invalid embedded timestamp: {exc}", index, 400
        ) from exc

    return ParsedMessage(
        msg_type=msg_type,
        sequence_id=_u16(data, 30),
        source=source,
        correction=_i64(data, 8),
        domain=data[4],
        raw=data,
        embedded_ns=embedded_ns,
        requesting=requesting,
    )


# --------------------------------------------------------------------------- #
# Audit state machine
# --------------------------------------------------------------------------- #
_INBOUND_TYPES = frozenset(
    {MsgType.SYNC, MsgType.FOLLOW_UP, MsgType.DELAY_RESP}
)


@dataclass
class _MasterStream:
    master: PortId
    sequence_id: int
    domain: int
    sync_correction: int
    t2_ns: int
    sync_index: int
    follow_seen: bool = False
    follow_correction: int = 0
    t1_ns: Optional[int] = None
    follow_index: int = -1
    completed_slaves: set[PortId] = field(default_factory=set)


@dataclass
class _PendingDelayReq:
    slave: PortId
    sequence_id: int
    local_ns: int
    correction: int
    domain: int
    index: int
    answered: bool = False


def _check_direction(msg: ParsedMessage, direction: str, index: int) -> None:
    expected = "in" if msg.msg_type in _INBOUND_TYPES else "out"
    if direction != expected:
        raise AuditError(
            "DIRECTION_MISMATCH",
            f"{msg.msg_type.name} must be captured as direction '{expected}', "
            f"got '{direction}'",
            index,
        )


def _finish(
    stream: _MasterStream,
    slave: PortId,
    dreq: _PendingDelayReq,
    dresp: ParsedMessage,
    index: int,
) -> dict:
    a = stream.t2_ns - stream.t1_ns  # type: ignore[operator]
    b = dresp.embedded_ns - dreq.local_ns  # type: ignore[operator]
    corr_sum = (
        stream.sync_correction
        + stream.follow_correction
        + dreq.correction
        + dresp.correction
    )
    offset_num = (a - b) * HALF_NS_UNITS + corr_sum
    delay_num = (a + b) * HALF_NS_UNITS - corr_sum
    if delay_num < 0:
        raise AuditError(
            "NEGATIVE_PATH_DELAY",
            f"mean path delay numerator {delay_num} / {DENOMINATOR_NS} ns is "
            "negative; the link measurements are impossible",
            index,
        )
    return {
        "sequenceId": stream.sequence_id,
        "masterPortIdentity": stream.master.as_json(),
        "slavePortIdentity": slave.as_json(),
        "domainNumber": stream.domain,
        "offsetFromMasterNumerator": offset_num,
        "meanPathDelayNumerator": delay_num,
        "correctionFieldSum": corr_sum,
        "denominatorNs": DENOMINATOR_NS,
        "syncCaptureIndex": stream.sync_index,
        "completedAtCaptureIndex": index,
    }


def _validate_record(rec: object, index: int) -> tuple[str, str, int]:
    if not isinstance(rec, dict):
        raise AuditError(
            "INVALID_REQUEST", "capture item must be an object", index, 400
        )
    missing = {"packet", "direction", "localTimestampNs"} - rec.keys()
    extra = rec.keys() - {"packet", "direction", "localTimestampNs"}
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {sorted(missing)}")
        if extra:
            detail.append(f"unexpected {sorted(extra)}")
        raise AuditError(
            "INVALID_REQUEST",
            "capture item must contain exactly packet, direction and "
            "localTimestampNs (" + "; ".join(detail) + ")",
            index,
            400,
        )
    direction = rec["direction"]
    if direction not in ("in", "out"):
        raise AuditError(
            "INVALID_REQUEST",
            "direction must be 'in' or 'out'",
            index,
            400,
        )
    local_ns = rec["localTimestampNs"]
    if not isinstance(local_ns, int) or isinstance(local_ns, bool):
        raise AuditError(
            "INVALID_REQUEST",
            "localTimestampNs must be an integer number of nanoseconds",
            index,
            400,
        )
    if local_ns < 0 or local_ns > UINT64_MAX:
        raise AuditError(
            "INVALID_REQUEST",
            "localTimestampNs must be within the uint64 nanosecond range",
            index,
            400,
        )
    return rec["packet"], direction, local_ns


def audit_captures(captures: object) -> list[dict]:
    """Audit capture records given in capture order.

    Each record is a mapping with keys ``packet`` (base64 str), ``direction``
    ("in"/"out") and ``localTimestampNs`` (non-negative uint64 int).

    Returns completed exchanges ordered by completion (Delay_Resp) capture
    position. Raises ``AuditError`` on the first violation; no partial results
    are returned.
    """
    if not isinstance(captures, list):
        raise AuditError(
            "INVALID_REQUEST", "captures must be a list", 0, status=400
        )
    if not 1 <= len(captures) <= MAX_CAPTURES:
        raise AuditError(
            "INVALID_REQUEST",
            f"captures length must be between 1 and {MAX_CAPTURES}, got "
            f"{len(captures)}",
            0,
            400,
        )

    streams: dict[tuple[PortId, int], _MasterStream] = {}
    pending_dreq: dict[tuple[PortId, int], _PendingDelayReq] = {}
    completed: list[dict] = []
    # Every observed message key mapped to its exact bytes; this is the
    # retransmission/conflict ledger.
    seen: dict[tuple, bytes] = {}

    for index, rec in enumerate(captures):
        b64_text, direction, local_ns = _validate_record(rec, index)
        data = decode_packet(b64_text, index)
        msg = parse_message(data, index)
        _check_direction(msg, direction, index)

        mtype = msg.msg_type
        seq = msg.sequence_id

        if mtype is MsgType.DELAY_RESP:
            dedup_key = (mtype, msg.source, msg.requesting, seq)
        else:
            dedup_key = (mtype, msg.source, seq)

        previous = seen.get(dedup_key)
        if previous is not None:
            if previous != data:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    f"{mtype.name} with the same port identity/sequenceId key "
                    f"(seq {seq}) was already captured with different bytes",
                    index,
                )
            # Byte-identical retransmission: allowed, state unchanged.
            continue

        if mtype is MsgType.SYNC:
            key = (msg.source, seq)
            if key in streams:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    f"Sync seq {seq} from this master port reuses an existing "
                    "identity/sequenceId key with different bytes (16-bit "
                    "rollover aliasing is rejected within a batch)",
                    index,
                )
            streams[key] = _MasterStream(
                master=msg.source,
                sequence_id=seq,
                domain=msg.domain,
                sync_correction=msg.correction,
                t2_ns=local_ns,
                sync_index=index,
            )
            seen[dedup_key] = data

        elif mtype is MsgType.FOLLOW_UP:
            stream = streams.get((msg.source, seq))
            if stream is None:
                raise AuditError(
                    "ORPHAN_MESSAGE",
                    f"Follow_Up seq {seq} has no preceding Sync from the same "
                    "master port identity",
                    index,
                )
            if stream.follow_seen:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    f"Follow_Up seq {seq} for this master was already "
                    "captured with different bytes",
                    index,
                )
            if msg.domain != stream.domain:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    "Follow_Up domainNumber does not match the Sync",
                    index,
                )
            stream.follow_seen = True
            stream.follow_correction = msg.correction
            stream.t1_ns = msg.embedded_ns
            stream.follow_index = index
            seen[dedup_key] = data

        elif mtype is MsgType.DELAY_REQ:
            key = (msg.source, seq)
            if key in pending_dreq:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    f"Delay_Req seq {seq} from this slave port was already "
                    "captured with different bytes",
                    index,
                )
            same_seq = [s for s in streams.values() if s.sequence_id == seq]
            if not same_seq:
                raise AuditError(
                    "ORPHAN_MESSAGE",
                    f"Delay_Req seq {seq} has no preceding Sync to answer it",
                    index,
                )
            if not any(s.follow_seen for s in same_seq):
                raise AuditError(
                    "OUT_OF_ORDER_STAGE",
                    f"Delay_Req seq {seq} arrived before the Follow_Up of its "
                    "exchange",
                    index,
                )
            pending_dreq[key] = _PendingDelayReq(
                slave=msg.source,
                sequence_id=seq,
                local_ns=local_ns,
                correction=msg.correction,
                domain=msg.domain,
                index=index,
            )
            seen[dedup_key] = data

        else:  # Delay_Resp
            assert mtype is MsgType.DELAY_RESP
            stream = streams.get((msg.source, seq))
            if stream is None:
                raise AuditError(
                    "ORPHAN_MESSAGE",
                    f"Delay_Resp seq {seq} has no preceding Sync/Follow_Up "
                    "from this master port identity",
                    index,
                )
            dreq = pending_dreq.get((msg.requesting, seq))
            if dreq is None:
                raise AuditError(
                    "ORPHAN_MESSAGE",
                    f"Delay_Resp seq {seq} has no preceding Delay_Req from "
                    "its requestingPortIdentity",
                    index,
                )
            if not stream.follow_seen:
                raise AuditError(
                    "OUT_OF_ORDER_STAGE",
                    f"Delay_Resp seq {seq} arrived before Follow_Up",
                    index,
                )
            if msg.requesting in stream.completed_slaves:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    f"exchange (master, slave, seq {seq}) is already closed "
                    "and the new Delay_Resp has different bytes",
                    index,
                )
            if msg.domain != stream.domain:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    "Delay_Resp domainNumber does not match the Sync/Follow_Up",
                    index,
                )
            if dreq.domain != stream.domain:
                raise AuditError(
                    "CONFLICTING_MESSAGE",
                    "Delay_Req domainNumber does not match the exchange",
                    dreq.index,
                )
            result = _finish(stream, msg.requesting, dreq, msg, index)
            stream.completed_slaves.add(msg.requesting)
            dreq.answered = True
            completed.append(result)
            seen[dedup_key] = data

    # Nothing may be left dangling. Report the earliest offending capture.
    earliest: Optional[AuditError] = None

    def consider(err: AuditError) -> None:
        nonlocal earliest
        if earliest is None or err.index < earliest.index:
            earliest = err

    for stream in streams.values():
        if not stream.completed_slaves:
            if not stream.follow_seen:
                reason = "missing Follow_Up/Delay_Req/Delay_Resp"
            else:
                reason = "missing Delay_Req/Delay_Resp"
            consider(
                AuditError(
                    "UNCLOSED_EXCHANGE",
                    f"master stream seq {stream.sequence_id} is unclosed "
                    f"({reason})",
                    stream.sync_index,
                )
            )
    for dreq in pending_dreq.values():
        if not dreq.answered:
            consider(
                AuditError(
                    "UNCLOSED_EXCHANGE",
                    f"Delay_Req seq {dreq.sequence_id} from slave port "
                    f"{dreq.slave.clock_identity.hex().upper()}:"
                    f"{dreq.slave.port_number} is not answered by a Delay_Resp",
                    dreq.index,
                )
            )
    if earliest is not None:
        raise earliest

    return completed
