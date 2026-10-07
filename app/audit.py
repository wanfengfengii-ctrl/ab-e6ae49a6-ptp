"""Pair PTPv2 two-step messages into closed four-step exchanges.

Captures are processed strictly in submission order.  An exchange is keyed by
the master port identity and the 16-bit sequence id and must run through the
phases Sync -> Follow_Up -> Delay_Req -> Delay_Resp.  Byte-identical
retransmissions are tolerated; any other reuse of a key while its exchange is
open is a conflict.  A sequence id may be reused for a fresh exchange only
after the previous exchange with the same key has closed, which is how 16-bit
sequence wraparound is handled.

Both reported quantities are integer numerators over a fixed denominator of
131072 (2**17) nanoseconds.  With t1..t4 in nanoseconds and C the sum of the
four signed correctionField values (units of 2**-16 ns):

    offsetNumerator        = ((t2 - t1) - (t4 - t3)) * 65536 - C
    meanPathDelayNumerator = ((t2 - t1) + (t4 - t3)) * 65536 - C

where t1 is the Follow_Up preciseOriginTimestamp, t2 the local receive time
of Sync, t3 the local send time of Delay_Req and t4 the Delay_Resp
receiveTimestamp.  A negative mean path delay numerator is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ptp import (
    DELAY_REQ,
    DELAY_RESP,
    FOLLOW_UP,
    SYNC,
    PtpMessage,
    format_port_identity,
)

DENOMINATOR = 131072  # 2**17 ns; reported quantities are numerators over this
CORRECTION_UNITS_PER_NS = 65536  # correctionField is scaled in 2**-16 ns units

RX = "rx"
TX = "tx"

# The capture point sits at the slave: Sync/Follow_Up/Delay_Resp arrive from
# the master, Delay_Req leaves towards it.
EXPECTED_DIRECTION = {
    SYNC: RX,
    FOLLOW_UP: RX,
    DELAY_REQ: TX,
    DELAY_RESP: RX,
}

_PHASE_AWAITING_FOLLOW_UP = 0
_PHASE_AWAITING_DELAY_REQ = 1
_PHASE_AWAITING_DELAY_RESP = 2
_PHASE_COMPLETED = 3


class AuditError(Exception):
    """Semantic audit failure tied to a capture position.

    ``capture_index`` is the 0-based position of the first capture item
    relevant to the failure.
    """

    code = "AUDIT_ERROR"

    def __init__(self, message: str, capture_index: int) -> None:
        super().__init__(message)
        self.message = message
        self.capture_index = capture_index


class ConflictingMessage(AuditError):
    code = "CONFLICTING_MESSAGE"


class OrphanResponse(AuditError):
    code = "ORPHAN_RESPONSE"


class OutOfOrderPhase(AuditError):
    code = "OUT_OF_ORDER_PHASE"


class UnclosedExchange(AuditError):
    code = "UNCLOSED_EXCHANGE"


class NegativePathDelay(AuditError):
    code = "NEGATIVE_PATH_DELAY"


class UnexpectedDirection(AuditError):
    code = "UNEXPECTED_DIRECTION"


@dataclass
class _Recorded:
    capture_index: int
    packet: bytes
    local_time_ns: int
    correction: int
    timestamp_ns: int


@dataclass
class _Exchange:
    master: bytes
    sequence_id: int
    first_index: int
    sync: _Recorded | None = None
    follow_up: _Recorded | None = None
    delay_req: _Recorded | None = None
    delay_resp: _Recorded | None = None
    slave: bytes | None = None
    t1: int = 0
    t2: int = 0
    t3: int = 0
    t4: int = 0

    @property
    def phase(self) -> int:
        if self.delay_resp is not None:
            return _PHASE_COMPLETED
        if self.delay_req is not None:
            return _PHASE_AWAITING_DELAY_RESP
        if self.follow_up is not None:
            return _PHASE_AWAITING_DELAY_REQ
        return _PHASE_AWAITING_FOLLOW_UP

    @property
    def completed(self) -> bool:
        return self.delay_resp is not None


class Auditor:
    """Stateful pairing of captured messages into four-step exchanges."""

    def __init__(self) -> None:
        # Latest exchange instance per (master identity, sequence id).
        self._current: dict[tuple[bytes, int], _Exchange] = {}
        # Every exchange instance per sequence id, in creation order.
        self._by_sequence: dict[int, list[_Exchange]] = {}
        # Verdicts in exchange completion order.
        self.results: list[dict] = []

    def process(
        self,
        capture_index: int,
        message: PtpMessage,
        packet: bytes,
        direction: str,
        local_time_ns: int,
    ) -> None:
        expected = EXPECTED_DIRECTION[message.message_type]
        if direction != expected:
            raise UnexpectedDirection(
                f"{message.type_name} must be captured with direction "
                f"'{expected}', got '{direction}'",
                capture_index,
            )
        if message.message_type == SYNC:
            self._on_sync(capture_index, message, packet, local_time_ns)
        elif message.message_type == FOLLOW_UP:
            self._on_follow_up(capture_index, message, packet, local_time_ns)
        elif message.message_type == DELAY_REQ:
            self._on_delay_req(capture_index, message, packet, local_time_ns)
        else:
            self._on_delay_resp(capture_index, message, packet, local_time_ns)

    def finalize(self) -> list[dict]:
        unclosed = [
            exchange.first_index
            for instances in self._by_sequence.values()
            for exchange in instances
            if not exchange.completed
        ]
        if unclosed:
            raise UnclosedExchange(
                "capture ended before all four phases of the exchange were "
                "observed",
                min(unclosed),
            )
        return self.results

    # -- phase handlers --------------------------------------------------

    def _instances(self, master: bytes, sequence_id: int) -> list[_Exchange]:
        return [
            ex
            for ex in self._by_sequence.get(sequence_id, ())
            if ex.master == master
        ]

    def _on_sync(
        self, index: int, message: PtpMessage, packet: bytes, local_time_ns: int
    ) -> None:
        master = message.source_port_identity
        key = (master, message.sequence_id)
        for ex in self._instances(master, message.sequence_id):
            if ex.sync is not None and ex.sync.packet == packet:
                return  # byte-identical retransmission
        current = self._current.get(key)
        if current is not None and not current.completed:
            raise ConflictingMessage(
                f"Sync for master {format_port_identity(master)} sequence "
                f"{message.sequence_id} conflicts with the exchange already open",
                index,
            )
        exchange = _Exchange(
            master=master, sequence_id=message.sequence_id, first_index=index
        )
        exchange.sync = _Recorded(
            index, packet, local_time_ns, message.correction, message.timestamp_ns
        )
        exchange.t2 = local_time_ns
        self._current[key] = exchange
        self._by_sequence.setdefault(message.sequence_id, []).append(exchange)

    def _on_follow_up(
        self, index: int, message: PtpMessage, packet: bytes, local_time_ns: int
    ) -> None:
        master = message.source_port_identity
        key = (master, message.sequence_id)
        for ex in self._instances(master, message.sequence_id):
            if ex.follow_up is not None and ex.follow_up.packet == packet:
                return  # byte-identical retransmission
        current = self._current.get(key)
        if current is None:
            raise OrphanResponse(
                f"Follow_Up for master {format_port_identity(master)} sequence "
                f"{message.sequence_id} has no preceding Sync",
                index,
            )
        if current.follow_up is not None:
            raise ConflictingMessage(
                f"Follow_Up for master {format_port_identity(master)} sequence "
                f"{message.sequence_id} conflicts with the one already recorded",
                index,
            )
        current.follow_up = _Recorded(
            index, packet, local_time_ns, message.correction, message.timestamp_ns
        )
        current.t1 = message.timestamp_ns

    def _on_delay_req(
        self, index: int, message: PtpMessage, packet: bytes, local_time_ns: int
    ) -> None:
        slave = message.source_port_identity
        instances = self._by_sequence.get(message.sequence_id, ())
        for ex in instances:
            if ex.delay_req is not None and ex.delay_req.packet == packet:
                return  # byte-identical retransmission
        for ex in instances:
            if ex.delay_req is not None and not ex.completed and ex.slave == slave:
                raise ConflictingMessage(
                    f"Delay_Req from slave {format_port_identity(slave)} sequence "
                    f"{message.sequence_id} conflicts with the one already recorded",
                    index,
                )
        candidates = [
            ex for ex in instances if ex.phase == _PHASE_AWAITING_DELAY_REQ
        ]
        if len(candidates) > 1:
            raise ConflictingMessage(
                f"Delay_Req from slave {format_port_identity(slave)} sequence "
                f"{message.sequence_id} matches more than one open exchange",
                index,
            )
        if not candidates:
            raise OutOfOrderPhase(
                f"Delay_Req from slave {format_port_identity(slave)} sequence "
                f"{message.sequence_id} arrived before the matching "
                "Sync/Follow_Up pair completed",
                index,
            )
        exchange = candidates[0]
        exchange.delay_req = _Recorded(
            index, packet, local_time_ns, message.correction, message.timestamp_ns
        )
        exchange.slave = slave
        exchange.t3 = local_time_ns

    def _on_delay_resp(
        self, index: int, message: PtpMessage, packet: bytes, local_time_ns: int
    ) -> None:
        master = message.source_port_identity
        requesting = message.requesting_port_identity
        instances = self._by_sequence.get(message.sequence_id, ())
        for ex in instances:
            if ex.delay_resp is not None and ex.delay_resp.packet == packet:
                return  # byte-identical retransmission
        for ex in instances:
            if (
                ex.phase == _PHASE_AWAITING_DELAY_RESP
                and ex.master == master
                and ex.slave == requesting
            ):
                ex.delay_resp = _Recorded(
                    index, packet, local_time_ns, message.correction,
                    message.timestamp_ns,
                )
                ex.t4 = message.timestamp_ns
                self._complete(ex, index)
                return
        for ex in instances:
            if (
                ex.delay_resp is not None
                and ex.master == master
                and ex.slave == requesting
            ):
                raise ConflictingMessage(
                    f"Delay_Resp from master {format_port_identity(master)} "
                    f"sequence {message.sequence_id} conflicts with the one "
                    "already recorded",
                    index,
                )
        raise OrphanResponse(
            f"Delay_Resp from master {format_port_identity(master)} for requester "
            f"{format_port_identity(requesting)} sequence {message.sequence_id} "
            "has no pending Delay_Req",
            index,
        )

    def _complete(self, exchange: _Exchange, index: int) -> None:
        correction_sum = (
            exchange.sync.correction
            + exchange.follow_up.correction
            + exchange.delay_req.correction
            + exchange.delay_resp.correction
        )
        forward = exchange.t2 - exchange.t1
        backward = exchange.t4 - exchange.t3
        offset_numerator = (
            forward - backward
        ) * CORRECTION_UNITS_PER_NS - correction_sum
        mean_path_delay_numerator = (
            forward + backward
        ) * CORRECTION_UNITS_PER_NS - correction_sum
        if mean_path_delay_numerator < 0:
            raise NegativePathDelay(
                f"exchange sequence {exchange.sequence_id} yields a negative "
                "mean path delay",
                exchange.first_index,
            )
        self.results.append(
            {
                "sequenceId": exchange.sequence_id,
                "masterPortIdentity": format_port_identity(exchange.master),
                "slavePortIdentity": format_port_identity(exchange.slave),
                "firstCaptureIndex": exchange.first_index,
                "completedCaptureIndex": index,
                "correctionFieldSum": correction_sum,
                "offsetNumerator": offset_numerator,
                "meanPathDelayNumerator": mean_path_delay_numerator,
            }
        )
