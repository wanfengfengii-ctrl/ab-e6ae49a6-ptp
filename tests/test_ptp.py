"""Unit tests for the PTPv2 parser/auditor state machine."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ptp import (  # noqa: E402
    DENOMINATOR_NS,
    AuditError,
    MsgType,
    PortId,
    audit_captures,
    decode_packet,
    parse_message,
)
from ptpbuild import (  # noqa: E402
    DELAY_REQ,
    DELAY_RESP,
    FOLLOW_UP,
    SYNC,
    b64,
    build_message,
    exchange_captures,
    port_identity,
)

MASTER = port_identity(0x0011223344556677, 1)
SLAVE = port_identity(0xAABBCCDDEEFF0011, 2)
OTHER_MASTER = port_identity(0x1111111111111111, 3)


def audit(captures):
    return audit_captures(captures)


# --------------------------------------------------------------------------- #
# Happy path / arithmetic
# --------------------------------------------------------------------------- #
def test_complete_exchange_basic():
    # symmetric 1 ms path, zero offset, no corrections
    # A = t2-t1 = 1e9 ; B = t4-t3 = 1e9
    results = audit(exchange_captures(seq=10))
    assert len(results) == 1
    r = results[0]
    assert r["sequenceId"] == 10
    assert r["denominatorNs"] == 131072
    assert r["offsetFromMasterNumerator"] == 0
    assert r["meanPathDelayNumerator"] == 2 * 1_000_000_000 * 65536
    assert r["syncCaptureIndex"] == 0
    assert r["completedAtCaptureIndex"] == 3
    assert r["masterPortIdentity"]["portNumber"] == 1
    assert r["slavePortIdentity"]["portNumber"] == 2


def test_offset_and_corrections():
    # A = 20 ns, B = 60 ns, C = 40 (1/65536 ns units)
    # offset = (A-B)*65536 + C = -40*65536 + 40 = -2621400
    # delay  = (A+B)*65536 - C = 80*65536 - 40 = 5242840
    caps = exchange_captures(
        seq=3,
        t1_ns=100, t2_ns=120, t3_ns=500, t4_ns=560,
        corrections=(10, 20, -30, 40),
    )
    (r,) = audit(caps)
    assert r["offsetFromMasterNumerator"] == -40 * 65536 + 40
    assert r["meanPathDelayNumerator"] == 80 * 65536 - 40
    assert r["correctionFieldSum"] == 40


def test_signed_correction_summation():
    caps = exchange_captures(
        seq=4, t1_ns=0, t2_ns=10, t3_ns=20, t4_ns=30,
        corrections=(-1000, -2000, 3000, -5),
    )
    (r,) = audit(caps)
    # A=10 B=10 -> offset = -5 ; delay = 20*65536 + 5
    assert r["offsetFromMasterNumerator"] == -5
    assert r["meanPathDelayNumerator"] == 20 * 65536 + 5


def test_zero_path_delay_allowed_but_not_negative():
    caps = exchange_captures(
        seq=5, t1_ns=0, t2_ns=0, t3_ns=0, t4_ns=0,
    )
    (r,) = audit(caps)
    assert r["meanPathDelayNumerator"] == 0
    assert r["offsetFromMasterNumerator"] == 0


def test_negative_path_delay_rejected():
    # A+B = 0 ns, positive correction -> delay numerator negative
    caps = exchange_captures(
        seq=6, t1_ns=0, t2_ns=0, t3_ns=0, t4_ns=0,
        corrections=(10, 0, 0, 0),
    )
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "NEGATIVE_PATH_DELAY"
    assert err.index == 3


def test_results_ordered_by_completion():
    caps = []
    # first stream
    caps += exchange_captures(seq=100)
    # second stream interleaved: closes first actually seq100 closes at idx3;
    # build two separate exchanges, second completes later
    caps += exchange_captures(seq=101, master=port_identity(0x2222222222222222, 9))
    results = audit(caps)
    assert [r["sequenceId"] for r in results] == [100, 101]
    assert results[0]["completedAtCaptureIndex"] == 3
    assert results[1]["completedAtCaptureIndex"] == 7


def test_interleaved_completion_order():
    # seq1 starts, seq2 starts, seq2 finishes, seq1 finishes
    c1 = exchange_captures(seq=1)
    c2 = exchange_captures(seq=2, master=OTHER_MASTER, slave=SLAVE)
    caps = c1[:2] + c2[:2] + c2[2:] + c1[2:]
    results = audit(caps)
    assert [r["sequenceId"] for r in results] == [2, 1]
    assert results[0]["completedAtCaptureIndex"] == 5
    assert results[1]["completedAtCaptureIndex"] == 7


# --------------------------------------------------------------------------- #
# Retransmissions / conflicts
# --------------------------------------------------------------------------- #
def test_byte_identical_retransmissions_allowed():
    base = exchange_captures(seq=20)
    caps = [base[0], base[0], base[1], base[1], base[2], base[3], base[3]]
    (r,) = audit(caps)
    assert r["sequenceId"] == 20
    assert r["completedAtCaptureIndex"] == 5  # index of last distinct packet
    # arithmetic unchanged
    assert r["meanPathDelayNumerator"] == 2 * 1_000_000_000 * 65536


def test_conflicting_same_key_rejected():
    caps = exchange_captures(seq=21)
    # second Sync, same identity/seq, different correction field
    evil = build_message(SYNC, 21, MASTER, correction=123)
    caps.append({"packet": b64(evil), "direction": "in", "localTimestampNs": 9})
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "CONFLICTING_MESSAGE"
    assert err.index == 4


def test_conflicting_followup_timestamps_rejected():
    caps = exchange_captures(seq=22)
    evil = build_message(
        FOLLOW_UP, 22, MASTER, correction=0, origin_ns=123456
    )
    # insert after the real Follow_Up (index 1) -> at index 2
    caps.insert(2, {"packet": b64(evil), "direction": "in", "localTimestampNs": 0})
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "CONFLICTING_MESSAGE"
    assert err.index == 2


def test_conflicting_delay_resp_requesting():
    # Same key (master, requesting slave, seq) but different receive timestamp
    caps = exchange_captures(seq=23)
    evil = build_message(
        DELAY_RESP, 23, MASTER, correction=0,
        receive_ns=9_999_999_999, requesting=SLAVE,
    )
    caps.append({"packet": b64(evil), "direction": "in", "localTimestampNs": 0})
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "CONFLICTING_MESSAGE"
    assert err.index == 4


# --------------------------------------------------------------------------- #
# Ordering / orphan / closure rules
# --------------------------------------------------------------------------- #
def test_followup_without_sync_is_orphan():
    caps = exchange_captures(seq=30)
    err = pytest.raises(AuditError, lambda: audit([caps[1]])).value
    assert err.code == "ORPHAN_MESSAGE"
    assert err.index == 0


def test_delay_resp_without_delay_req_is_orphan():
    caps = exchange_captures(seq=31)
    err = pytest.raises(AuditError, lambda: audit(caps[:2] + [caps[3]])).value
    assert err.code == "ORPHAN_MESSAGE"
    assert err.index == 2


def test_delay_req_before_followup_out_of_order():
    caps = exchange_captures(seq=32)
    err = pytest.raises(AuditError, lambda: audit([caps[0], caps[2]])).value
    assert err.code == "OUT_OF_ORDER_STAGE"
    assert err.index == 1


def test_delay_resp_wrong_master_is_orphan():
    caps = exchange_captures(seq=33)
    evil = build_message(
        DELAY_RESP, 33, OTHER_MASTER,
        receive_ns=3_000_000_000, requesting=SLAVE,
    )
    evil_rec = {"packet": b64(evil), "direction": "in", "localTimestampNs": 0}
    err = pytest.raises(AuditError, lambda: audit(caps[:3] + [evil_rec])).value
    assert err.code == "ORPHAN_MESSAGE"
    assert err.index == 3


def test_delay_resp_wrong_requesting_is_orphan():
    caps = exchange_captures(seq=34)
    other_slave = port_identity(0x9999999999999999, 5)
    evil = build_message(
        DELAY_RESP, 34, MASTER,
        receive_ns=3_000_000_000, requesting=other_slave,
    )
    evil_rec = {"packet": b64(evil), "direction": "in", "localTimestampNs": 0}
    err = pytest.raises(AuditError, lambda: audit(caps[:3] + [evil_rec])).value
    assert err.code == "ORPHAN_MESSAGE"
    assert err.index == 3


def test_unclosed_sync_only():
    caps = exchange_captures(seq=40)
    err = pytest.raises(AuditError, lambda: audit([caps[0]])).value
    assert err.code == "UNCLOSED_EXCHANGE"
    assert err.index == 0


def test_unanswered_delay_req():
    # Sync/Follow_Up/Delay_Req without a Delay_Resp: the first relevant
    # capture is the start of the unclosed exchange (the Sync).
    caps = exchange_captures(seq=41)
    err = pytest.raises(AuditError, lambda: audit(caps[:3])).value
    assert err.code == "UNCLOSED_EXCHANGE"
    assert err.index == 0


def test_orphan_delay_req_position():
    # A Delay_Req with no matching stream at all reports its own position.
    dreq = exchange_captures(seq=44)[2]
    err = pytest.raises(AuditError, lambda: audit([dreq])).value
    assert err.code == "ORPHAN_MESSAGE"
    assert err.index == 0


def test_domain_conflict_rejected():
    caps = exchange_captures(seq=42)
    evil = build_message(
        FOLLOW_UP, 42, MASTER, origin_ns=0, domain=7
    )
    caps[1] = {"packet": b64(evil), "direction": "in", "localTimestampNs": 0}
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "CONFLICTING_MESSAGE"
    assert err.index == 1


def test_direction_mismatch():
    caps = exchange_captures(seq=43)
    caps[2]["direction"] = "in"  # Delay_Req must be outbound
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "DIRECTION_MISMATCH"
    assert err.index == 2


# --------------------------------------------------------------------------- #
# Multiple slaves on same Sync stream (multicast)
# --------------------------------------------------------------------------- #
def test_two_slaves_share_sync_stream():
    slave2 = port_identity(0x8888888888888888, 4)
    caps = exchange_captures(seq=50)
    dreq2 = {
        "packet": b64(build_message(DELAY_REQ, 50, slave2)),
        "direction": "out",
        "localTimestampNs": 2_000_000_000,
    }
    dresp2 = {
        "packet": b64(
            build_message(
                DELAY_RESP, 50, MASTER,
                receive_ns=3_000_000_000, requesting=slave2,
            )
        ),
        "direction": "in",
        "localTimestampNs": 3_000_000_000,
    }
    caps += [dreq2, dresp2]
    results = audit(caps)
    assert len(results) == 2
    assert results[0]["slavePortIdentity"]["portNumber"] == 2
    assert results[1]["slavePortIdentity"]["portNumber"] == 4


# --------------------------------------------------------------------------- #
# Sequence rollover
# --------------------------------------------------------------------------- #
def test_sequence_rollover_distinct_bytes_conflict():
    # Two Sync messages with seq 65535, different correction -> conflict
    s1 = build_message(SYNC, 65535, MASTER, correction=0)
    s2 = build_message(SYNC, 65535, MASTER, correction=1)
    caps = [
        {"packet": b64(s1), "direction": "in", "localTimestampNs": 1},
        {"packet": b64(s2), "direction": "in", "localTimestampNs": 2},
    ]
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    assert err.code == "CONFLICTING_MESSAGE"
    assert err.index == 1


def test_sequence_rollover_same_bytes_is_retransmission():
    s = build_message(SYNC, 65535, MASTER)
    caps = [
        {"packet": b64(s), "direction": "in", "localTimestampNs": 1},
        {"packet": b64(s), "direction": "in", "localTimestampNs": 2},
    ]
    err = pytest.raises(AuditError, lambda: audit(caps)).value
    # identical retransmits allowed, but the exchange is then unclosed
    assert err.code == "UNCLOSED_EXCHANGE"
    assert err.index == 0


# --------------------------------------------------------------------------- #
# Malformed packets / request shape
# --------------------------------------------------------------------------- #
def test_invalid_base64():
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": "@@@not base64", "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "INVALID_BASE64"
    assert err.index == 0
    assert err.status == 400


def test_too_short():
    raw = b"\x00\x02" + b"\x00" * 10
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": b64(raw), "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "MALFORMED_PACKET"


def test_bad_version():
    raw = build_message(SYNC, 1, MASTER, version=1)
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": b64(raw), "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "MALFORMED_PACKET"


def test_unsupported_message_type():
    # Announce = 0xB
    raw = build_message(0xB, 1, MASTER)
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": b64(raw), "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "UNSUPPORTED_MESSAGE_TYPE"


def test_declared_length_mismatch():
    raw = build_message(SYNC, 1, MASTER, declared_length=99)
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": b64(raw), "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "MALFORMED_PACKET"


def test_record_shape_validation():
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": "AAAA", "direction": "in"}]),
    ).value
    assert err.code == "INVALID_REQUEST"
    assert err.index == 0


def test_empty_and_oversized_batch():
    with pytest.raises(AuditError) as ei:
        audit([])
    assert ei.value.code == "INVALID_REQUEST"
    big = exchange_captures(0) * 251  # 1004 records
    with pytest.raises(AuditError) as ei:
        audit(big)
    assert ei.value.code == "INVALID_REQUEST"


def test_parser_delay_resp_layout():
    # Directly verify correct parsing of the IEEE body offsets.
    raw = build_message(
        DELAY_RESP, 77, MASTER, correction=-9,
        receive_ns=123_456_789_012, requesting=SLAVE, domain=3,
    )
    msg = parse_message(raw, 0)
    assert msg.msg_type is MsgType.DELAY_RESP
    assert msg.sequence_id == 77
    assert msg.correction == -9
    assert msg.domain == 3
    assert msg.embedded_ns == 123_456_789_012
    assert msg.requesting == PortId(SLAVE[0], SLAVE[1])
    assert msg.source == PortId(MASTER[0], MASTER[1])


def test_decode_packet_rejects_non_string():
    err = pytest.raises(AuditError, lambda: decode_packet(123, 2)).value
    assert err.code == "INVALID_REQUEST"
    assert err.index == 2


def test_denominator_constant():
    assert DENOMINATOR_NS == 131072


def test_one_step_sync_rejected():
    raw = build_message(SYNC, 1, MASTER, flags=0)
    err = pytest.raises(
        AuditError,
        lambda: audit([{"packet": b64(raw), "direction": "in",
                        "localTimestampNs": 0}]),
    ).value
    assert err.code == "NON_TWO_STEP_MESSAGE"


def test_boundary_batch_size_accepted():
    # 250 complete exchanges = 1000 records, all with distinct sequence ids.
    caps: list = []
    for seq in range(250):
        caps += exchange_captures(seq=seq)
    results = audit(caps)
    assert len(results) == 250
    assert results[-1]["completedAtCaptureIndex"] == 999


def test_delay_req_retransmission_allowed():
    base = exchange_captures(seq=60)
    caps = [base[0], base[1], base[2], base[2], base[3]]
    (r,) = audit(caps)
    assert r["sequenceId"] == 60
    assert r["completedAtCaptureIndex"] == 4


def test_one_delay_req_answered_by_two_masters():
    # E2E multicast: a single Delay_Req may be answered by several masters.
    # These are two distinct (master, slave, seq) exchanges sharing t3.
    caps = exchange_captures(seq=61)
    extra_sync = {
        "packet": b64(build_message(SYNC, 61, OTHER_MASTER)),
        "direction": "in", "localTimestampNs": 100,
    }
    extra_follow = {
        "packet": b64(build_message(FOLLOW_UP, 61, OTHER_MASTER, origin_ns=0)),
        "direction": "in", "localTimestampNs": 0,
    }
    extra_resp = {
        "packet": b64(
            build_message(
                DELAY_RESP, 61, OTHER_MASTER,
                receive_ns=3_000_000_000, requesting=SLAVE,
            )
        ),
        "direction": "in", "localTimestampNs": 0,
    }
    caps += [extra_sync, extra_follow, extra_resp]
    results = audit(caps)
    assert {r["masterPortIdentity"]["portNumber"] for r in results} == {1, 3}
    assert all(r["slavePortIdentity"]["portNumber"] == 2 for r in results)
