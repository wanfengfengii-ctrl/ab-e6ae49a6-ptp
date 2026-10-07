import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ptp import DELAY_REQ, DELAY_RESP, FOLLOW_UP, SYNC
from tests.builders import (
    MASTER_IDENTITY,
    SLAVE_IDENTITY,
    build_message,
    capture_item,
    exchange_captures,
)

client = TestClient(app)

T1 = 1_000_500_000_000


def post(captures):
    return client.post("/api/ptp/exchanges/audit", json={"captures": captures})


def assert_error(response, status_code, code, capture_index):
    assert response.status_code == status_code, response.text
    body = response.json()
    assert body["error"]["code"] == code
    assert body["error"]["captureIndex"] == capture_index
    assert isinstance(body["error"]["message"], str)
    # no partially trusted results may leak into an error response
    assert "exchanges" not in body


# -- health -----------------------------------------------------------------


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# -- happy path ---------------------------------------------------------------


def test_complete_exchange_exact_numerators():
    corrections = (65536, -32768, 0, 131072)  # C = 163840
    captures = exchange_captures(sequence_id=40000, t1=T1, corrections=corrections)
    response = post(captures)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["denominator"] == 131072
    assert body["exchangeCount"] == 1
    (exchange,) = body["exchanges"]
    assert exchange["sequenceId"] == 40000
    assert exchange["masterPortIdentity"] == "0011223344556677:2"
    assert exchange["slavePortIdentity"] == "aabbccddeeff0011:1"
    assert exchange["firstCaptureIndex"] == 0
    assert exchange["completedCaptureIndex"] == 3
    assert exchange["correctionFieldSum"] == 163840
    # forward == backward == 1000 ns
    assert exchange["offsetNumerator"] == -163840
    assert exchange["meanPathDelayNumerator"] == 2000 * 65536 - 163840


def test_negative_correction_sum():
    corrections = (-65536, 0, 0, 0)  # C = -65536
    captures = exchange_captures(sequence_id=1, t1=T1, corrections=corrections)
    (exchange,) = post(captures).json()["exchanges"]
    assert exchange["offsetNumerator"] == 65536
    assert exchange["meanPathDelayNumerator"] == 131072000 + 65536


def test_zero_path_delay_accepted():
    captures = exchange_captures(sequence_id=2, t1=T1, t2=T1, t3=T1, t4=T1)
    (exchange,) = post(captures).json()["exchanges"]
    assert exchange["offsetNumerator"] == 0
    assert exchange["meanPathDelayNumerator"] == 0


def test_byte_identical_retransmissions_allowed():
    captures = exchange_captures(sequence_id=3, t1=T1)
    replayed = [
        captures[0],
        dict(captures[0]),  # Sync retransmission
        captures[1],
        dict(captures[1]),  # Follow_Up retransmission
        captures[2],
        dict(captures[2]),  # Delay_Req retransmission
        captures[3],
        dict(captures[3]),  # Delay_Resp retransmission
    ]
    response = post(replayed)
    assert response.status_code == 200, response.text
    (exchange,) = response.json()["exchanges"]
    assert exchange["firstCaptureIndex"] == 0
    assert exchange["completedCaptureIndex"] == 6
    assert exchange["offsetNumerator"] == 0
    assert exchange["meanPathDelayNumerator"] == 131072000


def test_retransmission_after_completion_allowed():
    captures = exchange_captures(sequence_id=4, t1=T1)
    replayed = captures + [dict(item) for item in captures]
    response = post(replayed)
    assert response.status_code == 200, response.text
    assert response.json()["exchangeCount"] == 1


def test_completion_order_follows_delay_resp_arrival():
    first = exchange_captures(sequence_id=10, t1=T1)
    second = exchange_captures(sequence_id=20, t1=T1)
    captures = [
        first[0],
        second[0],
        first[1],
        second[1],
        second[2],
        second[3],  # exchange 20 closes first
        first[2],
        first[3],
    ]
    body = post(captures).json()
    assert [ex["sequenceId"] for ex in body["exchanges"]] == [20, 10]
    assert body["exchanges"][0]["completedCaptureIndex"] == 5
    assert body["exchanges"][1]["completedCaptureIndex"] == 7


def test_sequence_wraparound_boundary():
    captures = exchange_captures(sequence_id=65535, t1=T1)
    captures += exchange_captures(sequence_id=0, t1=T1)
    body = post(captures).json()
    assert [ex["sequenceId"] for ex in body["exchanges"]] == [65535, 0]


def test_sequence_reuse_after_close_starts_new_exchange():
    captures = exchange_captures(sequence_id=7, t1=T1)
    captures += exchange_captures(
        sequence_id=7, t1=T1, corrections=(10, 20, 30, 40)
    )
    body = post(captures).json()
    assert body["exchangeCount"] == 2
    second = body["exchanges"][1]
    assert second["correctionFieldSum"] == 100
    assert second["offsetNumerator"] == -100
    assert second["meanPathDelayNumerator"] == 131072000 - 100


def test_two_masters_with_distinct_sequences():
    other_master = bytes.fromhex("ffee001122334455") + (9).to_bytes(2, "big")
    first = exchange_captures(sequence_id=60, t1=T1)
    second = exchange_captures(sequence_id=61, t1=T1, master=other_master)
    captures = [first[0], second[0], first[1], second[1]]
    captures += [first[2], first[3], second[2], second[3]]
    body = post(captures).json()
    assert body["exchangeCount"] == 2
    identities = {ex["masterPortIdentity"] for ex in body["exchanges"]}
    assert identities == {"0011223344556677:2", "ffee001122334455:9"}


def test_maximum_capture_count_accepted():
    captures = []
    for seq in range(250):
        captures += exchange_captures(sequence_id=seq, t1=T1)
    assert len(captures) == 1000
    body = post(captures).json()
    assert body["exchangeCount"] == 250


# -- conflicts and retransmission misuse --------------------------------------


def test_conflicting_sync_rejected():
    good = exchange_captures(sequence_id=11, t1=T1)
    conflicting = capture_item(
        build_message(SYNC, sequence_id=11, correction=1, timestamp_ns=T1), "rx", T1
    )
    assert_error(post([good[0], conflicting]), 422, "CONFLICTING_MESSAGE", 1)


def test_conflicting_follow_up_rejected():
    good = exchange_captures(sequence_id=12, t1=T1)
    conflicting = capture_item(
        build_message(FOLLOW_UP, sequence_id=12, correction=7, timestamp_ns=T1),
        "rx",
        T1,
    )
    assert_error(
        post([good[0], good[1], conflicting]), 422, "CONFLICTING_MESSAGE", 2
    )


def test_conflicting_delay_req_rejected():
    good = exchange_captures(sequence_id=13, t1=T1)
    conflicting = capture_item(
        build_message(
            DELAY_REQ, source=SLAVE_IDENTITY, sequence_id=13, correction=3
        ),
        "tx",
        T1 + 3000,
    )
    captures = [good[0], good[1], good[2], conflicting]
    assert_error(post(captures), 422, "CONFLICTING_MESSAGE", 3)


def test_conflicting_delay_resp_rejected():
    good = exchange_captures(sequence_id=14, t1=T1)
    conflicting = capture_item(
        build_message(DELAY_RESP, sequence_id=14, correction=9, timestamp_ns=T1 + 3000),
        "rx",
        T1 + 4000,
    )
    assert_error(post(good + [conflicting]), 422, "CONFLICTING_MESSAGE", 4)


def test_ambiguous_delay_req_rejected():
    other_master = bytes.fromhex("ffee001122334455") + (9).to_bytes(2, "big")
    first = exchange_captures(sequence_id=50, t1=T1)
    second = exchange_captures(sequence_id=50, t1=T1, master=other_master)
    captures = [first[0], first[1], second[0], second[1], first[2]]
    assert_error(post(captures), 422, "CONFLICTING_MESSAGE", 4)


# -- orphan responses and phase order -----------------------------------------


def test_orphan_follow_up_rejected():
    orphan = exchange_captures(sequence_id=21, t1=T1)[1]
    assert_error(post([orphan]), 422, "ORPHAN_RESPONSE", 0)


def test_orphan_delay_resp_rejected():
    orphan = exchange_captures(sequence_id=22, t1=T1)[3]
    assert_error(post([orphan]), 422, "ORPHAN_RESPONSE", 0)


def test_delay_resp_for_unknown_requester_rejected():
    other_slave = bytes.fromhex("1122334455667700") + (4).to_bytes(2, "big")
    captures = exchange_captures(sequence_id=23, t1=T1)
    stray = capture_item(
        build_message(
            DELAY_RESP,
            sequence_id=23,
            timestamp_ns=T1 + 3000,
            requesting=other_slave,
        ),
        "rx",
        T1 + 4000,
    )
    assert_error(post(captures[:3] + [stray]), 422, "ORPHAN_RESPONSE", 3)


def test_delay_req_before_follow_up_rejected():
    captures = exchange_captures(sequence_id=24, t1=T1)
    assert_error(post([captures[0], captures[2]]), 422, "OUT_OF_ORDER_PHASE", 1)


def test_delay_req_without_any_exchange_rejected():
    captures = exchange_captures(sequence_id=25, t1=T1)
    assert_error(post([captures[2]]), 422, "OUT_OF_ORDER_PHASE", 0)


def test_unclosed_exchange_rejected():
    captures = exchange_captures(sequence_id=26, t1=T1)
    assert_error(post(captures[:1]), 422, "UNCLOSED_EXCHANGE", 0)


def test_unclosed_exchange_reports_first_capture_of_exchange():
    complete = exchange_captures(sequence_id=27, t1=T1)
    dangling = exchange_captures(sequence_id=28, t1=T1)
    captures = complete + dangling[:2]
    assert_error(post(captures), 422, "UNCLOSED_EXCHANGE", 4)


def test_unclosed_exchange_reports_earliest_exchange():
    first = exchange_captures(sequence_id=29, t1=T1)
    second = exchange_captures(sequence_id=30, t1=T1)
    assert_error(post([first[0], second[0]]), 422, "UNCLOSED_EXCHANGE", 0)


# -- arithmetic guards ----------------------------------------------------------


def test_negative_path_delay_rejected():
    captures = exchange_captures(
        sequence_id=31, t1=T1, t2=T1 - 5000, t3=T1 - 4000, t4=T1 - 3900
    )
    assert_error(post(captures), 422, "NEGATIVE_PATH_DELAY", 0)


def test_negative_path_delay_reports_exchange_start():
    good = exchange_captures(sequence_id=32, t1=T1)
    bad = exchange_captures(
        sequence_id=33, t1=T1, t2=T1 - 5000, t3=T1 - 4000, t4=T1 - 3900
    )
    assert_error(post(good + bad), 422, "NEGATIVE_PATH_DELAY", 4)


# -- direction and packet shape -------------------------------------------------


def test_sync_with_wrong_direction_rejected():
    captures = exchange_captures(sequence_id=41, t1=T1)
    captures[0]["direction"] = "tx"
    assert_error(post(captures), 422, "UNEXPECTED_DIRECTION", 0)


def test_delay_req_with_wrong_direction_rejected():
    captures = exchange_captures(sequence_id=42, t1=T1)
    captures[2]["direction"] = "rx"
    assert_error(post(captures), 422, "UNEXPECTED_DIRECTION", 2)


def test_truncated_packet_rejected():
    assert_error(
        post([capture_item(b"\x00\x02\x00", "rx", 0)]),
        422,
        "MALFORMED_PACKET",
        0,
    )


def test_wrong_version_rejected():
    packet = bytearray(build_message(SYNC, sequence_id=43, timestamp_ns=T1))
    packet[1] = 0x01
    assert_error(
        post([capture_item(bytes(packet), "rx", T1)]),
        422,
        "MALFORMED_PACKET",
        0,
    )


def test_unsupported_message_type_rejected():
    packet = bytearray(build_message(SYNC, sequence_id=44, timestamp_ns=T1))
    packet[0] = 0x0B  # Announce
    assert_error(
        post([capture_item(bytes(packet), "rx", T1)]),
        422,
        "UNSUPPORTED_MESSAGE_TYPE",
        0,
    )


# -- request schema ---------------------------------------------------------------


def test_body_must_be_object():
    response = client.post(
        "/api/ptp/exchanges/audit",
        content=b"[1, 2]",
        headers={"content-type": "application/json"},
    )
    assert_error(response, 400, "INVALID_REQUEST", None)


def test_body_must_be_valid_json():
    response = client.post(
        "/api/ptp/exchanges/audit",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert_error(response, 400, "INVALID_REQUEST", None)


def test_captures_must_not_be_empty():
    assert_error(post([]), 400, "INVALID_REQUEST", None)


def test_captures_above_limit_rejected():
    captures = []
    for seq in range(250):
        captures += exchange_captures(sequence_id=seq, t1=T1)
    captures += exchange_captures(sequence_id=250, t1=T1)
    assert len(captures) == 1004
    assert_error(post(captures), 400, "INVALID_REQUEST", None)


def test_item_must_be_object():
    assert_error(post(["nope"]), 400, "INVALID_REQUEST", 0)


def test_packet_must_be_base64():
    item = {"packet": "!!!not-base64!!!", "direction": "rx", "localTimeNs": 0}
    assert_error(post([item]), 400, "INVALID_REQUEST", 0)


def test_direction_must_be_known():
    item = capture_item(build_message(SYNC, timestamp_ns=T1), "up", T1)
    assert_error(post([item]), 400, "INVALID_REQUEST", 0)


def test_local_time_must_be_integer():
    item = capture_item(build_message(SYNC, timestamp_ns=T1), "rx", "soon")
    assert_error(post([item]), 400, "INVALID_REQUEST", 0)


def test_local_time_must_not_be_bool():
    item = capture_item(build_message(SYNC, timestamp_ns=T1), "rx", True)
    assert_error(post([item]), 400, "INVALID_REQUEST", 0)


def test_local_time_must_not_be_negative():
    item = capture_item(build_message(SYNC, timestamp_ns=T1), "rx", -1)
    assert_error(post([item]), 400, "INVALID_REQUEST", 0)


def test_first_invalid_item_position_reported():
    good = exchange_captures(sequence_id=45, t1=T1)
    bad = capture_item(build_message(SYNC, timestamp_ns=T1), "rx", -5)
    assert_error(post(good + [bad]), 400, "INVALID_REQUEST", 4)
