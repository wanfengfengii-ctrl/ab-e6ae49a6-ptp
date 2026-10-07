"""HTTP-level tests for POST /api/ptp/exchanges/audit via ASGI TestClient."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from ptpbuild import exchange_captures  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_audit_happy_path():
    r = client.post(
        "/api/ptp/exchanges/audit", json={"captures": exchange_captures(seq=5)}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    assert body["denominatorNs"] == 131072
    ex = body["exchanges"][0]
    assert ex["sequenceId"] == 5
    assert ex["offsetFromMasterNumerator"] == 0
    assert ex["meanPathDelayNumerator"] == 2 * 1_000_000_000 * 65536


def test_invalid_json_envelope():
    r = client.post("/api/ptp/exchanges/audit", content="not json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


def test_missing_captures_field():
    r = client.post("/api/ptp/exchanges/audit", json={"nope": []})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


def test_bad_item_field_reports_index():
    caps = exchange_captures(seq=6)
    caps[2]["direction"] = "sideways"
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == "INVALID_REQUEST"
    assert err["captureIndex"] == 2
    assert err["capturePosition"] == 3


def test_bad_base64_reports_index():
    caps = exchange_captures(seq=7)
    caps[1]["packet"] = "@@@@"
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == "INVALID_BASE64"
    assert err["captureIndex"] == 1


def test_orphan_reports_index_and_no_partial_results():
    # First exchange is fully valid; an orphan later must still yield a 4xx
    # with zero results - partial output is never acceptable.
    caps = exchange_captures(seq=8)
    orphan = exchange_captures(seq=9)
    caps.append(orphan[3])  # Delay_Resp without its prerequisites
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "ORPHAN_MESSAGE"
    assert err["captureIndex"] == 4
    assert "exchanges" not in r.json()


def test_negative_delay_rejected():
    caps = exchange_captures(
        seq=10, t1_ns=0, t2_ns=0, t3_ns=0, t4_ns=0,
        corrections=(1, 0, 0, 0),
    )
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "NEGATIVE_PATH_DELAY"


def test_unclosed_rejected():
    caps = exchange_captures(seq=11)[:3]
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "UNCLOSED_EXCHANGE"
    assert err["captureIndex"] == 0  # Sync starts the unclosed exchange


def test_retransmissions_accepted():
    base = exchange_captures(seq=12)
    caps = [base[0], base[0], base[1], base[2], base[2], base[3]]
    r = client.post("/api/ptp/exchanges/audit", json={"captures": caps})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 1
