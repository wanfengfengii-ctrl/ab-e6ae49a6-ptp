"""Smoke check executed by the one-shot ``verify`` compose service.

Posts complete four-step exchanges (plus negative cases) to the running API
and verifies the exact verdicts.  Exits non-zero on the first failed check
summary so the container exit code reflects the outcome.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

from tests.builders import exchange_captures

T1 = 1_000_000_000_000


def _wait_for_health(client: httpx.Client, attempts: int = 60) -> None:
    for _ in range(attempts):
        try:
            response = client.get("/health")
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise AssertionError("API did not become healthy in time")


def _check_complete_exchange_with_retransmission(client: httpx.Client) -> None:
    t2 = T1 + 20_000
    t3 = t2 + 5_000_000
    t4 = t3 + 18_000
    corrections = (1024, -2048, 512, 0)  # C = -512
    captures = exchange_captures(
        sequence_id=4242, t1=T1, t2=t2, t3=t3, t4=t4, corrections=corrections
    )
    # byte-identical retransmissions must be tolerated
    captures.insert(1, dict(captures[0]))
    captures.append(dict(captures[-1]))
    response = client.post("/api/ptp/exchanges/audit", json={"captures": captures})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["denominator"] == 131072, body
    assert body["exchangeCount"] == 1, body
    (exchange,) = body["exchanges"]
    assert exchange["sequenceId"] == 4242, exchange
    assert exchange["completedCaptureIndex"] == 4, exchange
    # forward = 20000 ns, backward = 18000 ns, C = -512
    assert exchange["offsetNumerator"] == 131_072_512, exchange
    assert exchange["meanPathDelayNumerator"] == 2_490_368_512, exchange


def _check_completion_order(client: httpx.Client) -> None:
    first = exchange_captures(sequence_id=600, t1=T1)
    second = exchange_captures(sequence_id=601, t1=T1)
    captures = [
        first[0],
        second[0],
        first[1],
        second[1],
        second[2],
        second[3],  # exchange 601 closes first
        first[2],
        first[3],
    ]
    response = client.post("/api/ptp/exchanges/audit", json={"captures": captures})
    assert response.status_code == 200, response.text
    body = response.json()
    assert [ex["sequenceId"] for ex in body["exchanges"]] == [601, 600], body


def _check_orphan_response_rejected(client: httpx.Client) -> None:
    orphan = exchange_captures(sequence_id=77, t1=T1)[3]  # lone Delay_Resp
    response = client.post("/api/ptp/exchanges/audit", json={"captures": [orphan]})
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["error"]["code"] == "ORPHAN_RESPONSE", body
    assert body["error"]["captureIndex"] == 0, body
    assert "exchanges" not in body


def _check_negative_path_delay_rejected(client: httpx.Client) -> None:
    captures = exchange_captures(
        sequence_id=88, t1=T1, t2=T1 - 5000, t3=T1 - 4000, t4=T1 - 3900
    )
    response = client.post("/api/ptp/exchanges/audit", json={"captures": captures})
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["error"]["code"] == "NEGATIVE_PATH_DELAY", body
    assert body["error"]["captureIndex"] == 0, body


def main() -> int:
    base_url = os.environ.get("API_BASE_URL", "http://api:8000").rstrip("/")
    checks = [
        _check_complete_exchange_with_retransmission,
        _check_completion_order,
        _check_orphan_response_rejected,
        _check_negative_path_delay_rejected,
    ]
    failures = 0
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        try:
            _wait_for_health(client)
        except AssertionError as exc:
            print(f"[smoke] FAIL health check: {exc}")
            return 1
        for check in checks:
            try:
                check(client)
            except AssertionError as exc:
                failures += 1
                print(f"[smoke] FAIL {check.__name__}: {exc}")
            else:
                print(f"[smoke] ok   {check.__name__}")
    if failures:
        print(f"[smoke] {failures} of {len(checks)} checks failed")
        return 1
    print(f"[smoke] all {len(checks)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
