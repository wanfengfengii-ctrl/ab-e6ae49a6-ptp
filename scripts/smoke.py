#!/usr/bin/env python3
"""End-to-end API smoke test for the PTP audit service.

Posts one complete, well-formed four-step exchange and asserts the exact
verdict (offset / mean path delay). Exits non-zero on any mismatch. Uses only
the standard library so it can run inside a slim container.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ptpbuild import exchange_captures  # noqa: E402

BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")
DEN = 131072


def _request(method: str, path: str, payload: dict | None = None,
             timeout: float = 5.0) -> tuple[int, dict]:
    data = None
    headers = {"accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(
        BASE_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def wait_for_health(attempts: int = 30, delay: float = 1.0) -> None:
    for i in range(attempts):
        try:
            status, body = _request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                print(f"smoke: health ok after {i + 1} attempt(s)")
                return
        except Exception:
            pass
        time.sleep(delay)
    raise SystemExit("smoke: service did not become healthy")


def main() -> int:
    wait_for_health()

    # Asymmetric but feasible link: A = 100 ns, B = 140 ns,
    # corrections sum C = 20 (1/65536 ns units).
    # offset = (A-B)*65536 + C = -40*65536 + 20 = -2621420
    # delay  = (A+B)*65536 - C = 240*65536 - 20 = 15_728_620
    captures = exchange_captures(
        seq=1234,
        t1_ns=1_000_000_000,
        t2_ns=1_000_000_100,
        t3_ns=2_000_000_000,
        t4_ns=2_000_000_140,
        corrections=(5, 10, 0, 5),
    )
    status, body = _request(
        "POST", "/api/ptp/exchanges/audit", {"captures": captures}
    )
    if status != 200:
        print(f"smoke: unexpected status {status}: {body}", file=sys.stderr)
        return 1
    if body.get("count") != 1 or body.get("denominatorNs") != DEN:
        print(f"smoke: bad envelope: {body}", file=sys.stderr)
        return 1
    ex = body["exchanges"][0]
    expected = {
        "sequenceId": 1234,
        "offsetFromMasterNumerator": -40 * 65536 + 20,
        "meanPathDelayNumerator": 240 * 65536 - 20,
        "correctionFieldSum": 20,
    }
    for key, want in expected.items():
        got = ex.get(key)
        if got != want:
            print(f"smoke: {key} = {got}, want {want}", file=sys.stderr)
            return 1

    # Negative case: unclosed exchange must be rejected with a stable code
    # and a capture index, never with partial results.
    status, body = _request(
        "POST", "/api/ptp/exchanges/audit", {"captures": captures[:3]}
    )
    if status == 200 or body.get("error", {}).get("code") != "UNCLOSED_EXCHANGE":
        print(f"smoke: unclosed exchange not rejected: {status} {body}",
              file=sys.stderr)
        return 1
    if "captureIndex" not in body["error"]:
        print("smoke: error lacks captureIndex", file=sys.stderr)
        return 1

    print(
        "smoke: complete exchange accepted "
        f"(offset={ex['offsetFromMasterNumerator']}/{DEN} ns, "
        f"meanPathDelay={ex['meanPathDelayNumerator']}/{DEN} ns); "
        "unclosed exchange rejected"
    )
    print("SMOKE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
