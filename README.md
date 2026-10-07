# PTPv2 Two-Step Exchange Auditor

Audits PTPv2 (IEEE 1588-2008) two-step delay-request exchanges between a
master and a slave clock.  A capture of raw messages is submitted in
observation order; the service pairs Sync / Follow_Up / Delay_Req / Delay_Resp
into closed four-step exchanges and returns exact offset and mean-path-delay
verdicts, so sequence-number wraparound, duplicate frames and correctionField
misaccounting cannot mask an abnormal link.

## Running

```sh
cp .env.example .env          # optional; sets API_HOST_PORT (default 8080)
docker compose up -d api      # start the API behind its health check
```

The API listens on container port 8000 and is published on the host port
given by the `API_HOST_PORT` environment variable (default `8080`).  The
compose health check polls `GET /health` before the service is considered up.

### One-shot verification

```sh
docker compose up --exit-code-from verify
```

The `verify` service waits for the API health check, then runs, in order:

1. the code tests (`pytest`),
2. the application build check (byte-compilation of all modules plus an
   import/route sanity check of the FastAPI app),
3. an API smoke test posting complete four-step exchanges (including
   byte-identical retransmissions, completion ordering, orphan-response and
   negative-path-delay rejection),

and exits non-zero if any step fails.

## API

### `POST /api/ptp/exchanges/audit`

Request body — 1 to 1000 capture items in capture order:

```json
{
  "captures": [
    {"packet": "<base64 PTP datagram>", "direction": "rx", "localTimeNs": 1000500001000}
  ]
}
```

* `packet` — Base64 of exactly one PTPv2 datagram (`messageLength` must match
  the captured byte count).  Only Sync (`0x0`), Delay_Req (`0x1`),
  Follow_Up (`0x8`) and Delay_Resp (`0x9`) are audited.
* `direction` — `"rx"` or `"tx"` as seen at the slave-side capture point.
  Sync, Follow_Up and Delay_Resp must be `rx`; Delay_Req must be `tx`.
* `localTimeNs` — local nanosecond timestamp of the capture
  (`0 .. 2**63 - 1`).  Used as t2 (Sync) and t3 (Delay_Req).

### Success — `200 OK`

Exchanges are reported in completion order (order of their Delay_Resp):

```json
{
  "denominator": 131072,
  "exchangeCount": 1,
  "exchanges": [
    {
      "sequenceId": 40000,
      "masterPortIdentity": "0011223344556677:2",
      "slavePortIdentity": "aabbccddeeff0011:1",
      "firstCaptureIndex": 0,
      "completedCaptureIndex": 3,
      "correctionFieldSum": 163840,
      "offsetNumerator": -163840,
      "meanPathDelayNumerator": 130908160
    }
  ]
}
```

`offsetNumerator / 131072` and `meanPathDelayNumerator / 131072` are the
offset-from-master and mean path delay in nanoseconds.  With t1..t4 in
nanoseconds (t1 from Follow_Up preciseOriginTimestamp, t2/t3 the local
timestamps, t4 from Delay_Resp receiveTimestamp) and `C` the sum of the four
**signed** correctionField values (units of 2^-16 ns):

```
offsetNumerator        = ((t2 - t1) - (t4 - t3)) * 65536 - C
meanPathDelayNumerator = ((t2 - t1) + (t4 - t3)) * 65536 - C
```

A negative `meanPathDelayNumerator` is rejected.

### Errors — `400` / `422`

Every invalid input returns a stable error code and the 0-based position of
the first relevant capture item; no partial results are ever emitted:

```json
{"error": {"code": "ORPHAN_RESPONSE", "captureIndex": 5, "message": "..."}}
```

| Code (`error.code`)     | HTTP | Meaning |
|-------------------------|------|---------|
| `INVALID_REQUEST`       | 400  | Body/schema violation (count outside 1..1000, bad Base64, unknown direction, bad `localTimeNs`). |
| `MALFORMED_PACKET`      | 422  | Datagram too short, wrong PTP version, `messageLength` mismatch, truncated body, bad timestamp. |
| `UNSUPPORTED_MESSAGE_TYPE` | 422 | Well-formed PTP message that is not Sync/Follow_Up/Delay_Req/Delay_Resp. |
| `UNEXPECTED_DIRECTION`  | 422  | Message captured in a direction inconsistent with its role. |
| `CONFLICTING_MESSAGE`   | 422  | Same pairing key but different bytes (or an ambiguous Delay_Req pairing). |
| `ORPHAN_RESPONSE`       | 422  | Follow_Up or Delay_Resp with no matching pending exchange. |
| `OUT_OF_ORDER_PHASE`    | 422  | Delay_Req arrived before its Sync/Follow_Up pair completed. |
| `UNCLOSED_EXCHANGE`     | 422  | Capture ended with an exchange missing phases. |
| `NEGATIVE_PATH_DELAY`   | 422  | Computed mean path delay numerator is negative. |

## Pairing rules

* An exchange is keyed by the master port identity and the 16-bit
  `sequenceId`; phases must appear in capture order as
  Sync → Follow_Up → Delay_Req → Delay_Resp.
* Delay_Req carries the slave port identity and binds to the unique open
  exchange awaiting it for that sequence id; Delay_Resp must name the same
  master and requester.
* Byte-identical retransmissions (same datagram bytes) are always tolerated
  and keep the first occurrence's timestamps; the same key with different
  bytes is a conflict.
* A sequence id may be reused only after the previous exchange with that key
  has closed — this is how 16-bit wraparound is handled.  A byte-identical
  datagram is always treated as a retransmission of the latest exchange using
  its key, so a reuse that changes nothing observable is folded into it.

## Layout

```
app/        FastAPI service (main.py), PTPv2 parser (ptp.py), auditor (audit.py)
tests/      pytest suite plus packet builders shared with the smoke test
verify/     one-shot compose service: run.sh drives tests, build check, smoke
```

Local development without Docker:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests -q
uvicorn app.main:app --port 8000
```
