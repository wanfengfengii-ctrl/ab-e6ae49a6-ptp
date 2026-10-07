"""HTTP API for the PTPv2 two-step exchange auditor."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .audit import DENOMINATOR, AuditError, Auditor
from .ptp import PacketError, parse_message

MAX_CAPTURES = 1000
MAX_LOCAL_TIME_NS = 2**63 - 1
DIRECTIONS = ("rx", "tx")

app = FastAPI(
    title="PTPv2 Exchange Auditor",
    version="1.0.0",
    summary=(
        "Audit two-step PTPv2 delay-request exchanges between a master and "
        "a slave clock."
    ),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _error(
    status_code: int, code: str, message: str, capture_index: int | None
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "captureIndex": capture_index,
                "message": message,
            }
        },
    )


def _invalid_request(message: str, capture_index: int | None = None) -> JSONResponse:
    return _error(400, "INVALID_REQUEST", message, capture_index)


def _validate_item(item: Any) -> tuple[bytes, str, int] | str:
    """Validate one capture item.

    Returns the decoded ``(packet, direction, local_time_ns)`` triple, or a
    human-readable problem string.
    """
    if not isinstance(item, dict):
        return "capture item must be an object"
    packet_b64 = item.get("packet")
    if not isinstance(packet_b64, str):
        return "'packet' must be a Base64 encoded string"
    try:
        packet = base64.b64decode(packet_b64, validate=True)
    except (binascii.Error, ValueError):
        return "'packet' is not valid Base64"
    direction = item.get("direction")
    if direction not in DIRECTIONS:
        return "'direction' must be 'rx' or 'tx'"
    local_time_ns = item.get("localTimeNs")
    if isinstance(local_time_ns, bool) or not isinstance(local_time_ns, int):
        return "'localTimeNs' must be an integer"
    if not 0 <= local_time_ns <= MAX_LOCAL_TIME_NS:
        return f"'localTimeNs' must be within 0..{MAX_LOCAL_TIME_NS}"
    return packet, direction, local_time_ns


@app.post("/api/ptp/exchanges/audit")
async def audit_exchanges(request: Request):
    try:
        body = await request.json()
    except Exception:
        return _invalid_request("request body must be a JSON object")
    if not isinstance(body, dict) or "captures" not in body:
        return _invalid_request(
            "request body must be an object with a 'captures' array"
        )
    captures = body["captures"]
    if not isinstance(captures, list) or not 1 <= len(captures) <= MAX_CAPTURES:
        return _invalid_request(
            f"'captures' must be an array of 1..{MAX_CAPTURES} items"
        )

    decoded: list[tuple[bytes, str, int]] = []
    for index, item in enumerate(captures):
        validated = _validate_item(item)
        if isinstance(validated, str):
            return _invalid_request(validated, index)
        decoded.append(validated)

    auditor = Auditor()
    for index, (packet, direction, local_time_ns) in enumerate(decoded):
        try:
            message = parse_message(packet)
        except PacketError as exc:
            return _error(422, exc.code, str(exc), index)
        try:
            auditor.process(index, message, packet, direction, local_time_ns)
        except AuditError as exc:
            return _error(422, exc.code, exc.message, exc.capture_index)
    try:
        exchanges = auditor.finalize()
    except AuditError as exc:
        return _error(422, exc.code, exc.message, exc.capture_index)
    return {
        "denominator": DENOMINATOR,
        "exchangeCount": len(exchanges),
        "exchanges": exchanges,
    }
