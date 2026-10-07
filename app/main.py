"""FastAPI application exposing the PTPv2 two-step exchange audit endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from .ptp import AuditError, audit_captures

__all__ = ["app"]


class CaptureItem(BaseModel):
    packet: str = Field(..., description="Base64 encoded raw PTPv2 message")
    direction: str = Field(..., description="'in' (toward slave) or 'out'")
    localTimestampNs: int


class AuditRequest(BaseModel):
    captures: list[CaptureItem]


def _error_body(code: str, message: str, index: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if index is not None:
        body["captureIndex"] = index  # 0-based, machine-readable
        body["capturePosition"] = index + 1  # 1-based, human-friendly
    return {"error": body}


def create_app() -> FastAPI:
    app = FastAPI(
        title="PTPv2 Two-Step Exchange Audit",
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    @app.exception_handler(AuditError)
    async def audit_error_handler(
        _request: Request, exc: AuditError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            content=_error_body(exc.code, exc.message, exc.index),
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/ptp/exchanges/audit")
    async def audit(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content=_error_body(
                    "INVALID_REQUEST", "request body must be valid JSON", None
                ),
            )
        if not isinstance(payload, dict) or "captures" not in payload:
            return JSONResponse(
                status_code=400,
                content=_error_body(
                    "INVALID_REQUEST",
                    "request body must be an object with a 'captures' array",
                    None,
                ),
            )

        try:
            validated = AuditRequest.model_validate(
                {"captures": payload["captures"]}
            )
        except ValidationError as exc:
            index = 0
            message = "request failed schema validation"
            for err in exc.errors():
                loc = err.get("loc", ())
                # loc shape: ("captures", <index>, "field")
                if len(loc) >= 2 and isinstance(loc[1], int):
                    index = loc[1]
                    field_name = loc[2] if len(loc) > 2 else "item"
                    message = f"{field_name}: {err.get('msg', 'invalid value')}"
                    break
            return JSONResponse(
                status_code=400,
                content=_error_body("INVALID_REQUEST", message, index),
            )

        records = [item.model_dump() for item in validated.captures]
        # audit_captures raises AuditError (handled above); on any failure no
        # partial result is ever serialized.
        exchanges = audit_captures(records)
        return JSONResponse(
            status_code=200,
            content={
                "exchanges": exchanges,
                "count": len(exchanges),
                "denominatorNs": 131072,
            },
        )

    return app


app = create_app()
