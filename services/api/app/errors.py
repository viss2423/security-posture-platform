from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .request_context import request_id_ctx

logger = logging.getLogger("secplat")

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


def _error_payload(
    *,
    message: str,
    status_code: int,
    detail: Any | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "error": {
            "message": message,
            "status_code": status_code,
            "retryable": status_code in RETRYABLE_STATUS,
        }
    }
    if detail is not None:
        payload["error"]["detail"] = detail
    request_id = request_id_ctx.get(None)
    if request_id:
        payload["error"]["request_id"] = request_id
    return payload


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exception_handler(_request: Request, exc: HTTPException):
        retryable = exc.status_code in RETRYABLE_STATUS
        log_level = logging.WARNING if retryable or exc.status_code >= 500 else logging.INFO
        logger.log(
            log_level,
            "http_exception",
            extra={
                "action": "http_exception",
                "status": exc.status_code,
                "retryable": retryable,
                "detail": exc.detail,
            },
        )
        detail = exc.detail
        message = detail if isinstance(detail, str) else "Request failed"
        payload = _error_payload(message=message, status_code=exc.status_code, detail=detail)
        return JSONResponse(status_code=exc.status_code, content=payload)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_request: Request, exc: RequestValidationError):
        logger.info(
            "validation_error",
            extra={
                "action": "validation_error",
                "status": 422,
                "retryable": False,
                "error_count": len(exc.errors()),
            },
        )
        payload = _error_payload(
            message="Request validation failed",
            status_code=422,
            detail=exc.errors(),
        )
        return JSONResponse(status_code=422, content=payload)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, exc: Exception):
        logger.exception(
            "unhandled_exception",
            extra={"action": "unhandled_exception", "status": 500, "retryable": True},
        )
        payload = _error_payload(message="Internal server error", status_code=500, detail=str(exc))
        return JSONResponse(status_code=500, content=payload)
