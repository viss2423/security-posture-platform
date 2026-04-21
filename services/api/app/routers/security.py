"""Security disclosure and AppSec program endpoints."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.request_context import request_id_ctx
from app.security_program import build_security_program, render_security_txt

router = APIRouter(tags=["security"])
logger = logging.getLogger("secplat.security")


class SecurityReportRequest(BaseModel):
    reporter_email: str | None = Field(default=None, max_length=320)
    title: str = Field(min_length=3, max_length=200)
    details: str = Field(min_length=20, max_length=12000)
    severity: str | None = Field(default=None, max_length=32)
    affected_component: str | None = Field(default=None, max_length=160)
    reproduction_steps: str | None = Field(default=None, max_length=8000)


@router.get("/platform/security-program")
def platform_security_program() -> dict[str, Any]:
    return build_security_program()


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt(request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        render_security_txt(canonical_base=str(request.base_url)),
        media_type="text/plain; charset=utf-8",
    )


@router.get("/security.txt", response_class=PlainTextResponse)
def security_txt_shortcut(request: Request) -> PlainTextResponse:
    return security_txt(request)


@router.post("/security/report")
def submit_security_report(
    body: SecurityReportRequest,
    request: Request,
) -> dict[str, Any]:
    report_id = f"sec-{uuid.uuid4().hex[:12]}"
    logger.info(
        "security_report_submitted",
        extra={
            "report_id": report_id,
            "request_id": request_id_ctx.get(None),
            "title": body.title,
            "severity": body.severity,
            "affected_component": body.affected_component,
            "details_length": len(body.details),
            "reproduction_steps_length": len(body.reproduction_steps or ""),
            "path": str(request.url.path),
            "user_agent": request.headers.get("user-agent"),
            "reporter_email_present": bool((body.reporter_email or "").strip()),
        },
    )
    return {
        "report_id": report_id,
        "status": "accepted",
        "intake_sla_hours": 24,
        "message": (
            "Security report accepted. Keep the report_id for follow-up; "
            "the team will acknowledge within the published intake SLA."
        ),
    }
