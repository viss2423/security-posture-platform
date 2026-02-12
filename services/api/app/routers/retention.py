"""Data retention: prune old events (OpenSearch) and report snapshots (Postgres)."""
import logging
from datetime import datetime, timezone, timedelta
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.settings import settings
from app.db import get_db
from app.routers.auth import require_auth
from app.rate_limit import check_rate_limit
from app.request_context import request_id_ctx
from app.audit import log_audit

audit = logging.getLogger("secplat.audit")

router = APIRouter(prefix="/retention", tags=["retention"])

EVENTS_INDEX = "secplat-events"


def _client_id(request: Request) -> str:
    return request.client.host if request.client else request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()


@router.post("/apply")
async def retention_apply(
    request: Request,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    key = f"retention:{_client_id(request)}"
    if not await check_rate_limit(key, settings.RATE_LIMIT_RETENTION_PER_HOUR, 3600.0):
        raise HTTPException(status_code=429, detail="Retention apply rate limited. Try again later.")
    result = {"events_deleted": None, "snapshots_deleted": None, "errors": []}

    # OpenSearch: delete events older than EVENTS_RETENTION_DAYS
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.EVENTS_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"{settings.OPENSEARCH_URL.rstrip('/')}/{EVENTS_INDEX}/_delete_by_query"
    body = {
        "query": {"range": {"@timestamp": {"lt": cutoff}}},
    }
    try:
        with httpx.Client(timeout=60.0) as client:
            r = client.post(url, json=body)
            r.raise_for_status()
            data = r.json()
            result["events_deleted"] = data.get("deleted", 0)
    except Exception as e:
        result["errors"].append(f"opensearch: {e!s}")

    # Postgres: keep only the newest SNAPSHOTS_RETENTION_KEEP snapshots
    try:
        q = text("""
            WITH ranked AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) AS rn
                FROM posture_report_snapshots
            ),
            to_delete AS (
                SELECT id FROM ranked WHERE rn > :keep
            )
            DELETE FROM posture_report_snapshots
            WHERE id IN (SELECT id FROM to_delete)
        """)
        r = db.execute(q, {"keep": settings.SNAPSHOTS_RETENTION_KEEP})
        result["snapshots_deleted"] = r.rowcount
        db.commit()
    except Exception as e:
        db.rollback()
        result["errors"].append(f"postgres: {e!s}")

    if result["errors"]:
        raise HTTPException(status_code=502, detail={"message": "Retention applied with errors", "result": result})
    req_id = request_id_ctx.get("")
    audit.info(
        "action=retention_apply user=%s events_deleted=%s snapshots_deleted=%s request_id=%s",
        _user,
        result["events_deleted"],
        result["snapshots_deleted"],
        req_id,
    )
    log_audit(
        db,
        "retention_apply",
        user_name=_user,
        details={"events_deleted": result["events_deleted"], "snapshots_deleted": result["snapshots_deleted"]},
        request_id=req_id or None,
    )
    db.commit()
    return result
