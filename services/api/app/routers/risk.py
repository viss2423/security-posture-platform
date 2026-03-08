"""Entity-level risk scoring APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.risk_engine import (
    attach_trend_delta,
    build_full_risk_snapshot,
    compute_asset_risk_rows,
    compute_environment_risk_rows,
    compute_incident_risk_rows,
    get_risk_priorities,
    get_risk_trends,
)
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/risk", tags=["risk"])


def _refresh_snapshot(db: Session) -> dict:
    payload = build_full_risk_snapshot(db, persist=True)
    db.commit()
    return payload


@router.get("/assets")
def list_asset_risk(
    limit: int = Query(200, ge=1, le=2000),
    include_trend_days: int = Query(30, ge=1, le=180),
    refresh: bool = Query(True, description="Recompute and persist a daily snapshot before returning"),
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
):
    if refresh:
        payload = _refresh_snapshot(db)
        rows = payload["assets"]
    else:
        rows = compute_asset_risk_rows(db, limit=limit)
    rows = attach_trend_delta(db, rows, days=include_trend_days)
    return {"items": rows[:limit], "total": len(rows)}


@router.get("/incidents")
def list_incident_risk(
    limit: int = Query(200, ge=1, le=2000),
    include_trend_days: int = Query(30, ge=1, le=180),
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    if refresh:
        payload = _refresh_snapshot(db)
        rows = payload["incidents"]
    else:
        rows = compute_incident_risk_rows(db, limit=limit)
    rows = attach_trend_delta(db, rows, days=include_trend_days)
    return {"items": rows[:limit], "total": len(rows)}


@router.get("/environments")
def list_environment_risk(
    include_trend_days: int = Query(30, ge=1, le=180),
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    if refresh:
        payload = _refresh_snapshot(db)
        rows = payload["environments"]
    else:
        rows = compute_environment_risk_rows(db)
    rows = attach_trend_delta(db, rows, days=include_trend_days)
    return {"items": rows, "total": len(rows)}


@router.get("/trends")
def list_risk_trends(
    entity_type: str = Query("asset", pattern="^(asset|incident|environment)$"),
    entity_key: str | None = Query(None),
    days: int = Query(30, ge=1, le=180),
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    items = get_risk_trends(
        db,
        entity_type=entity_type,
        entity_key=entity_key,
        days=days,
        limit=limit,
    )
    return {"items": items, "total": len(items)}


@router.get("/priorities")
def list_risk_priorities(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    items = get_risk_priorities(db, limit=limit)
    return {"items": items, "total": len(items)}


@router.post("/snapshots/refresh")
def refresh_risk_snapshot(
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    payload = _refresh_snapshot(db)
    log_audit(
        db,
        "risk.snapshot.refresh",
        user_name=user,
        details={
            "asset_rows": len(payload.get("assets") or []),
            "incident_rows": len(payload.get("incidents") or []),
            "environment_rows": len(payload.get("environments") or []),
            "computed_at": payload.get("computed_at"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {
        "ok": True,
        "computed_at": payload.get("computed_at"),
        "asset_rows": len(payload.get("assets") or []),
        "incident_rows": len(payload.get("incidents") or []),
        "environment_rows": len(payload.get("environments") or []),
    }
