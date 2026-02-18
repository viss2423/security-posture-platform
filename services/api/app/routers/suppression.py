"""Phase 3.2: Maintenance windows and suppression rules. CRUD + auditable."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/suppression", tags=["suppression"])


def _serialize_mw(row: dict) -> dict:
    out = dict(row)
    for k in ("start_at", "end_at", "created_at"):
        if hasattr(out.get(k), "isoformat"):
            out[k] = out[k].isoformat()
    return out


def _serialize_sr(row: dict) -> dict:
    out = dict(row)
    for k in ("starts_at", "ends_at", "created_at"):
        if hasattr(out.get(k), "isoformat"):
            out[k] = out[k].isoformat()
    return out


# ---------- Maintenance windows ----------
@router.get("/maintenance-windows")
def list_maintenance_windows(
    asset_key: str | None = Query(None),
    active_only: bool = Query(False, description="Only windows that cover now"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List maintenance windows. Optional filter by asset_key or active_only (now in window)."""
    conditions = ["1=1"]
    params: dict = {}
    if asset_key:
        conditions.append("asset_key = :ak")
        params["ak"] = asset_key
    if active_only:
        conditions.append("start_at <= NOW() AND end_at >= NOW()")
    where = " AND ".join(conditions)
    q = text(f"""
        SELECT id, asset_key, start_at, end_at, reason, created_by, created_at
        FROM maintenance_windows WHERE {where}
        ORDER BY start_at DESC
    """)
    rows = db.execute(q, params).mappings().all()
    return {"items": [_serialize_mw(dict(r)) for r in rows]}


class CreateMaintenanceWindowBody(BaseModel):
    asset_key: str
    start_at: str  # ISO
    end_at: str
    reason: str | None = None


@router.post("/maintenance-windows", status_code=201)
def create_maintenance_window(
    body: CreateMaintenanceWindowBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Schedule a maintenance window for an asset. Alerts/incidents for that asset are suppressed during the window."""
    try:
        start_at = datetime.fromisoformat(body.start_at.replace("Z", "+00:00"))
        end_at = datetime.fromisoformat(body.end_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="start_at and end_at must be ISO 8601")
    if end_at <= start_at:
        raise HTTPException(status_code=400, detail="end_at must be after start_at")
    q = text("""
        INSERT INTO maintenance_windows (asset_key, start_at, end_at, reason, created_by)
        VALUES (:ak, :start_at, :end_at, :reason, :created_by)
        RETURNING id, asset_key, start_at, end_at, reason, created_by, created_at
    """)
    row = (
        db.execute(
            q,
            {
                "ak": body.asset_key.strip(),
                "start_at": start_at,
                "end_at": end_at,
                "reason": body.reason or None,
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    return _serialize_mw(dict(row))


@router.delete("/maintenance-windows/{window_id}")
def delete_maintenance_window(
    window_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    r = db.execute(text("DELETE FROM maintenance_windows WHERE id = :id"), {"id": window_id})
    db.commit()
    if r.rowcount == 0:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    return {"ok": True}


# ---------- Suppression rules ----------
@router.get("/rules")
def list_suppression_rules(
    scope: str | None = Query(None, description="asset | finding | all"),
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    conditions = ["1=1"]
    params: dict = {}
    if scope:
        if scope not in ("asset", "finding", "all"):
            raise HTTPException(status_code=400, detail="scope must be asset, finding, or all")
        conditions.append("scope = :scope")
        params["scope"] = scope
    if active_only:
        conditions.append("starts_at <= NOW() AND ends_at >= NOW()")
    where = " AND ".join(conditions)
    q = text(f"""
        SELECT id, scope, scope_value, starts_at, ends_at, reason, created_by, created_at
        FROM suppression_rules WHERE {where}
        ORDER BY starts_at DESC
    """)
    rows = db.execute(q, params).mappings().all()
    return {"items": [_serialize_sr(dict(r)) for r in rows]}


class CreateSuppressionRuleBody(BaseModel):
    scope: str  # asset | finding | all
    scope_value: str | None = None  # required for asset/finding
    starts_at: str
    ends_at: str
    reason: str | None = None


@router.post("/rules", status_code=201)
def create_suppression_rule(
    body: CreateSuppressionRuleBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    if body.scope not in ("asset", "finding", "all"):
        raise HTTPException(status_code=400, detail="scope must be asset, finding, or all")
    if body.scope != "all" and not (body.scope_value or "").strip():
        raise HTTPException(status_code=400, detail="scope_value required for asset/finding")
    try:
        starts_at = datetime.fromisoformat(body.starts_at.replace("Z", "+00:00"))
        ends_at = datetime.fromisoformat(body.ends_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="starts_at and ends_at must be ISO 8601")
    if ends_at <= starts_at:
        raise HTTPException(status_code=400, detail="ends_at must be after starts_at")
    q = text("""
        INSERT INTO suppression_rules (scope, scope_value, starts_at, ends_at, reason, created_by)
        VALUES (:scope, :scope_value, :starts_at, :ends_at, :reason, :created_by)
        RETURNING id, scope, scope_value, starts_at, ends_at, reason, created_by, created_at
    """)
    row = (
        db.execute(
            q,
            {
                "scope": body.scope,
                "scope_value": (body.scope_value or "").strip() or None,
                "starts_at": starts_at,
                "ends_at": ends_at,
                "reason": body.reason or None,
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    return _serialize_sr(dict(row))


@router.delete("/rules/{rule_id}")
def delete_suppression_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    r = db.execute(text("DELETE FROM suppression_rules WHERE id = :id"), {"id": rule_id})
    db.commit()
    if r.rowcount == 0:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    return {"ok": True}
