"""Audit log API: list persisted audit events with filters."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(
    user: str | None = Query(None, description="Filter by user_name"),
    action: str | None = Query(None, description="Filter by action (e.g. login, retention_apply)"),
    since: str | None = Query(None, description="ISO datetime; only events after this"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List audit events, newest first. Optional filters: user, action, since."""
    conditions = ["1=1"]
    params: dict = {"limit": limit}
    if user:
        conditions.append("user_name = :user")
        params["user"] = user
    if action:
        conditions.append("action = :action")
        params["action"] = action
    if since:
        conditions.append("created_at >= CAST(:since AS timestamptz)")
        params["since"] = since
    where = " AND ".join(conditions)
    q = text(f"""
        SELECT id, created_at, action, user_name, asset_key, details, request_id
        FROM audit_events
        WHERE {where}
        ORDER BY created_at DESC
        LIMIT :limit
    """)
    rows = db.execute(q, params).mappings().all()
    return {
        "items": [
            {
                "id": r["id"],
                "created_at": r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
                "action": r["action"],
                "user_name": r["user_name"],
                "asset_key": r["asset_key"],
                "details": r["details"],
                "request_id": r["request_id"],
            }
            for r in rows
        ],
        "actions": _distinct_actions(db),
    }


def _distinct_actions(db: Session) -> list[str]:
    """Return distinct action values for filter dropdown."""
    q = text("SELECT DISTINCT action FROM audit_events ORDER BY action")
    return [r[0] for r in db.execute(q).fetchall() if r[0]]
