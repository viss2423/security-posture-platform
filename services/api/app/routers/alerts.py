"""Alert lifecycle: firing, acked, suppressed, resolved. Uses posture down_assets + alert_states table."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth
from app.routers.posture import _get_down_assets

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_alert_states(db: Session) -> dict:
    """Return dict asset_key -> { state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at }."""
    q = text("SELECT asset_key, state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at FROM alert_states")
    rows = db.execute(q).mappings().all()
    return {r["asset_key"]: dict(r) for r in rows}


def _upsert_alert_state(
    db: Session,
    asset_key: str,
    state: str,
    ack_reason: str | None = None,
    acked_by: str | None = None,
    suppressed_until: datetime | None = None,
    assigned_to: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    if state == "acked":
        q = text("""
            INSERT INTO alert_states (asset_key, state, ack_reason, acked_by, acked_at, updated_at)
            VALUES (:asset_key, 'acked', :ack_reason, :acked_by, :now, :now)
            ON CONFLICT (asset_key) DO UPDATE SET
              state = 'acked', ack_reason = :ack_reason, acked_by = :acked_by, acked_at = :now,
              suppressed_until = NULL, updated_at = :now
        """)
        db.execute(q, {"asset_key": asset_key, "ack_reason": ack_reason or "", "acked_by": acked_by, "now": now})
    elif state == "suppressed":
        q = text("""
            INSERT INTO alert_states (asset_key, state, suppressed_until, updated_at)
            VALUES (:asset_key, 'suppressed', :suppressed_until, :now)
            ON CONFLICT (asset_key) DO UPDATE SET
              state = 'suppressed', suppressed_until = :suppressed_until, updated_at = :now
        """)
        db.execute(q, {"asset_key": asset_key, "suppressed_until": suppressed_until, "now": now})
    elif state == "resolved":
        q = text("""
            INSERT INTO alert_states (asset_key, state, resolved_at, updated_at)
            VALUES (:asset_key, 'resolved', :now, :now)
            ON CONFLICT (asset_key) DO UPDATE SET
              state = 'resolved', resolved_at = :now, updated_at = :now
        """)
        db.execute(q, {"asset_key": asset_key, "now": now})
    elif state == "assigned":
        q = text("""
            INSERT INTO alert_states (asset_key, state, assigned_to, updated_at)
            VALUES (:asset_key, 'firing', :assigned_to, :now)
            ON CONFLICT (asset_key) DO UPDATE SET assigned_to = :assigned_to, updated_at = :now
        """)
        db.execute(q, {"asset_key": asset_key, "assigned_to": assigned_to or "", "now": now})
    db.commit()


@router.get("")
def list_alerts(db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """Return alerts grouped by state: firing, acked, suppressed, resolved."""
    down_assets = _get_down_assets()
    states_map = _get_alert_states(db)
    now = datetime.now(timezone.utc)

    firing = []
    acked = []
    suppressed = []
    resolved = []

    def _serialize(row: dict | None) -> dict:
        if not row:
            return {}
        out = dict(row)
        for k in ("acked_at", "suppressed_until", "resolved_at", "updated_at"):
            v = out.get(k)
            if hasattr(v, "isoformat"):
                out[k] = v.isoformat()
        return out

    for asset_key in down_assets:
        row = states_map.get(asset_key)
        sup_until = row.get("suppressed_until") if row else None
        if sup_until and (sup_until if hasattr(sup_until, "tzinfo") else sup_until) > now:
            suppressed.append({"asset_key": asset_key, **_serialize(row)} if row else {"asset_key": asset_key, "state": "suppressed"})
            continue
        if row and row.get("state") == "acked":
            acked.append({"asset_key": asset_key, **_serialize(row)})
            continue
        firing.append({"asset_key": asset_key, **_serialize(row or {"state": "firing"})})

    for asset_key, row in states_map.items():
        if asset_key in down_assets:
            continue
        if row.get("state") == "resolved":
            resolved.append({"asset_key": asset_key, **_serialize(row)})
        elif row.get("state") == "suppressed":
            sup_until = row.get("suppressed_until")
            if sup_until and (sup_until if hasattr(sup_until, "tzinfo") else sup_until) > now:
                suppressed.append({"asset_key": asset_key, **_serialize(row)})

    return {"firing": firing, "acked": acked, "suppressed": suppressed, "resolved": resolved}


class AckBody(BaseModel):
    asset_key: str
    reason: str | None = None


class SuppressBody(BaseModel):
    asset_key: str
    until_iso: str  # ISO datetime


class ResolveBody(BaseModel):
    asset_key: str


class AssignBody(BaseModel):
    asset_key: str
    assigned_to: str | None = None


@router.post("/ack")
def alert_ack(body: AckBody, db: Session = Depends(get_db), user: str = Depends(require_auth)):
    _upsert_alert_state(db, body.asset_key, "acked", ack_reason=body.reason, acked_by=user)
    return {"ok": True, "asset_key": body.asset_key, "state": "acked"}


@router.post("/suppress")
def alert_suppress(body: SuppressBody, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    try:
        until = datetime.fromisoformat(body.until_iso.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid until_iso; use ISO datetime")
    _upsert_alert_state(db, body.asset_key, "suppressed", suppressed_until=until)
    return {"ok": True, "asset_key": body.asset_key, "state": "suppressed", "suppressed_until": body.until_iso}


@router.post("/resolve")
def alert_resolve(body: ResolveBody, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    _upsert_alert_state(db, body.asset_key, "resolved")
    return {"ok": True, "asset_key": body.asset_key, "state": "resolved"}


@router.post("/assign")
def alert_assign(body: AssignBody, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    _upsert_alert_state(db, body.asset_key, "assigned", assigned_to=body.assigned_to)
    return {"ok": True, "asset_key": body.asset_key, "assigned_to": body.assigned_to}
