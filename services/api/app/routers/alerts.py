"""Alert lifecycle and alert queue enrichment."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth, require_role
from app.routers.posture import _fetch_posture_list_raw
from app.schemas.posture import raw_to_asset_state

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _normalize_criticality(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        if value <= 2:
            return "high"
        if value <= 3:
            return "medium"
        return "low"
    text_value = str(value).strip().lower()
    if not text_value:
        return None
    if text_value.isdigit():
        return _normalize_criticality(int(text_value))
    if text_value in ("high", "medium", "low"):
        return text_value
    return "medium"


def _serialize_datetimes(row: dict, keys: tuple[str, ...]) -> dict:
    out = dict(row)
    for key in keys:
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def _sql_in_params(prefix: str, values: list[str]) -> tuple[str, dict[str, str]]:
    placeholders = ", ".join(f":{prefix}{idx}" for idx in range(len(values)))
    return placeholders, {f"{prefix}{idx}": value for idx, value in enumerate(values)}


def _get_alert_states(db: Session) -> dict:
    """Return dict asset_key -> { state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at }."""
    q = text(
        "SELECT asset_key, state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at FROM alert_states"
    )
    rows = db.execute(q).mappings().all()
    return {r["asset_key"]: dict(r) for r in rows}


def _get_asset_metadata(db: Session, asset_keys: list[str]) -> dict[str, dict]:
    if not asset_keys:
        return {}
    placeholders, params = _sql_in_params("ak", asset_keys)
    rows = db.execute(
        text(
            f"""
            SELECT asset_key, name, owner, environment, criticality, type, verified
            FROM assets
            WHERE asset_key IN ({placeholders})
            """
        ),
        params,
    ).mappings()
    out: dict[str, dict] = {}
    for row in rows:
        out[row["asset_key"]] = {
            "asset_name": row.get("name"),
            "owner": row.get("owner"),
            "environment": row.get("environment"),
            "criticality": _normalize_criticality(row.get("criticality")),
            "asset_type": row.get("type"),
            "verified": row.get("verified"),
        }
    return out


def _posture_map(raw_items: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for raw in raw_items:
        asset_key = raw.get("asset_key") or raw.get("asset_id")
        if not asset_key:
            continue
        try:
            state = raw_to_asset_state(raw)
        except (ValueError, KeyError):
            continue
        out[str(asset_key)] = {
            "posture_status": state.status,
            "posture_score": state.posture_score,
            "reason": state.reason,
            "last_seen": state.last_seen.isoformat() if state.last_seen else None,
            "staleness_seconds": state.staleness_seconds,
        }
    return out


def _active_maintenance_map(
    db: Session, asset_keys: list[str], now: datetime
) -> dict[str, list[dict]]:
    out = {asset_key: [] for asset_key in asset_keys}
    if not asset_keys:
        return out
    placeholders, params = _sql_in_params("mw", asset_keys)
    params["now"] = now
    rows = db.execute(
        text(
            f"""
            SELECT id, asset_key, start_at, end_at, reason, created_by, created_at
            FROM maintenance_windows
            WHERE asset_key IN ({placeholders})
              AND :now >= start_at
              AND :now <= end_at
            ORDER BY end_at ASC
            """
        ),
        params,
    ).mappings()
    for row in rows:
        out[row["asset_key"]].append(
            _serialize_datetimes(dict(row), ("start_at", "end_at", "created_at"))
        )
    return out


def _active_suppression_map(
    db: Session, asset_keys: list[str], now: datetime
) -> dict[str, list[dict]]:
    out = {asset_key: [] for asset_key in asset_keys}
    if not asset_keys:
        return out
    placeholders, params = _sql_in_params("sr", asset_keys)
    params["now"] = now
    rows = db.execute(
        text(
            f"""
            SELECT id, scope, scope_value, starts_at, ends_at, reason, created_by, created_at
            FROM suppression_rules
            WHERE :now >= starts_at
              AND :now <= ends_at
              AND (
                scope = 'all'
                OR (scope = 'asset' AND scope_value IN ({placeholders}))
              )
            ORDER BY ends_at ASC
            """
        ),
        params,
    ).mappings()
    for row in rows:
        item = _serialize_datetimes(dict(row), ("starts_at", "ends_at", "created_at"))
        if row.get("scope") == "all":
            for asset_key in asset_keys:
                out[asset_key].append(item)
        else:
            scoped_asset = row.get("scope_value")
            if scoped_asset in out:
                out[scoped_asset].append(item)
    return out


def _active_finding_summary_map(db: Session, asset_keys: list[str]) -> dict[str, dict]:
    out = {
        asset_key: {
            "active_finding_count": 0,
            "top_risk_score": None,
            "top_risk_level": None,
        }
        for asset_key in asset_keys
    }
    if not asset_keys:
        return out
    placeholders, params = _sql_in_params("fk", asset_keys)
    rows = db.execute(
        text(
            f"""
            WITH ranked_findings AS (
              SELECT
                a.asset_key,
                f.risk_score,
                f.risk_level,
                ROW_NUMBER() OVER (
                  PARTITION BY a.asset_key
                  ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
                ) AS rn
              FROM assets a
              JOIN findings f ON f.asset_id = a.asset_id
              WHERE a.asset_key IN ({placeholders})
                AND COALESCE(f.status, 'open') <> 'remediated'
            ),
            counts AS (
              SELECT
                a.asset_key,
                COUNT(*) AS active_finding_count
              FROM assets a
              JOIN findings f ON f.asset_id = a.asset_id
              WHERE a.asset_key IN ({placeholders})
                AND COALESCE(f.status, 'open') <> 'remediated'
              GROUP BY a.asset_key
            )
            SELECT
              c.asset_key,
              c.active_finding_count,
              r.risk_score AS top_risk_score,
              r.risk_level AS top_risk_level
            FROM counts c
            LEFT JOIN ranked_findings r
              ON r.asset_key = c.asset_key
             AND r.rn = 1
            """
        ),
        params,
    ).mappings()
    for row in rows:
        out[row["asset_key"]] = {
            "active_finding_count": int(row.get("active_finding_count") or 0),
            "top_risk_score": int(row["top_risk_score"])
            if row.get("top_risk_score") is not None
            else None,
            "top_risk_level": row.get("top_risk_level"),
        }
    return out


def _open_incident_summary_map(db: Session, asset_keys: list[str]) -> dict[str, dict]:
    out = {
        asset_key: {
            "open_incident_count": 0,
            "open_incident_ids": [],
            "open_incident_severities": [],
        }
        for asset_key in asset_keys
    }
    if not asset_keys:
        return out
    placeholders, params = _sql_in_params("ia", asset_keys)
    rows = db.execute(
        text(
            f"""
            SELECT
              ia.asset_key,
              COUNT(*) AS open_incident_count,
              ARRAY_AGG(i.id ORDER BY i.created_at DESC) AS open_incident_ids,
              ARRAY_AGG(i.severity ORDER BY i.created_at DESC) AS open_incident_severities
            FROM incident_alerts ia
            JOIN incidents i ON i.id = ia.incident_id
            WHERE ia.asset_key IN ({placeholders})
              AND i.status NOT IN ('resolved', 'closed')
            GROUP BY ia.asset_key
            """
        ),
        params,
    ).mappings()
    for row in rows:
        out[row["asset_key"]] = {
            "open_incident_count": int(row.get("open_incident_count") or 0),
            "open_incident_ids": list(row.get("open_incident_ids") or []),
            "open_incident_severities": list(row.get("open_incident_severities") or []),
        }
    return out


def _alert_ai_summary_map(db: Session, asset_keys: list[str]) -> dict[str, dict]:
    out = {
        asset_key: {
            "ai_recommended_action": None,
            "ai_urgency": None,
            "ai_generated_at": None,
        }
        for asset_key in asset_keys
    }
    if not asset_keys:
        return out
    placeholders, params = _sql_in_params("ag", asset_keys)
    rows = db.execute(
        text(
            f"""
            SELECT asset_key, recommended_action, urgency, generated_at
            FROM alert_ai_guidance
            WHERE asset_key IN ({placeholders})
            """
        ),
        params,
    ).mappings()
    for row in rows:
        out[row["asset_key"]] = {
            "ai_recommended_action": row.get("recommended_action"),
            "ai_urgency": row.get("urgency"),
            "ai_generated_at": row.get("generated_at").isoformat()
            if hasattr(row.get("generated_at"), "isoformat")
            else None,
        }
    return out


def _load_alert_enrichment(
    db: Session,
    asset_keys: list[str],
    *,
    posture_items: list[dict] | None = None,
    now: datetime | None = None,
) -> dict[str, dict]:
    normalized_keys = sorted(
        {(asset_key or "").strip() for asset_key in asset_keys if asset_key and asset_key.strip()}
    )
    if not normalized_keys:
        return {}
    active_now = now or datetime.now(UTC)
    if posture_items is None:
        _total, posture_items = _fetch_posture_list_raw()
    posture = _posture_map(posture_items)
    metadata = _get_asset_metadata(db, normalized_keys)
    maintenance = _active_maintenance_map(db, normalized_keys, active_now)
    suppressions = _active_suppression_map(db, normalized_keys, active_now)
    findings = _active_finding_summary_map(db, normalized_keys)
    incidents = _open_incident_summary_map(db, normalized_keys)
    ai_summary = _alert_ai_summary_map(db, normalized_keys)

    out: dict[str, dict] = {}
    for asset_key in normalized_keys:
        item = {
            "asset_name": None,
            "owner": None,
            "environment": None,
            "criticality": None,
            "asset_type": None,
            "verified": None,
            "posture_status": None,
            "posture_score": None,
            "reason": None,
            "last_seen": None,
            "staleness_seconds": None,
            "active_finding_count": 0,
            "top_risk_score": None,
            "top_risk_level": None,
            "open_incident_count": 0,
            "open_incident_ids": [],
            "open_incident_severities": [],
            "maintenance_active": False,
            "maintenance_reason": None,
            "maintenance_end_at": None,
            "suppression_rule_active": False,
            "suppression_reason": None,
            "suppression_end_at": None,
            "ai_recommended_action": None,
            "ai_urgency": None,
            "ai_generated_at": None,
        }
        item.update(metadata.get(asset_key) or {})
        item.update(posture.get(asset_key) or {})
        item.update(findings.get(asset_key) or {})
        item.update(incidents.get(asset_key) or {})
        item.update(ai_summary.get(asset_key) or {})

        maintenance_items = maintenance.get(asset_key) or []
        if maintenance_items:
            next_window = maintenance_items[0]
            item["maintenance_active"] = True
            item["maintenance_reason"] = next_window.get("reason")
            item["maintenance_end_at"] = next_window.get("end_at")

        suppression_items = suppressions.get(asset_key) or []
        if suppression_items:
            next_rule = suppression_items[0]
            item["suppression_rule_active"] = True
            item["suppression_reason"] = next_rule.get("reason")
            item["suppression_end_at"] = next_rule.get("ends_at")

        out[asset_key] = item
    return out


def _upsert_alert_state(
    db: Session,
    asset_key: str,
    state: str,
    ack_reason: str | None = None,
    acked_by: str | None = None,
    suppressed_until: datetime | None = None,
    assigned_to: str | None = None,
) -> None:
    now = datetime.now(UTC)
    if state == "acked":
        q = text("""
            INSERT INTO alert_states (asset_key, state, ack_reason, acked_by, acked_at, updated_at)
            VALUES (:asset_key, 'acked', :ack_reason, :acked_by, :now, :now)
            ON CONFLICT (asset_key) DO UPDATE SET
              state = 'acked', ack_reason = :ack_reason, acked_by = :acked_by, acked_at = :now,
              suppressed_until = NULL, updated_at = :now
        """)
        db.execute(
            q,
            {
                "asset_key": asset_key,
                "ack_reason": ack_reason or "",
                "acked_by": acked_by,
                "now": now,
            },
        )
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
    states_map = _get_alert_states(db)
    now = datetime.now(UTC)
    _total, raw_items = _fetch_posture_list_raw()
    posture = _posture_map(raw_items)
    down_assets = sorted(
        asset_key for asset_key, item in posture.items() if item.get("posture_status") == "red"
    )
    candidate_asset_keys = sorted(set(down_assets) | set(states_map.keys()))
    enrichment = _load_alert_enrichment(db, candidate_asset_keys, posture_items=raw_items, now=now)

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
        item = {
            "asset_key": asset_key,
            **(enrichment.get(asset_key) or {}),
        }
        if row:
            item.update(_serialize(row))
        else:
            item.setdefault("state", "firing")
        if (
            item.get("maintenance_active")
            or item.get("suppression_rule_active")
            or (sup_until and (sup_until if hasattr(sup_until, "tzinfo") else sup_until) > now)
        ):
            item["state"] = "suppressed"
            if sup_until and hasattr(sup_until, "isoformat"):
                item["suppressed_until"] = sup_until.isoformat()
            suppressed.append(item)
            continue
        if row and row.get("state") == "acked":
            item["state"] = "acked"
            acked.append(item)
            continue
        item["state"] = "firing"
        firing.append(item)

    for asset_key, row in states_map.items():
        if asset_key in down_assets:
            continue
        item = {
            "asset_key": asset_key,
            **(enrichment.get(asset_key) or {}),
            **_serialize(row),
        }
        sup_until = row.get("suppressed_until")
        if (
            item.get("maintenance_active")
            or item.get("suppression_rule_active")
            or (
                row.get("state") == "suppressed"
                and sup_until
                and (sup_until if hasattr(sup_until, "tzinfo") else sup_until) > now
            )
        ):
            item["state"] = "suppressed"
            suppressed.append(item)
        elif row.get("state") == "resolved":
            item["state"] = "resolved"
            resolved.append(item)
        elif row.get("state") == "acked":
            item["state"] = "acked"
            acked.append(item)
        elif row.get("state") == "firing":
            item["state"] = "firing"
            firing.append(item)
        else:
            item.setdefault("state", row.get("state") or "resolved")
            resolved.append(item)

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
def alert_ack(
    body: AckBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    _upsert_alert_state(db, body.asset_key, "acked", ack_reason=body.reason, acked_by=user)
    return {"ok": True, "asset_key": body.asset_key, "state": "acked"}


@router.post("/suppress")
def alert_suppress(
    body: SuppressBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    try:
        until = datetime.fromisoformat(body.until_iso.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid until_iso; use ISO datetime")
    _upsert_alert_state(db, body.asset_key, "suppressed", suppressed_until=until)
    return {
        "ok": True,
        "asset_key": body.asset_key,
        "state": "suppressed",
        "suppressed_until": body.until_iso,
    }


@router.post("/resolve")
def alert_resolve(
    body: ResolveBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    _upsert_alert_state(db, body.asset_key, "resolved")
    return {"ok": True, "asset_key": body.asset_key, "state": "resolved"}


@router.post("/assign")
def alert_assign(
    body: AssignBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    _upsert_alert_state(db, body.asset_key, "assigned", assigned_to=body.assigned_to)
    return {"ok": True, "asset_key": body.asset_key, "assigned_to": body.assigned_to}
