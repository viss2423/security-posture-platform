"""Telemetry and event-alert APIs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.alerts_v2 import (
    reopen_expired_suppressed_alerts,
    serialize_security_alert,
    transition_security_alert,
)
from app.db import get_db
from app.routers.auth import get_current_role, require_auth, require_role
from app.telemetry import SUPPORTED_TELEMETRY_SOURCES, ingest_telemetry_events

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


def _safe_json(value: Any, *, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return default
        if isinstance(parsed, type(default)):
            return parsed
    return default


def _serialize_event(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("event_time", "created_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["mitre_techniques"] = _safe_json(out.get("mitre_techniques"), default=[])
    out["payload_json"] = _safe_json(out.get("payload_json"), default={})
    return out


@router.get("/summary")
def telemetry_summary(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    reopen_expired_suppressed_alerts(db)
    source_rows = (
        db.execute(
            text(
                """
                SELECT
                  source,
                  COUNT(*) AS event_count,
                  COUNT(*) FILTER (WHERE ti_match = TRUE) AS ti_matches,
                  COUNT(DISTINCT asset_key) FILTER (WHERE asset_key IS NOT NULL) AS asset_count,
                  MAX(event_time) AS last_event_at
                FROM security_events
                GROUP BY source
                ORDER BY event_count DESC
                """
            )
        )
        .mappings()
        .all()
    )
    alert_rows = (
        db.execute(
            text(
                """
                SELECT
                  source,
                  status,
                  COUNT(*) AS count
                FROM security_alerts
                GROUP BY source, status
                """
            )
        )
        .mappings()
        .all()
    )
    anomaly_rows = (
        db.execute(
            text(
                """
                SELECT asset_key, anomaly_score, baseline_mean, baseline_std, current_value, computed_at
                FROM asset_anomaly_scores
                ORDER BY computed_at DESC
                LIMIT 20
                """
            )
        )
        .mappings()
        .all()
    )
    recent_alerts = (
        db.execute(
            text(
                """
                SELECT *
                FROM security_alerts
                ORDER BY last_seen_at DESC
                LIMIT 12
                """
            )
        )
        .mappings()
        .all()
    )
    totals = (
        db.execute(
            text(
                """
                SELECT
                  COUNT(*) AS total_events,
                  COUNT(*) FILTER (WHERE ti_match = TRUE) AS total_ti_matches,
                  COUNT(DISTINCT asset_key) FILTER (WHERE asset_key IS NOT NULL) AS active_assets
                FROM security_events
                """
            )
        )
        .mappings()
        .first()
        or {}
    )
    by_source_status: dict[str, dict[str, int]] = {}
    for item in alert_rows:
        source = str(item.get("source") or "unknown")
        by_source_status.setdefault(
            source, {"firing": 0, "acked": 0, "suppressed": 0, "resolved": 0}
        )
        status = str(item.get("status") or "firing")
        if status in by_source_status[source]:
            by_source_status[source][status] = int(item.get("count") or 0)

    return {
        "totals": {
            "events": int(totals.get("total_events") or 0),
            "ti_matches": int(totals.get("total_ti_matches") or 0),
            "assets": int(totals.get("active_assets") or 0),
            "sources": len(source_rows),
        },
        "sources": [
            {
                "source": item.get("source"),
                "event_count": int(item.get("event_count") or 0),
                "ti_matches": int(item.get("ti_matches") or 0),
                "asset_count": int(item.get("asset_count") or 0),
                "last_event_at": item.get("last_event_at").isoformat()
                if hasattr(item.get("last_event_at"), "isoformat")
                else item.get("last_event_at"),
                "alerts": by_source_status.get(str(item.get("source") or "unknown"), {}),
            }
            for item in source_rows
        ],
        "recent_alerts": [serialize_security_alert(dict(item)) for item in recent_alerts],
        "latest_anomaly_scores": [
            {
                **dict(item),
                "computed_at": item.get("computed_at").isoformat()
                if hasattr(item.get("computed_at"), "isoformat")
                else item.get("computed_at"),
            }
            for item in anomaly_rows
        ],
    }


@router.get("/events")
def list_telemetry_events(
    source: str | None = Query(None),
    asset_key: str | None = Query(None),
    ti_match: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
    role: str = Depends(get_current_role),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if source:
        normalized_source = source.strip().lower()
        if normalized_source == "cowrie" and role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        clauses.append("source = :source")
        params["source"] = normalized_source
    elif role != "admin":
        clauses.append("source <> 'cowrie'")
    if asset_key:
        clauses.append("asset_key = :asset_key")
        params["asset_key"] = asset_key.strip()
    if ti_match is not None:
        clauses.append("ti_match = :ti_match")
        params["ti_match"] = bool(ti_match)
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT *
                FROM security_events
                WHERE {where}
                ORDER BY event_time DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_event(dict(row)) for row in rows]}


@router.get("/assets/{asset_key}")
def telemetry_asset_logs(
    asset_key: str,
    source: str | None = Query(None),
    limit: int = Query(150, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
    role: str = Depends(get_current_role),
):
    normalized_asset_key = (asset_key or "").strip()
    if not normalized_asset_key:
        raise HTTPException(status_code=400, detail="asset_key required")
    clauses = ["asset_key = :asset_key"]
    params: dict[str, Any] = {"asset_key": normalized_asset_key, "limit": int(limit)}
    if source:
        normalized_source = source.strip().lower()
        if normalized_source == "cowrie" and role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        clauses.append("source = :source")
        params["source"] = normalized_source
    elif role != "admin":
        clauses.append("source <> 'cowrie'")
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT *
                FROM security_events
                WHERE {where}
                ORDER BY event_time DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    return {
        "asset_key": normalized_asset_key,
        "items": [_serialize_event(dict(row)) for row in rows],
    }


class TelemetryIngestBody(BaseModel):
    source: str
    events: list[dict[str, Any]] = Field(default_factory=list)
    asset_key: str | None = None
    create_alerts: bool = True


@router.post("/ingest")
def ingest_telemetry(
    body: TelemetryIngestBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    source = body.source.strip().lower()
    if source not in SUPPORTED_TELEMETRY_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported telemetry source")
    if not body.events:
        raise HTTPException(status_code=400, detail="events cannot be empty")
    summary = ingest_telemetry_events(
        db,
        source=source,
        events=body.events,
        default_asset_key=body.asset_key,
        create_alerts=body.create_alerts,
    )
    db.commit()
    return {"ok": True, **summary}


@router.get("/alerts")
def list_event_alerts(
    status: str | None = Query(None),
    source: str | None = Query(None),
    asset_key: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    reopen_expired_suppressed_alerts(db)
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit), "now": datetime.now(UTC)}
    if status:
        clauses.append("status = :status")
        params["status"] = status.strip().lower()
    if source:
        clauses.append("source = :source")
        params["source"] = source.strip().lower()
    if asset_key:
        clauses.append("asset_key = :asset_key")
        params["asset_key"] = asset_key.strip()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT *
                FROM security_alerts
                WHERE {where}
                ORDER BY
                  CASE status
                    WHEN 'firing' THEN 0
                    WHEN 'acked' THEN 1
                    WHEN 'suppressed' THEN 2
                    ELSE 3
                  END,
                  last_seen_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    grouped = {"firing": [], "acked": [], "suppressed": [], "resolved": []}
    for row in rows:
        item = serialize_security_alert(dict(row))
        status_value = str(item.get("status") or "firing")
        grouped.setdefault(status_value, [])
        grouped[status_value].append(item)
    return grouped


class AlertTransitionBody(BaseModel):
    alert_id: int
    reason: str | None = None
    until_iso: str | None = None
    assigned_to: str | None = None


@router.post("/alerts/ack")
def ack_event_alert(
    body: AlertTransitionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    row = transition_security_alert(
        db,
        alert_id=int(body.alert_id),
        action="ack",
        user_name=user,
        reason=body.reason,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.commit()
    return {"ok": True, "item": row}


@router.post("/alerts/suppress")
def suppress_event_alert(
    body: AlertTransitionBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    if not body.until_iso:
        raise HTTPException(status_code=400, detail="until_iso required")
    try:
        until = datetime.fromisoformat(body.until_iso.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid until_iso") from exc
    row = transition_security_alert(
        db,
        alert_id=int(body.alert_id),
        action="suppress",
        reason=body.reason,
        until=until,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.commit()
    return {"ok": True, "item": row}


@router.post("/alerts/resolve")
def resolve_event_alert(
    body: AlertTransitionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    row = transition_security_alert(
        db,
        alert_id=int(body.alert_id),
        action="resolve",
        user_name=user,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.commit()
    return {"ok": True, "item": row}


@router.post("/alerts/assign")
def assign_event_alert(
    body: AlertTransitionBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    row = transition_security_alert(
        db,
        alert_id=int(body.alert_id),
        action="assign",
        assigned_to=body.assigned_to,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.commit()
    return {"ok": True, "item": row}
