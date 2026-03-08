"""Incidents: SOC workflow — group alerts, state machine, notes, SLA (Phase A.1). B.4: Jira ticket from incident."""

import base64
import json
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role
from app.settings import settings
from app.timeline_aggregator import build_incident_timeline

router = APIRouter(prefix="/incidents", tags=["incidents"])

VALID_STATUS = ("new", "triaged", "contained", "resolved", "closed")
VALID_SEVERITY = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _coerce_json_value(value, *, default):
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


def _severity_meets_threshold(value: str | None, threshold: str | None) -> bool:
    lhs = SEVERITY_RANK.get(str(value or "medium").strip().lower(), SEVERITY_RANK["medium"])
    rhs = SEVERITY_RANK.get(str(threshold or "high").strip().lower(), SEVERITY_RANK["high"])
    return lhs >= rhs


def _serialize_incident(row: dict) -> dict:
    out = dict(row)
    for k in ("created_at", "updated_at", "resolved_at", "closed_at", "sla_due_at", "added_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    if "metadata" in out:
        out["metadata"] = _coerce_json_value(out.get("metadata"), default={})
    return out


def _serialize_note(row: dict) -> dict:
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    if "details" in out:
        out["details"] = _coerce_json_value(out.get("details"), default={})
    return out


def _serialize_linked_risk_finding(row: dict) -> dict:
    out = dict(row)
    for key in ("first_seen", "last_seen", "accepted_risk_at", "accepted_risk_expires_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["risk_factors_json"] = _coerce_json_value(out.get("risk_factors_json"), default={})
    return out


def _load_incident_linked_risk(db: Session, incident_id: int, *, limit: int = 5) -> dict:
    asset_count = (
        db.execute(
            text("SELECT COUNT(*) FROM incident_alerts WHERE incident_id = :id"),
            {"id": incident_id},
        ).scalar()
        or 0
    )
    if asset_count == 0:
        return {
            "asset_count": 0,
            "finding_count": 0,
            "active_finding_count": 0,
            "top_risk_score": None,
            "top_risk_level": None,
            "items": [],
        }

    findings_rows = (
        db.execute(
            text(
                """
            SELECT
              f.finding_id, f.finding_key, f.asset_id,
              a.asset_key, a.name AS asset_name,
              COALESCE(f.first_seen, f.time) AS first_seen,
              COALESCE(f.last_seen, f.time) AS last_seen,
              COALESCE(f.status, 'open') AS status,
              f.source,
              f.category, f.title, f.severity, f.confidence, f.evidence, f.remediation,
              f.risk_score, f.risk_level, f.risk_factors_json,
              f.accepted_risk_at, f.accepted_risk_expires_at, f.accepted_risk_reason, f.accepted_risk_by
            FROM incident_alerts ia
            JOIN assets a ON a.asset_key = ia.asset_key
            JOIN findings f ON f.asset_id = a.asset_id
            WHERE ia.incident_id = :id
            ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
            LIMIT :limit
            """
            ),
            {"id": incident_id, "limit": limit},
        )
        .mappings()
        .all()
    )
    items = [_serialize_linked_risk_finding(dict(row)) for row in findings_rows]

    summary_row = (
        db.execute(
            text(
                """
            SELECT
              COUNT(*) AS finding_count,
              COUNT(*) FILTER (WHERE COALESCE(f.status, 'open') <> 'remediated') AS active_finding_count,
              MAX(f.risk_score) AS top_risk_score
            FROM incident_alerts ia
            JOIN assets a ON a.asset_key = ia.asset_key
            JOIN findings f ON f.asset_id = a.asset_id
            WHERE ia.incident_id = :id
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .first()
        or {}
    )

    top_risk_score = summary_row.get("top_risk_score")
    return {
        "asset_count": int(asset_count),
        "finding_count": int(summary_row.get("finding_count") or 0),
        "active_finding_count": int(summary_row.get("active_finding_count") or 0),
        "top_risk_score": int(top_risk_score) if top_risk_score is not None else None,
        "top_risk_level": items[0].get("risk_level") if items else None,
        "items": items,
    }


def _serialize_evidence(row: dict) -> dict:
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    out["details"] = _coerce_json_value(out.get("details"), default={})
    return out


def _serialize_watcher(row: dict) -> dict:
    out = dict(row)
    if hasattr(out.get("added_at"), "isoformat"):
        out["added_at"] = out["added_at"].isoformat()
    return out


def _serialize_checklist_item(row: dict) -> dict:
    out = dict(row)
    for key in ("done_at", "created_at", "updated_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def _serialize_decision(row: dict) -> dict:
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    out["details"] = _coerce_json_value(out.get("details"), default={})
    return out


def _parse_csv_filter(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    values = {str(item).strip().lower() for item in str(raw).split(",") if str(item).strip()}
    return values or None


def _incident_timeline_aggregated(
    db: Session,
    incident_id: int,
    *,
    lookback_hours: int = 72,
    source_limit: int = 140,
    source_types: set[str] | None = None,
    event_types: set[str] | None = None,
    limit_total: int | None = None,
) -> list[dict]:
    return build_incident_timeline(
        db,
        incident_id=int(incident_id),
        lookback_hours=lookback_hours,
        source_limit=source_limit,
        source_types=source_types,
        event_types=event_types,
        limit_total=limit_total,
    )


def _insert_incident_evidence(
    db: Session,
    *,
    incident_id: int,
    evidence_type: str,
    ref_id: str,
    relation: str = "linked",
    summary: str | None = None,
    details: dict | None = None,
    added_by: str | None = None,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO incident_evidence (
              incident_id, evidence_type, ref_id, relation, summary, details, added_by
            )
            VALUES (
              :incident_id, :evidence_type, :ref_id, :relation, :summary,
              CAST(:details AS jsonb), :added_by
            )
            ON CONFLICT (incident_id, evidence_type, ref_id, relation) DO NOTHING
            """
        ),
        {
            "incident_id": int(incident_id),
            "evidence_type": evidence_type,
            "ref_id": str(ref_id),
            "relation": str(relation or "linked"),
            "summary": summary,
            "details": json.dumps(details or {}),
            "added_by": added_by,
        },
    )


def _has_open_incident_for_asset(db: Session, asset_key: str) -> bool:
    row = db.execute(
        text(
            """
                SELECT 1
                FROM incident_alerts ia
                JOIN incidents i ON i.id = ia.incident_id
                WHERE ia.asset_key = :asset_key
                  AND i.status NOT IN ('resolved', 'closed')
                LIMIT 1
                """
        ),
        {"asset_key": asset_key},
    ).first()
    return row is not None


def _run_incident_auto_rules(db: Session, *, user: str) -> dict:
    rules = (
        db.execute(
            text(
                """
                SELECT
                  auto_rule_id,
                  name,
                  description,
                  enabled,
                  severity_threshold,
                  window_minutes,
                  min_alerts,
                  require_distinct_sources,
                  incident_severity
                FROM incident_auto_rules
                WHERE enabled = TRUE
                ORDER BY auto_rule_id ASC
                """
            )
        )
        .mappings()
        .all()
    )
    triggered: list[dict] = []
    created_incident_ids: list[int] = []
    for rule in rules:
        window_minutes = max(1, int(rule.get("window_minutes") or 15))
        min_alerts = max(1, int(rule.get("min_alerts") or 2))
        threshold = str(rule.get("severity_threshold") or "high").strip().lower()
        rows = (
            db.execute(
                text(
                    """
                    SELECT
                      asset_key,
                      COUNT(*) AS alert_count,
                      COUNT(DISTINCT source) AS source_count,
                      ARRAY_AGG(alert_id ORDER BY last_seen_at DESC) AS alert_ids,
                      ARRAY_AGG(source ORDER BY last_seen_at DESC) AS sources
                    FROM security_alerts
                    WHERE status IN ('firing', 'acked')
                      AND asset_key IS NOT NULL
                      AND asset_key <> ''
                      AND last_seen_at >= NOW() - (:window_minutes * INTERVAL '1 minute')
                    GROUP BY asset_key
                    """
                ),
                {"window_minutes": window_minutes},
            )
            .mappings()
            .all()
        )
        for row in rows:
            asset_key = str(row.get("asset_key") or "").strip()
            if not asset_key:
                continue
            alert_ids = [int(alert_id) for alert_id in (row.get("alert_ids") or []) if alert_id]
            if len(alert_ids) < min_alerts:
                continue
            source_count = int(row.get("source_count") or 0)
            if bool(rule.get("require_distinct_sources")) and source_count < 2:
                continue
            matching_alerts: list[dict] = []
            for alert_id in alert_ids:
                alert_match = (
                    db.execute(
                        text(
                            """
                            SELECT alert_id, severity
                            FROM security_alerts
                            WHERE alert_id = :alert_id
                            """
                        ),
                        {"alert_id": alert_id},
                    )
                    .mappings()
                    .first()
                )
                if alert_match:
                    matching_alerts.append(dict(alert_match))
            if not matching_alerts:
                continue
            if not any(
                _severity_meets_threshold(alert.get("severity"), threshold)
                for alert in matching_alerts
            ):
                continue
            if _has_open_incident_for_asset(db, asset_key):
                continue

            incident_title = (
                f"Auto incident: {asset_key} ({len(alert_ids)} alerts in {window_minutes}m)"
            )
            incident_row = (
                db.execute(
                    text(
                        """
                        INSERT INTO incidents (
                          title, severity, status, assigned_to, updated_at, metadata
                        )
                        VALUES (
                          :title, :severity, 'new', NULL, NOW(), CAST(:metadata AS jsonb)
                        )
                        RETURNING id
                        """
                    ),
                    {
                        "title": incident_title,
                        "severity": str(rule.get("incident_severity") or "high").strip().lower(),
                        "metadata": json.dumps(
                            {
                                "auto_rule_id": int(rule.get("auto_rule_id")),
                                "auto_rule_name": rule.get("name"),
                                "window_minutes": window_minutes,
                                "min_alerts": min_alerts,
                            }
                        ),
                    },
                )
                .mappings()
                .first()
            )
            if not incident_row:
                continue
            incident_id = int(incident_row["id"])
            created_incident_ids.append(incident_id)

            for alert_id in alert_ids:
                alert_asset_row = (
                    db.execute(
                        text(
                            """
                            SELECT asset_key
                            FROM security_alerts
                            WHERE alert_id = :alert_id
                            """
                        ),
                        {"alert_id": alert_id},
                    )
                    .mappings()
                    .first()
                )
                derived_asset_key = str(alert_asset_row.get("asset_key") or asset_key)
                db.execute(
                    text(
                        """
                        INSERT INTO incident_alerts (incident_id, asset_key, alert_id, added_by)
                        VALUES (:incident_id, :asset_key, :alert_id, :added_by)
                        ON CONFLICT (incident_id, asset_key) DO NOTHING
                        """
                    ),
                    {
                        "incident_id": incident_id,
                        "asset_key": derived_asset_key,
                        "alert_id": alert_id,
                        "added_by": user,
                    },
                )
                _insert_incident_evidence(
                    db,
                    incident_id=incident_id,
                    evidence_type="alert",
                    ref_id=str(alert_id),
                    relation="triggered_by",
                    summary="Auto-linked alert evidence",
                    details={"auto_rule_id": int(rule.get("auto_rule_id"))},
                    added_by=user,
                )
            _insert_incident_evidence(
                db,
                incident_id=incident_id,
                evidence_type="asset",
                ref_id=asset_key,
                relation="impacted_asset",
                summary="Auto-linked impacted asset",
                details={"source_count": source_count},
                added_by=user,
            )
            db.execute(
                text(
                    """
                    INSERT INTO incident_notes (incident_id, event_type, author, details)
                    VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
                    """
                ),
                {
                    "incident_id": incident_id,
                    "author": user,
                    "details": json.dumps(
                        {
                            "auto_rule_id": int(rule.get("auto_rule_id")),
                            "asset_key": asset_key,
                            "alert_ids": alert_ids,
                        }
                    ),
                },
            )
            triggered.append(
                {
                    "auto_rule_id": int(rule.get("auto_rule_id")),
                    "incident_id": incident_id,
                    "asset_key": asset_key,
                    "alert_ids": alert_ids,
                    "source_count": source_count,
                }
            )
    return {
        "rules_evaluated": len(rules),
        "incidents_created": len(created_incident_ids),
        "incident_ids": created_incident_ids,
        "triggered": triggered,
    }


@router.get("")
def list_incidents(
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    assigned_to: str | None = Query(None, description="Filter by assignee"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List incidents with optional filters. Newest first."""
    if status and status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if severity and severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    conditions = ["1=1"]
    params = {"limit": limit, "offset": offset}
    if status:
        conditions.append("i.status = :status")
        params["status"] = status
    if severity:
        conditions.append("i.severity = :severity")
        params["severity"] = severity
    if assigned_to:
        conditions.append("i.assigned_to = :assigned_to")
        params["assigned_to"] = assigned_to

    where = " AND ".join(conditions)
    q = text(f"""
        SELECT i.id, i.incident_key, i.title, i.severity, i.status, i.assigned_to,
               i.created_at, i.updated_at, i.resolved_at, i.closed_at, i.sla_due_at,
               (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count
        FROM incidents i
        WHERE {where}
        ORDER BY i.created_at DESC
        LIMIT :limit OFFSET :offset
    """)
    rows = db.execute(q, params).mappings().all()
    total_q = text(f"SELECT COUNT(*) AS n FROM incidents i WHERE {where}")
    total = db.execute(total_q, params).scalar() or 0

    return {
        "total": total,
        "items": [_serialize_incident(dict(r)) for r in rows],
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one incident with linked alerts and timeline (notes)."""
    q = text("""
        SELECT id, incident_key, title, severity, status, assigned_to,
               created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
        FROM incidents WHERE id = :id
    """)
    row = db.execute(q, {"id": incident_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = _serialize_incident(dict(row))

    alerts_q = text(
        "SELECT incident_id, asset_key, alert_id, added_at, added_by FROM incident_alerts WHERE incident_id = :id ORDER BY added_at"
    )
    alerts = db.execute(alerts_q, {"id": incident_id}).mappings().all()
    incident["alerts"] = [_serialize_incident(dict(a)) for a in alerts]

    incident["timeline"] = _incident_timeline_aggregated(db, incident_id)
    incident["linked_risk"] = _load_incident_linked_risk(db, incident_id)

    evidence_rows = (
        db.execute(
            text(
                """
            SELECT evidence_id, incident_id, evidence_type, ref_id, relation, summary, details, added_by, created_at
            FROM incident_evidence
            WHERE incident_id = :id
            ORDER BY created_at ASC, evidence_id ASC
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    incident["evidence"] = [_serialize_evidence(dict(row)) for row in evidence_rows]

    watcher_rows = (
        db.execute(
            text(
                """
            SELECT incident_id, username, added_by, added_at
            FROM incident_watchers
            WHERE incident_id = :id
            ORDER BY added_at ASC, username ASC
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    incident["watchers"] = [_serialize_watcher(dict(row)) for row in watcher_rows]

    checklist_rows = (
        db.execute(
            text(
                """
            SELECT item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at
            FROM incident_checklist_items
            WHERE incident_id = :id
            ORDER BY created_at ASC, item_id ASC
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    incident["checklist"] = [_serialize_checklist_item(dict(row)) for row in checklist_rows]

    decision_rows = (
        db.execute(
            text(
                """
            SELECT decision_id, incident_id, decision, rationale, decided_by, details, created_at
            FROM incident_decisions
            WHERE incident_id = :id
            ORDER BY created_at ASC, decision_id ASC
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    incident["decisions"] = [_serialize_decision(dict(row)) for row in decision_rows]

    return incident


class CreateIncidentBody(BaseModel):
    incident_key: str | None = None
    title: str
    severity: str = "medium"
    assigned_to: str | None = None
    sla_due_at: str | None = None  # ISO datetime
    asset_keys: list[str] | None = None  # link these alerts (asset_keys) to the incident
    alert_ids: list[int] | None = None  # link event alerts (security_alerts.alert_id)


@router.post("", status_code=201)
def create_incident(
    body: CreateIncidentBody,
    response: Response,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Create an incident (idempotent by incident_key) and optionally link alerts by asset_key."""
    if body.severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}")

    now = datetime.now(UTC)
    sla_due_at = None
    if body.sla_due_at:
        try:
            sla_due_at = datetime.fromisoformat(body.sla_due_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid sla_due_at format (use ISO 8601)")
    incident_key = (body.incident_key or "").strip() or None

    q = text("""
        INSERT INTO incidents (incident_key, title, severity, status, assigned_to, sla_due_at, updated_at)
        VALUES (:incident_key, :title, :severity, 'new', :assigned_to, :sla_due_at, :now)
        ON CONFLICT (incident_key) DO NOTHING
        RETURNING id, incident_key, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
    """)
    row = (
        db.execute(
            q,
            {
                "incident_key": incident_key,
                "title": body.title,
                "severity": body.severity,
                "assigned_to": body.assigned_to or None,
                "sla_due_at": sla_due_at,
                "now": now,
            },
        )
        .mappings()
        .first()
    )
    deduped = False
    if not row and incident_key:
        row = (
            db.execute(
                text(
                    """
                SELECT id, incident_key, title, severity, status, assigned_to, created_at, updated_at,
                       resolved_at, closed_at, sla_due_at, metadata
                FROM incidents
                WHERE incident_key = :incident_key
                """
                ),
                {"incident_key": incident_key},
            )
            .mappings()
            .first()
        )
        deduped = row is not None
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create incident")
    incident_id = row["id"]

    linked_asset_keys: list[str] = []
    if body.asset_keys:
        for asset_key in body.asset_keys:
            if not asset_key or not asset_key.strip():
                continue
            link_q = text("""
                INSERT INTO incident_alerts (incident_id, asset_key, added_by)
                VALUES (:incident_id, :asset_key, :added_by)
                ON CONFLICT (incident_id, asset_key) DO NOTHING
                RETURNING asset_key
            """)
            linked = (
                db.execute(
                    link_q,
                    {
                        "incident_id": incident_id,
                        "asset_key": asset_key.strip(),
                        "added_by": user,
                    },
                )
                .mappings()
                .first()
            )
            if linked and linked.get("asset_key"):
                linked_asset_keys.append(linked["asset_key"])
                _insert_incident_evidence(
                    db,
                    incident_id=incident_id,
                    evidence_type="asset",
                    ref_id=str(linked["asset_key"]),
                    relation="linked_asset",
                    summary="Asset linked during incident creation",
                    details={},
                    added_by=user,
                )
        if linked_asset_keys:
            # Timeline: one "alert_added" entry for this request's newly-linked assets.
            note_q = text("""
                INSERT INTO incident_notes (incident_id, event_type, author, details)
                VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
            """)
            db.execute(
                note_q,
                {
                    "incident_id": incident_id,
                    "author": user,
                    "details": json.dumps({"asset_keys": linked_asset_keys}),
                },
            )

    linked_alert_ids: list[int] = []
    if body.alert_ids:
        for alert_id in body.alert_ids:
            if not alert_id:
                continue
            alert_row = (
                db.execute(
                    text(
                        "SELECT alert_id, asset_key FROM security_alerts WHERE alert_id = :alert_id"
                    ),
                    {"alert_id": int(alert_id)},
                )
                .mappings()
                .first()
            )
            if not alert_row:
                continue
            derived_asset_key = str(alert_row.get("asset_key") or f"event:{int(alert_id)}")
            link_q = text("""
                INSERT INTO incident_alerts (incident_id, asset_key, alert_id, added_by)
                VALUES (:incident_id, :asset_key, :alert_id, :added_by)
                ON CONFLICT (incident_id, asset_key) DO NOTHING
                RETURNING alert_id
            """)
            linked = (
                db.execute(
                    link_q,
                    {
                        "incident_id": incident_id,
                        "asset_key": derived_asset_key,
                        "alert_id": int(alert_id),
                        "added_by": user,
                    },
                )
                .mappings()
                .first()
            )
            if linked and linked.get("alert_id") is not None:
                linked_alert_ids.append(int(linked["alert_id"]))
                _insert_incident_evidence(
                    db,
                    incident_id=incident_id,
                    evidence_type="alert",
                    ref_id=str(linked["alert_id"]),
                    relation="linked_alert",
                    summary="Alert linked during incident creation",
                    details={},
                    added_by=user,
                )
        if linked_alert_ids:
            note_q = text("""
                INSERT INTO incident_notes (incident_id, event_type, author, details)
                VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
            """)
            db.execute(
                note_q,
                {
                    "incident_id": incident_id,
                    "author": user,
                    "details": json.dumps({"alert_ids": linked_alert_ids}),
                },
            )

    db.commit()
    log_audit(
        db,
        "incident.dedupe_hit" if deduped else "incident.create",
        user_name=user,
        asset_key=None,
        details={
            "incident_id": incident_id,
            "title": body.title,
            "incident_key": incident_key,
            "deduped": deduped,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    if deduped:
        response.status_code = 200
    out = _serialize_incident(dict(row))
    out["deduped"] = deduped
    return out


class UpdateStatusBody(BaseModel):
    status: str


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    body: UpdateStatusBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Update incident status (state machine). Sets resolved_at/closed_at when appropriate."""
    if body.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    row = (
        db.execute(text("SELECT id, status FROM incidents WHERE id = :id"), {"id": incident_id})
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(UTC)
    resolved_at = None
    closed_at = None
    if body.status == "resolved":
        resolved_at = now
    elif body.status == "closed":
        closed_at = now
        # Also set resolved_at if not already
        existing = (
            db.execute(
                text("SELECT resolved_at FROM incidents WHERE id = :id"), {"id": incident_id}
            )
            .mappings()
            .first()
        )
        resolved_at = existing["resolved_at"] or now

    q = text("""
        UPDATE incidents
        SET status = :status, assigned_to = COALESCE(assigned_to, :assigned_to), updated_at = :now,
            resolved_at = COALESCE(resolved_at, :resolved_at), closed_at = COALESCE(closed_at, :closed_at)
        WHERE id = :id
        RETURNING id, incident_key, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at
    """)
    updated = (
        db.execute(
            q,
            {
                "id": incident_id,
                "status": body.status,
                "assigned_to": user,
                "now": now,
                "resolved_at": resolved_at,
                "closed_at": closed_at,
            },
        )
        .mappings()
        .first()
    )

    # Timeline: state_change
    note_q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, details)
        VALUES (:incident_id, 'state_change', :author, CAST(:details AS jsonb))
    """)
    import json

    db.execute(
        note_q,
        {
            "incident_id": incident_id,
            "author": user,
            "details": json.dumps({"from": row["status"], "to": body.status}),
        },
    )

    db.commit()
    log_audit(
        db,
        "incident.status.update",
        user_name=user,
        asset_key=None,
        details={"incident_id": incident_id, "status": body.status},
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    return _serialize_incident(dict(updated))


class AddNoteBody(BaseModel):
    body: str


@router.post("/{incident_id}/notes", status_code=201)
def add_incident_note(
    incident_id: int,
    body: AddNoteBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Add a note to the incident timeline."""
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")

    q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, body)
        VALUES (:incident_id, 'note', :author, :body)
        RETURNING id, incident_id, event_type, author, body, details, created_at
    """)
    row = (
        db.execute(q, {"incident_id": incident_id, "author": user, "body": body.body or ""})
        .mappings()
        .first()
    )
    db.execute(
        text("UPDATE incidents SET updated_at = :now WHERE id = :id"),
        {"now": datetime.now(UTC), "id": incident_id},
    )
    log_audit(
        db,
        "incident.note.create",
        user_name=user,
        details={"incident_id": incident_id, "note_id": int(row["id"]) if row else None},
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    return _serialize_note(dict(row))


class LinkAlertBody(BaseModel):
    asset_key: str | None = None
    alert_id: int | None = None


@router.post("/{incident_id}/alerts", status_code=201)
def link_alert(
    incident_id: int,
    body: LinkAlertBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Link an alert (by asset_key or alert_id) to this incident."""
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")

    asset_key = (body.asset_key or "").strip()
    alert_id = int(body.alert_id) if body.alert_id else None
    if not asset_key and not alert_id:
        raise HTTPException(status_code=400, detail="asset_key or alert_id required")
    if alert_id and not asset_key:
        alert_row = (
            db.execute(
                text("SELECT asset_key FROM security_alerts WHERE alert_id = :alert_id"),
                {"alert_id": alert_id},
            )
            .mappings()
            .first()
        )
        if not alert_row:
            raise HTTPException(status_code=404, detail="Alert not found")
        asset_key = str(alert_row.get("asset_key") or f"event:{alert_id}")

    q = text("""
        INSERT INTO incident_alerts (incident_id, asset_key, alert_id, added_by)
        VALUES (:incident_id, :asset_key, :alert_id, :added_by)
        ON CONFLICT (incident_id, asset_key) DO NOTHING
        RETURNING incident_id, asset_key, alert_id, added_at, added_by
    """)
    row = (
        db.execute(
            q,
            {
                "incident_id": incident_id,
                "asset_key": asset_key,
                "alert_id": alert_id,
                "added_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        # Already linked
        return {"incident_id": incident_id, "asset_key": asset_key, "message": "already linked"}

    if alert_id is not None:
        _insert_incident_evidence(
            db,
            incident_id=incident_id,
            evidence_type="alert",
            ref_id=str(alert_id),
            relation="linked_alert",
            summary="Alert linked to incident",
            details={"asset_key": asset_key},
            added_by=user,
        )
    _insert_incident_evidence(
        db,
        incident_id=incident_id,
        evidence_type="asset",
        ref_id=asset_key,
        relation="linked_asset",
        summary="Asset linked to incident",
        details={"alert_id": alert_id},
        added_by=user,
    )

    note_q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, details)
        VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
    """)
    import json

    db.execute(
        note_q,
        {
            "incident_id": incident_id,
            "author": user,
            "details": json.dumps({"asset_key": asset_key, "alert_id": alert_id}),
        },
    )
    log_audit(
        db,
        "incident.alert.link",
        user_name=user,
        asset_key=asset_key,
        details={
            "incident_id": incident_id,
            "asset_key": asset_key,
            "alert_id": alert_id,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    return _serialize_incident(dict(row))


@router.delete("/{incident_id}/alerts")
def unlink_alert(
    incident_id: int,
    asset_key: str = Query(..., description="Asset key to unlink"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Remove an alert (asset_key) from this incident."""
    q = text(
        "DELETE FROM incident_alerts WHERE incident_id = :incident_id AND asset_key = :asset_key"
    )
    r = db.execute(q, {"incident_id": incident_id, "asset_key": asset_key})
    if r.rowcount == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    log_audit(
        db,
        "incident.alert.unlink",
        user_name=user,
        asset_key=asset_key,
        details={"incident_id": incident_id, "asset_key": asset_key},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True}


class IncidentEvidenceBody(BaseModel):
    evidence_type: str
    ref_id: str
    relation: str = "linked"
    summary: str | None = None
    details: dict | None = None


@router.get("/{incident_id}/evidence")
def list_incident_evidence(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = (
        db.execute(
            text(
                """
                SELECT evidence_id, incident_id, evidence_type, ref_id, relation, summary, details, added_by, created_at
                FROM incident_evidence
                WHERE incident_id = :incident_id
                ORDER BY created_at ASC, evidence_id ASC
                """
            ),
            {"incident_id": incident_id},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_evidence(dict(row)) for row in rows]}


@router.post("/{incident_id}/evidence", status_code=201)
def add_incident_evidence(
    incident_id: int,
    body: IncidentEvidenceBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    valid_types = {"alert", "finding", "asset", "job", "ticket", "note", "event", "other"}
    evidence_type = str(body.evidence_type or "").strip().lower()
    if evidence_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid evidence_type")
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    _insert_incident_evidence(
        db,
        incident_id=incident_id,
        evidence_type=evidence_type,
        ref_id=str(body.ref_id),
        relation=str(body.relation or "linked"),
        summary=body.summary,
        details=body.details or {},
        added_by=user,
    )
    created = (
        db.execute(
            text(
                """
                SELECT evidence_id, incident_id, evidence_type, ref_id, relation, summary, details, added_by, created_at
                FROM incident_evidence
                WHERE incident_id = :incident_id
                  AND evidence_type = :evidence_type
                  AND ref_id = :ref_id
                  AND relation = :relation
                ORDER BY evidence_id DESC
                LIMIT 1
                """
            ),
            {
                "incident_id": incident_id,
                "evidence_type": evidence_type,
                "ref_id": str(body.ref_id),
                "relation": str(body.relation or "linked"),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    log_audit(
        db,
        "incident.evidence.add",
        user_name=user,
        details={
            "incident_id": incident_id,
            "evidence_type": evidence_type,
            "ref_id": str(body.ref_id),
            "relation": str(body.relation or "linked"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_evidence(dict(created or {}))


@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: int,
    source_type: str | None = Query(
        None,
        description="Optional comma-separated source types (note, alert, finding, log, job, automation, response)",
    ),
    event_type: str | None = Query(
        None, description="Optional comma-separated timeline event types"
    ),
    lookback_hours: int = Query(72, ge=1, le=720),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    source_types = _parse_csv_filter(source_type)
    event_types = _parse_csv_filter(event_type)
    return {
        "items": _incident_timeline_aggregated(
            db,
            incident_id,
            lookback_hours=lookback_hours,
            source_limit=max(limit, 140),
            source_types=source_types,
            event_types=event_types,
            limit_total=limit,
        )
    }


class IncidentWatcherBody(BaseModel):
    username: str


@router.get("/{incident_id}/watchers")
def list_incident_watchers(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT incident_id, username, added_by, added_at
                FROM incident_watchers
                WHERE incident_id = :incident_id
                ORDER BY added_at ASC, username ASC
                """
            ),
            {"incident_id": incident_id},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_watcher(dict(row)) for row in rows]}


@router.post("/{incident_id}/watchers", status_code=201)
def add_incident_watcher(
    incident_id: int,
    body: IncidentWatcherBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    username = (body.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.execute(
        text(
            """
            INSERT INTO incident_watchers (incident_id, username, added_by)
            VALUES (:incident_id, :username, :added_by)
            ON CONFLICT (incident_id, username) DO NOTHING
            """
        ),
        {"incident_id": incident_id, "username": username, "added_by": user},
    )
    row = (
        db.execute(
            text(
                """
                SELECT incident_id, username, added_by, added_at
                FROM incident_watchers
                WHERE incident_id = :incident_id AND username = :username
                """
            ),
            {"incident_id": incident_id, "username": username},
        )
        .mappings()
        .first()
    )
    db.commit()
    log_audit(
        db,
        "incident.watcher.add",
        user_name=user,
        details={"incident_id": incident_id, "username": username},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_watcher(dict(row or {}))


@router.delete("/{incident_id}/watchers")
def remove_incident_watcher(
    incident_id: int,
    username: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    removed = db.execute(
        text(
            """
            DELETE FROM incident_watchers
            WHERE incident_id = :incident_id AND username = :username
            """
        ),
        {"incident_id": incident_id, "username": username},
    )
    if int(removed.rowcount or 0) == 0:
        raise HTTPException(status_code=404, detail="Watcher not found")
    db.commit()
    log_audit(
        db,
        "incident.watcher.remove",
        user_name=user,
        details={"incident_id": incident_id, "username": username},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True}


class IncidentChecklistBody(BaseModel):
    title: str


class IncidentChecklistUpdateBody(BaseModel):
    done: bool


@router.get("/{incident_id}/checklist")
def list_incident_checklist(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at
                FROM incident_checklist_items
                WHERE incident_id = :incident_id
                ORDER BY created_at ASC, item_id ASC
                """
            ),
            {"incident_id": incident_id},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_checklist_item(dict(row)) for row in rows]}


@router.post("/{incident_id}/checklist", status_code=201)
def add_incident_checklist_item(
    incident_id: int,
    body: IncidentChecklistBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    title = (body.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title required")
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = (
        db.execute(
            text(
                """
                INSERT INTO incident_checklist_items (incident_id, title, created_by, updated_at)
                VALUES (:incident_id, :title, :created_by, NOW())
                RETURNING item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at
                """
            ),
            {"incident_id": incident_id, "title": title, "created_by": user},
        )
        .mappings()
        .first()
    )
    db.commit()
    log_audit(
        db,
        "incident.checklist.add",
        user_name=user,
        details={"incident_id": incident_id, "item_id": int(row["item_id"]) if row else None},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_checklist_item(dict(row or {}))


@router.patch("/{incident_id}/checklist/{item_id}")
def update_incident_checklist_item(
    incident_id: int,
    item_id: int,
    body: IncidentChecklistUpdateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = (
        db.execute(
            text(
                """
                UPDATE incident_checklist_items
                SET
                  done = :done,
                  done_by = CASE WHEN :done THEN :user_name ELSE NULL END,
                  done_at = CASE WHEN :done THEN NOW() ELSE NULL END,
                  updated_at = NOW()
                WHERE incident_id = :incident_id
                  AND item_id = :item_id
                RETURNING item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at
                """
            ),
            {
                "incident_id": incident_id,
                "item_id": item_id,
                "done": bool(body.done),
                "user_name": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Checklist item not found")
    db.commit()
    log_audit(
        db,
        "incident.checklist.update",
        user_name=user,
        details={"incident_id": incident_id, "item_id": item_id, "done": bool(body.done)},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_checklist_item(dict(row))


class IncidentDecisionBody(BaseModel):
    decision: str
    rationale: str | None = None
    details: dict | None = None


@router.get("/{incident_id}/decisions")
def list_incident_decisions(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT decision_id, incident_id, decision, rationale, decided_by, details, created_at
                FROM incident_decisions
                WHERE incident_id = :incident_id
                ORDER BY created_at ASC, decision_id ASC
                """
            ),
            {"incident_id": incident_id},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_decision(dict(row)) for row in rows]}


@router.post("/{incident_id}/decisions", status_code=201)
def add_incident_decision(
    incident_id: int,
    body: IncidentDecisionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    decision = (body.decision or "").strip()
    if not decision:
        raise HTTPException(status_code=400, detail="decision required")
    exists = db.execute(
        text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}
    ).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = (
        db.execute(
            text(
                """
                INSERT INTO incident_decisions (incident_id, decision, rationale, decided_by, details)
                VALUES (:incident_id, :decision, :rationale, :decided_by, CAST(:details AS jsonb))
                RETURNING decision_id, incident_id, decision, rationale, decided_by, details, created_at
                """
            ),
            {
                "incident_id": incident_id,
                "decision": decision,
                "rationale": (body.rationale or "").strip() or None,
                "decided_by": user,
                "details": json.dumps(body.details or {}),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    log_audit(
        db,
        "incident.decision.add",
        user_name=user,
        details={
            "incident_id": incident_id,
            "decision_id": int(row["decision_id"]) if row else None,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_decision(dict(row or {}))


class IncidentAutoRuleBody(BaseModel):
    name: str
    description: str | None = None
    enabled: bool = True
    severity_threshold: str = "high"
    window_minutes: int = 15
    min_alerts: int = 2
    require_distinct_sources: bool = False
    incident_severity: str = "high"


class IncidentAutoRuleUpdateBody(BaseModel):
    description: str | None = None
    enabled: bool | None = None
    severity_threshold: str | None = None
    window_minutes: int | None = None
    min_alerts: int | None = None
    require_distinct_sources: bool | None = None
    incident_severity: str | None = None


@router.get("/auto-rules/list")
def list_incident_auto_rules(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT
                  auto_rule_id, name, description, enabled, severity_threshold,
                  window_minutes, min_alerts, require_distinct_sources, incident_severity,
                  created_by, created_at, updated_at
                FROM incident_auto_rules
                ORDER BY updated_at DESC, auto_rule_id DESC
                """
            )
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_incident(dict(row)) for row in rows]}


@router.post("/auto-rules/create", status_code=201)
def create_incident_auto_rule(
    body: IncidentAutoRuleBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if body.severity_threshold not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid severity_threshold")
    if body.incident_severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid incident_severity")
    row = (
        db.execute(
            text(
                """
                INSERT INTO incident_auto_rules (
                  name, description, enabled, severity_threshold, window_minutes, min_alerts,
                  require_distinct_sources, incident_severity, created_by, updated_at
                )
                VALUES (
                  :name, :description, :enabled, :severity_threshold, :window_minutes, :min_alerts,
                  :require_distinct_sources, :incident_severity, :created_by, NOW()
                )
                RETURNING
                  auto_rule_id, name, description, enabled, severity_threshold,
                  window_minutes, min_alerts, require_distinct_sources, incident_severity,
                  created_by, created_at, updated_at
                """
            ),
            {
                "name": name,
                "description": (body.description or "").strip() or None,
                "enabled": bool(body.enabled),
                "severity_threshold": body.severity_threshold,
                "window_minutes": max(1, int(body.window_minutes)),
                "min_alerts": max(1, int(body.min_alerts)),
                "require_distinct_sources": bool(body.require_distinct_sources),
                "incident_severity": body.incident_severity,
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create incident auto rule")
    db.commit()
    log_audit(
        db,
        "incident.auto_rule.create",
        user_name=user,
        details={"auto_rule_id": int(row["auto_rule_id"]), "name": name},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_incident(dict(row))


@router.patch("/auto-rules/{auto_rule_id}")
def update_incident_auto_rule(
    auto_rule_id: int,
    body: IncidentAutoRuleUpdateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    current = (
        db.execute(
            text("SELECT * FROM incident_auto_rules WHERE auto_rule_id = :auto_rule_id"),
            {"auto_rule_id": auto_rule_id},
        )
        .mappings()
        .first()
    )
    if not current:
        raise HTTPException(status_code=404, detail="Incident auto rule not found")
    severity_threshold = (
        body.severity_threshold
        if body.severity_threshold is not None
        else current["severity_threshold"]
    )
    incident_severity = (
        body.incident_severity
        if body.incident_severity is not None
        else current["incident_severity"]
    )
    if severity_threshold not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid severity_threshold")
    if incident_severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid incident_severity")
    updated = (
        db.execute(
            text(
                """
                UPDATE incident_auto_rules
                SET
                  description = :description,
                  enabled = :enabled,
                  severity_threshold = :severity_threshold,
                  window_minutes = :window_minutes,
                  min_alerts = :min_alerts,
                  require_distinct_sources = :require_distinct_sources,
                  incident_severity = :incident_severity,
                  updated_at = NOW()
                WHERE auto_rule_id = :auto_rule_id
                RETURNING
                  auto_rule_id, name, description, enabled, severity_threshold,
                  window_minutes, min_alerts, require_distinct_sources, incident_severity,
                  created_by, created_at, updated_at
                """
            ),
            {
                "auto_rule_id": auto_rule_id,
                "description": (
                    body.description if body.description is not None else current["description"]
                ),
                "enabled": bool(body.enabled)
                if body.enabled is not None
                else bool(current["enabled"]),
                "severity_threshold": severity_threshold,
                "window_minutes": (
                    max(1, int(body.window_minutes))
                    if body.window_minutes is not None
                    else int(current["window_minutes"])
                ),
                "min_alerts": (
                    max(1, int(body.min_alerts))
                    if body.min_alerts is not None
                    else int(current["min_alerts"])
                ),
                "require_distinct_sources": (
                    bool(body.require_distinct_sources)
                    if body.require_distinct_sources is not None
                    else bool(current["require_distinct_sources"])
                ),
                "incident_severity": incident_severity,
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    log_audit(
        db,
        "incident.auto_rule.update",
        user_name=user,
        details={"auto_rule_id": auto_rule_id},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return _serialize_incident(dict(updated or {}))


@router.post("/auto-rules/run")
def run_incident_auto_rules(
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    result = _run_incident_auto_rules(db, user=user)
    db.commit()
    log_audit(
        db,
        "incident.auto_rule.run",
        user_name=user,
        details={
            "rules_evaluated": result.get("rules_evaluated"),
            "incidents_created": result.get("incidents_created"),
            "incident_ids": result.get("incident_ids") or [],
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return result


def _jira_create_issue(incident: dict, project_key: str, frontend_url: str) -> tuple[str, str]:
    """Create Jira issue for incident. Returns (issue_key, browse_url). Raises HTTPException on config/API error."""
    base = (getattr(settings, "JIRA_BASE_URL", None) or "").rstrip("/")
    email = getattr(settings, "JIRA_EMAIL", None) or ""
    token = getattr(settings, "JIRA_API_TOKEN", None) or ""
    if not base or not email or not token:
        raise HTTPException(
            status_code=503,
            detail="Jira not configured (JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN)",
        )
    summary = (incident.get("title") or "SecPlat incident")[:255]
    alert_keys = [a.get("asset_key") for a in incident.get("alerts") or [] if isinstance(a, dict)]
    desc_lines = [
        f"SecPlat incident #{incident.get('id')}",
        f"Severity: {incident.get('severity', '')}",
        f"Status: {incident.get('status', '')}",
        f"Linked assets: {', '.join(alert_keys) if alert_keys else 'None'}",
        "",
        f"View in SecPlat: {frontend_url}/incidents/{incident.get('id')}",
    ]
    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "\n".join(desc_lines)}],
            }
        ],
    }
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "issuetype": {"name": "Task"},
            "description": description,
        }
    }
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    url = f"{base}/rest/api/3/issue"
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        try:
            err = e.response.json()
            msg = err.get("errorMessages", [])
            if not msg and "errors" in err:
                msg = list(err["errors"].values())
            raise HTTPException(
                status_code=502,
                detail=f"Jira API error: {msg or e.response.text}",
            )
        except Exception:
            raise HTTPException(status_code=502, detail=f"Jira API error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Jira unreachable: {e!s}")

    data = r.json()
    issue_key = data.get("key") or ""
    browse_url = f"{base}/browse/{issue_key}"
    return issue_key, browse_url


class CreateJiraBody(BaseModel):
    project_key: str | None = None


@router.post("/{incident_id}/jira")
def create_jira_ticket(
    incident_id: int,
    body: CreateJiraBody | None = None,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Create a Jira issue for this incident. Stores issue_key and url in incident.metadata. Returns existing if already created."""
    q = text("""
        SELECT id, title, severity, status, assigned_to, metadata
        FROM incidents WHERE id = :id
    """)
    row = db.execute(q, {"id": incident_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = dict(row)
    meta = incident.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta) if meta else {}
        except Exception:
            meta = {}
    if meta.get("jira_issue_key"):
        return {
            "issue_key": meta["jira_issue_key"],
            "url": meta.get("jira_issue_url") or "",
            "message": "Jira ticket already created for this incident",
        }

    project_key = (body and body.project_key) or getattr(settings, "JIRA_PROJECT_KEY", None) or ""
    if not project_key or not project_key.strip():
        raise HTTPException(
            status_code=400,
            detail="project_key required (pass in body or set JIRA_PROJECT_KEY)",
        )
    project_key = project_key.strip().upper()

    alerts_q = text("SELECT asset_key FROM incident_alerts WHERE incident_id = :id")
    alerts = db.execute(alerts_q, {"id": incident_id}).mappings().all()
    incident_for_jira = {
        **incident,
        "alerts": [{"asset_key": a["asset_key"]} for a in alerts],
    }
    frontend_url = (getattr(settings, "FRONTEND_URL", None) or "http://localhost:3000").rstrip("/")
    issue_key, browse_url = _jira_create_issue(incident_for_jira, project_key, frontend_url)

    new_meta = {**meta, "jira_issue_key": issue_key, "jira_issue_url": browse_url}
    db.execute(
        text("UPDATE incidents SET metadata = :meta, updated_at = :now WHERE id = :id"),
        {"meta": json.dumps(new_meta), "now": datetime.now(UTC), "id": incident_id},
    )
    db.commit()
    log_audit(
        db,
        "incident.jira.create",
        user_name=user,
        asset_key=None,
        details={"incident_id": incident_id, "jira_issue_key": issue_key},
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    return {"issue_key": issue_key, "url": browse_url}
