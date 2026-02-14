"""Incidents: SOC workflow — group alerts, state machine, notes, SLA (Phase A.1). B.4: Jira ticket from incident."""
import base64
import json
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth, require_role
from app.audit import log_audit
from app.request_context import request_id_ctx
from app.settings import settings

router = APIRouter(prefix="/incidents", tags=["incidents"])

VALID_STATUS = ("new", "triaged", "contained", "resolved", "closed")
VALID_SEVERITY = ("critical", "high", "medium", "low", "info")


def _serialize_incident(row: dict) -> dict:
    out = dict(row)
    for k in ("created_at", "updated_at", "resolved_at", "closed_at", "sla_due_at", "added_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out


def _serialize_note(row: dict) -> dict:
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


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
        SELECT i.id, i.title, i.severity, i.status, i.assigned_to,
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
        SELECT id, title, severity, status, assigned_to,
               created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
        FROM incidents WHERE id = :id
    """)
    row = db.execute(q, {"id": incident_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = _serialize_incident(dict(row))

    alerts_q = text("SELECT incident_id, asset_key, added_at, added_by FROM incident_alerts WHERE incident_id = :id ORDER BY added_at")
    alerts = db.execute(alerts_q, {"id": incident_id}).mappings().all()
    incident["alerts"] = [_serialize_incident(dict(a)) for a in alerts]

    notes_q = text("""
        SELECT id, incident_id, event_type, author, body, details, created_at
        FROM incident_notes WHERE incident_id = :id ORDER BY created_at ASC
    """)
    notes = db.execute(notes_q, {"id": incident_id}).mappings().all()
    incident["timeline"] = [_serialize_note(dict(n)) for n in notes]

    return incident


class CreateIncidentBody(BaseModel):
    title: str
    severity: str = "medium"
    assigned_to: str | None = None
    sla_due_at: str | None = None  # ISO datetime
    asset_keys: list[str] | None = None  # link these alerts (asset_keys) to the incident


@router.post("", status_code=201)
def create_incident(
    body: CreateIncidentBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Create an incident and optionally link alerts by asset_key."""
    if body.severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}")

    now = datetime.now(timezone.utc)
    sla_due_at = None
    if body.sla_due_at:
        try:
            sla_due_at = datetime.fromisoformat(body.sla_due_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid sla_due_at format (use ISO 8601)")

    q = text("""
        INSERT INTO incidents (title, severity, status, assigned_to, sla_due_at, updated_at)
        VALUES (:title, :severity, 'new', :assigned_to, :sla_due_at, :now)
        RETURNING id, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
    """)
    row = db.execute(q, {
        "title": body.title,
        "severity": body.severity,
        "assigned_to": body.assigned_to or None,
        "sla_due_at": sla_due_at,
        "now": now,
    }).mappings().first()
    incident_id = row["id"]

    if body.asset_keys:
        for asset_key in body.asset_keys:
            if not asset_key or not asset_key.strip():
                continue
            link_q = text("""
                INSERT INTO incident_alerts (incident_id, asset_key, added_by)
                VALUES (:incident_id, :asset_key, :added_by)
                ON CONFLICT (incident_id, asset_key) DO NOTHING
            """)
            db.execute(link_q, {"incident_id": incident_id, "asset_key": asset_key.strip(), "added_by": user})
        # Timeline: one "alert_added" per batch
        note_q = text("""
            INSERT INTO incident_notes (incident_id, event_type, author, details)
            VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
        """)
        import json
        db.execute(note_q, {
            "incident_id": incident_id,
            "author": user,
            "details": json.dumps({"asset_keys": body.asset_keys}),
        })

    db.commit()
    log_audit(db, "incident_create", user_name=user, asset_key=None, details={"incident_id": incident_id, "title": body.title}, request_id=request_id_ctx.get(None))
    db.commit()

    return _serialize_incident(dict(row))


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

    row = db.execute(text("SELECT id, status FROM incidents WHERE id = :id"), {"id": incident_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    resolved_at = None
    closed_at = None
    if body.status == "resolved":
        resolved_at = now
    elif body.status == "closed":
        closed_at = now
        # Also set resolved_at if not already
        existing = db.execute(text("SELECT resolved_at FROM incidents WHERE id = :id"), {"id": incident_id}).mappings().first()
        resolved_at = existing["resolved_at"] or now

    q = text("""
        UPDATE incidents
        SET status = :status, assigned_to = COALESCE(assigned_to, :assigned_to), updated_at = :now,
            resolved_at = COALESCE(resolved_at, :resolved_at), closed_at = COALESCE(closed_at, :closed_at)
        WHERE id = :id
        RETURNING id, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at
    """)
    updated = db.execute(q, {
        "id": incident_id,
        "status": body.status,
        "assigned_to": user,
        "now": now,
        "resolved_at": resolved_at,
        "closed_at": closed_at,
    }).mappings().first()

    # Timeline: state_change
    note_q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, details)
        VALUES (:incident_id, 'state_change', :author, CAST(:details AS jsonb))
    """)
    import json
    db.execute(note_q, {
        "incident_id": incident_id,
        "author": user,
        "details": json.dumps({"from": row["status"], "to": body.status}),
    })

    db.commit()
    log_audit(db, "incident_status", user_name=user, asset_key=None, details={"incident_id": incident_id, "status": body.status}, request_id=request_id_ctx.get(None))
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
    exists = db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")

    q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, body)
        VALUES (:incident_id, 'note', :author, :body)
        RETURNING id, incident_id, event_type, author, body, details, created_at
    """)
    row = db.execute(q, {"incident_id": incident_id, "author": user, "body": body.body or ""}).mappings().first()
    db.execute(text("UPDATE incidents SET updated_at = :now WHERE id = :id"), {"now": datetime.now(timezone.utc), "id": incident_id})
    db.commit()

    return _serialize_note(dict(row))


class LinkAlertBody(BaseModel):
    asset_key: str


@router.post("/{incident_id}/alerts", status_code=201)
def link_alert(
    incident_id: int,
    body: LinkAlertBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Link an alert (by asset_key) to this incident."""
    exists = db.execute(text("SELECT id FROM incidents WHERE id = :id"), {"id": incident_id}).scalar()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")

    asset_key = (body.asset_key or "").strip()
    if not asset_key:
        raise HTTPException(status_code=400, detail="asset_key required")

    q = text("""
        INSERT INTO incident_alerts (incident_id, asset_key, added_by)
        VALUES (:incident_id, :asset_key, :added_by)
        ON CONFLICT (incident_id, asset_key) DO NOTHING
        RETURNING incident_id, asset_key, added_at, added_by
    """)
    row = db.execute(q, {"incident_id": incident_id, "asset_key": asset_key, "added_by": user}).mappings().first()
    if not row:
        # Already linked
        return {"incident_id": incident_id, "asset_key": asset_key, "message": "already linked"}

    note_q = text("""
        INSERT INTO incident_notes (incident_id, event_type, author, details)
        VALUES (:incident_id, 'alert_added', :author, CAST(:details AS jsonb))
    """)
    import json
    db.execute(note_q, {"incident_id": incident_id, "author": user, "details": json.dumps({"asset_key": asset_key})})
    db.commit()

    return _serialize_incident(dict(row))


@router.delete("/{incident_id}/alerts")
def unlink_alert(
    incident_id: int,
    asset_key: str = Query(..., description="Asset key to unlink"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Remove an alert (asset_key) from this incident."""
    q = text("DELETE FROM incident_alerts WHERE incident_id = :incident_id AND asset_key = :asset_key")
    r = db.execute(q, {"incident_id": incident_id, "asset_key": asset_key})
    db.commit()
    if r.rowcount == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"ok": True}


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
        {"meta": json.dumps(new_meta), "now": datetime.now(timezone.utc), "id": incident_id},
    )
    db.commit()
    log_audit(
        db,
        "incident_jira_create",
        user_name=user,
        asset_key=None,
        details={"incident_id": incident_id, "jira_issue_key": issue_key},
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    return {"issue_key": issue_key, "url": browse_url}
