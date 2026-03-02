import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..db import get_db
from ..queue import publish_correlation_event
from ..request_context import request_id_ctx
from ..risk_labels import VALID_RISK_LABEL_SOURCES, VALID_RISK_LABELS
from ..risk_scoring import recompute_finding_risk
from ..suppression import is_asset_suppressed
from .auth import get_current_role, require_auth, require_role

router = APIRouter()

VALID_STATUS = ("open", "in_progress", "remediated", "accepted_risk")
VALID_RISK_LEVELS = ("critical", "high", "medium", "low", "unscored")
SENSITIVE_FINDING_FIELDS_FOR_VIEWER = {"evidence", "accepted_risk_reason"}


def _redact_finding(row: dict, role: str) -> dict:
    out = dict(row)
    if role == "viewer":
        for key in SENSITIVE_FINDING_FIELDS_FOR_VIEWER:
            out[key] = None
    return out


@router.get("/")
def list_findings(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="Filter by status (open, ignored, remediated)"),
    source: str | None = Query(None, description="Filter by source (e.g. tls_scan, header_scan)"),
    risk_level: str | None = Query(
        None, description="Filter by risk level (critical, high, medium, low, unscored)"
    ),
    asset_key: str | None = Query(None, description="Filter by asset_key"),
    limit: int = Query(200, ge=1, le=500),
    _user: str = Depends(require_auth),
    role: str = Depends(get_current_role),
):
    """List findings with optional filters. Returns finding_key, first_seen, last_seen, status, source, asset_key."""
    conditions = ["1=1"]
    params: dict = {"limit": limit}
    if status:
        conditions.append("COALESCE(f.status, 'open') = :status")
        params["status"] = status
    if source:
        conditions.append("f.source = :source")
        params["source"] = source
    if risk_level:
        normalized_risk_level = risk_level.strip().lower()
        if normalized_risk_level not in VALID_RISK_LEVELS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk_level. Use one of: {VALID_RISK_LEVELS}",
            )
        if normalized_risk_level == "unscored":
            conditions.append("f.risk_score IS NULL")
        else:
            conditions.append("COALESCE(f.risk_level, '') = :risk_level")
            params["risk_level"] = normalized_risk_level
    if asset_key:
        conditions.append("a.asset_key = :asset_key")
        params["asset_key"] = asset_key
    where = " AND ".join(conditions)
    q = text(f"""
      SELECT
        f.finding_id, f.finding_key, f.asset_id,
        COALESCE(f.first_seen, f.time) AS first_seen,
        COALESCE(f.last_seen, f.time) AS last_seen,
        COALESCE(f.status, 'open') AS status,
        f.source,
        f.time,
        a.asset_key,
        a.name AS asset_name,
        f.category, f.title, f.severity, f.confidence, f.evidence, f.remediation,
        f.risk_score, f.risk_level, f.risk_factors_json,
        rl.label AS risk_label,
        rl.source AS risk_label_source,
        rl.created_at AS risk_label_created_at,
        rl.created_by AS risk_label_created_by,
        f.accepted_risk_at, f.accepted_risk_expires_at, f.accepted_risk_reason, f.accepted_risk_by
      FROM findings f
      LEFT JOIN assets a ON a.asset_id = f.asset_id
      LEFT JOIN LATERAL (
        SELECT label, source, created_at, created_by
        FROM finding_risk_labels frl
        WHERE frl.finding_id = f.finding_id
        ORDER BY
          CASE
            WHEN frl.source = 'analyst' THEN 0
            WHEN frl.source = 'incident_linked' THEN 1
            ELSE 2
          END,
          frl.created_at DESC,
          frl.id DESC
        LIMIT 1
      ) rl ON TRUE
      WHERE {where}
      ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
      LIMIT :limit
    """)
    rows = db.execute(q, params).mappings().all()

    def _serialize(r):
        out = dict(r)
        for k in (
            "first_seen",
            "last_seen",
            "risk_label_created_at",
            "accepted_risk_at",
            "accepted_risk_expires_at",
        ):
            v = out.get(k)
            if hasattr(v, "isoformat"):
                out[k] = v.isoformat()
            elif v is not None and k in out:
                out[k] = str(v)
        if isinstance(out.get("risk_factors_json"), str):
            try:
                out["risk_factors_json"] = json.loads(out["risk_factors_json"])
            except json.JSONDecodeError:
                out["risk_factors_json"] = {}
        return out

    return [_redact_finding(_serialize(r), role=role) for r in rows]


class FindingUpsertBody(BaseModel):
    finding_key: str
    asset_key: str | None = None
    asset_id: int | None = None
    category: str | None = None
    title: str
    severity: str = "medium"
    confidence: str = "high"
    evidence: str | None = None
    remediation: str | None = None
    source: str | None = None  # e.g. tls_scan, header_scan


@router.post("/")
def upsert_finding(
    body: FindingUpsertBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """
    Upsert by finding_key. If exists: update last_seen (and optionally evidence).
    If new: insert with first_seen=last_seen=now. Requires asset_id or asset_key to resolve.
    """
    asset_id = body.asset_id
    if asset_id is None and body.asset_key:
        row = (
            db.execute(
                text("SELECT asset_id FROM assets WHERE asset_key = :k"),
                {"k": body.asset_key},
            )
            .mappings()
            .first()
        )
        if not row:
            raise HTTPException(status_code=400, detail=f"Asset not found: {body.asset_key}")
        asset_id = row["asset_id"]
    if asset_id is None:
        raise HTTPException(status_code=400, detail="Provide asset_id or asset_key")

    existing = (
        db.execute(
            text("SELECT finding_id, last_seen FROM findings WHERE finding_key = :k"),
            {"k": body.finding_key},
        )
        .mappings()
        .first()
    )

    if existing:
        finding_id = int(existing["finding_id"])
        db.execute(
            text("""
              UPDATE findings SET last_seen = NOW(), evidence = COALESCE(:evidence, evidence),
                category = COALESCE(:category, category),
                remediation = COALESCE(:remediation, remediation),
                title = COALESCE(NULLIF(:title, ''), title),
                severity = COALESCE(NULLIF(:severity, ''), severity),
                confidence = COALESCE(NULLIF(:confidence, ''), confidence),
                source = COALESCE(NULLIF(:source, ''), source),
                asset_id = COALESCE(:asset_id, asset_id)
              WHERE finding_key = :k
            """),
            {
                "k": body.finding_key,
                "evidence": body.evidence,
                "category": body.category,
                "remediation": body.remediation,
                "title": body.title,
                "severity": body.severity,
                "confidence": body.confidence,
                "source": body.source,
                "asset_id": asset_id,
            },
        )
        recompute_finding_risk(db, finding_id)
        db.commit()
        return {"ok": True, "finding_key": body.finding_key, "updated": True}
    else:
        row = (
            db.execute(
                text("""
              INSERT INTO findings (finding_key, asset_id, first_seen, last_seen, time, status, source, category, title, severity, confidence, evidence, remediation)
              VALUES (:finding_key, :asset_id, NOW(), NOW(), NOW(), 'open', :source, :category, :title, :severity, :confidence, :evidence, :remediation)
              RETURNING finding_id
            """),
                {
                    "finding_key": body.finding_key,
                    "asset_id": asset_id,
                    "source": body.source or "",
                    "category": body.category or "",
                    "title": body.title,
                    "severity": body.severity,
                    "confidence": body.confidence,
                    "evidence": body.evidence or "",
                    "remediation": body.remediation or "",
                },
            )
            .mappings()
            .first()
        )
        if not row:
            raise HTTPException(status_code=500, detail="Failed to create finding")
        recompute_finding_risk(db, int(row["finding_id"]))
        db.commit()
        ak = body.asset_key
        if not ak:
            row = (
                db.execute(
                    text("SELECT asset_key FROM assets WHERE asset_id = :id"), {"id": asset_id}
                )
                .mappings()
                .first()
            )
            ak = (row["asset_key"] or "") if row else ""
        if ak and not is_asset_suppressed(db, ak):
            publish_correlation_event(
                "finding.created",
                asset_key=ak,
                finding_key=body.finding_key,
                severity=body.severity,
                incident_key=f"finding:{ak}:{body.finding_key}",
            )
        return {"ok": True, "finding_key": body.finding_key, "updated": False}


class UpdateStatusBody(BaseModel):
    status: str


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    body: UpdateStatusBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Update finding status: open | in_progress | remediated | accepted_risk."""
    if body.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail=f"Invalid status. Use one of: {VALID_STATUS}")
    row = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.execute(
        text("UPDATE findings SET status = :status WHERE finding_id = :id"),
        {"status": body.status, "id": finding_id},
    )
    recompute_finding_risk(db, finding_id)
    log_audit(
        db,
        "finding_status",
        user_name=_user,
        asset_key=None,
        details={"finding_id": finding_id, "status": body.status},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True, "finding_id": finding_id, "status": body.status}


class AcceptRiskBody(BaseModel):
    reason: str
    expires_at: str  # ISO datetime


@router.post("/{finding_id}/accept-risk")
def accept_finding_risk(
    finding_id: int,
    body: AcceptRiskBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Set finding to accepted_risk with reason and expiry. Must be reviewed when expires_at passes."""
    try:
        expires_at = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="expires_at must be ISO 8601 datetime")
    row = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    now = datetime.now(UTC)
    db.execute(
        text("""
          UPDATE findings SET
            status = 'accepted_risk',
            accepted_risk_at = :now,
            accepted_risk_expires_at = :expires_at,
            accepted_risk_reason = :reason,
            accepted_risk_by = :user
          WHERE finding_id = :id
        """),
        {
            "id": finding_id,
            "now": now,
            "expires_at": expires_at,
            "reason": body.reason or "",
            "user": user,
        },
    )
    recompute_finding_risk(db, finding_id)
    log_audit(
        db,
        "accept_risk",
        user_name=user,
        asset_key=None,
        details={
            "finding_id": finding_id,
            "reason": body.reason[:100] if body.reason else "",
            "expires_at": body.expires_at,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True, "finding_id": finding_id, "status": "accepted_risk"}


class CreateRiskLabelBody(BaseModel):
    label: str
    source: str = "analyst"
    note: str | None = None


@router.get("/{finding_id}/risk-labels")
def list_finding_risk_labels(
    finding_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    finding = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    rows = (
        db.execute(
            text(
                """
                SELECT id, finding_id, label, source, note, created_by, created_at
                FROM finding_risk_labels
                WHERE finding_id = :finding_id
                ORDER BY created_at DESC, id DESC
                """
            ),
            {"finding_id": finding_id},
        )
        .mappings()
        .all()
    )
    items = []
    for row in rows:
        item = dict(row)
        created_at = item.get("created_at")
        if hasattr(created_at, "isoformat"):
            item["created_at"] = created_at.isoformat()
        items.append(item)
    return {"items": items}


@router.post("/{finding_id}/risk-labels")
def create_finding_risk_label(
    finding_id: int,
    body: CreateRiskLabelBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    finding = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    label = body.label.strip().lower()
    source = body.source.strip().lower()
    if label not in VALID_RISK_LABELS:
        raise HTTPException(
            status_code=400, detail=f"Invalid label. Use one of: {VALID_RISK_LABELS}"
        )
    if source not in VALID_RISK_LABEL_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source. Use one of: {VALID_RISK_LABEL_SOURCES}",
        )

    row = (
        db.execute(
            text(
                """
                INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
                VALUES (:finding_id, :label, :source, :note, :created_by)
                RETURNING id, finding_id, label, source, note, created_by, created_at
                """
            ),
            {
                "finding_id": finding_id,
                "label": label,
                "source": source,
                "note": (body.note or "").strip() or None,
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "finding_risk_label",
        user_name=user,
        asset_key=None,
        details={"finding_id": finding_id, "label": label, "source": source},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    item = dict(row or {})
    created_at = item.get("created_at")
    if hasattr(created_at, "isoformat"):
        item["created_at"] = created_at.isoformat()
    return item
