from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..db import get_db
from ..queue import publish_correlation_event
from ..request_context import request_id_ctx
from ..suppression import is_asset_suppressed
from .auth import require_role

router = APIRouter()

VALID_STATUS = ("open", "in_progress", "remediated", "accepted_risk")


@router.get("/")
def list_findings(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="Filter by status (open, ignored, remediated)"),
    source: str | None = Query(None, description="Filter by source (e.g. tls_scan, header_scan)"),
    asset_key: str | None = Query(None, description="Filter by asset_key"),
    limit: int = Query(200, ge=1, le=500),
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
        f.accepted_risk_at, f.accepted_risk_expires_at, f.accepted_risk_reason, f.accepted_risk_by
      FROM findings f
      LEFT JOIN assets a ON a.asset_id = f.asset_id
      WHERE {where}
      ORDER BY COALESCE(f.last_seen, f.time) DESC
      LIMIT :limit
    """)
    rows = db.execute(q, params).mappings().all()

    def _serialize(r):
        out = dict(r)
        for k in ("first_seen", "last_seen", "accepted_risk_at", "accepted_risk_expires_at"):
            v = out.get(k)
            if hasattr(v, "isoformat"):
                out[k] = v.isoformat()
            elif v is not None and k in out:
                out[k] = str(v)
        return out

    return [_serialize(r) for r in rows]


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
def upsert_finding(body: FindingUpsertBody, db: Session = Depends(get_db)):
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
        db.execute(
            text("""
              UPDATE findings SET last_seen = NOW(), evidence = COALESCE(:evidence, evidence),
                category = COALESCE(:category, category), remediation = COALESCE(:remediation, remediation)
              WHERE finding_key = :k
            """),
            {
                "k": body.finding_key,
                "evidence": body.evidence,
                "category": body.category,
                "remediation": body.remediation,
            },
        )
        db.commit()
        return {"ok": True, "finding_key": body.finding_key, "updated": True}
    else:
        db.execute(
            text("""
              INSERT INTO findings (finding_key, asset_id, first_seen, last_seen, time, status, source, category, title, severity, confidence, evidence, remediation)
              VALUES (:finding_key, :asset_id, NOW(), NOW(), NOW(), 'open', :source, :category, :title, :severity, :confidence, :evidence, :remediation)
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
