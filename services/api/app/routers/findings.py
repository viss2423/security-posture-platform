from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..db import get_db

router = APIRouter()


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
        f.category, f.title, f.severity, f.confidence, f.evidence, f.remediation
      FROM findings f
      LEFT JOIN assets a ON a.asset_id = f.asset_id
      WHERE {where}
      ORDER BY COALESCE(f.last_seen, f.time) DESC
      LIMIT :limit
    """)
    rows = db.execute(q, params).mappings().all()
    return [
        {
            **dict(r),
            "first_seen": r["first_seen"].isoformat() if hasattr(r["first_seen"], "isoformat") else str(r["first_seen"]) if r["first_seen"] else None,
            "last_seen": r["last_seen"].isoformat() if hasattr(r["last_seen"], "isoformat") else str(r["last_seen"]) if r["last_seen"] else None,
        }
        for r in rows
    ]


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
        row = db.execute(
            text("SELECT asset_id FROM assets WHERE asset_key = :k"),
            {"k": body.asset_key},
        ).mappings().first()
        if not row:
            raise HTTPException(status_code=400, detail=f"Asset not found: {body.asset_key}")
        asset_id = row["asset_id"]
    if asset_id is None:
        raise HTTPException(status_code=400, detail="Provide asset_id or asset_key")

    existing = db.execute(
        text("SELECT finding_id, last_seen FROM findings WHERE finding_key = :k"),
        {"k": body.finding_key},
    ).mappings().first()

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
        return {"ok": True, "finding_key": body.finding_key, "updated": False}
