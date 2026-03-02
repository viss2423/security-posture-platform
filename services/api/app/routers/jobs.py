"""Job runner: scan_jobs table, list/get/retry, logs. Phase B.3. Phase 1: publish to Redis stream."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.queue import publish_scan_job
from app.routers.auth import require_auth, require_role

router = APIRouter()


def _serialize_job(r) -> dict:
    # RowMapping (SQLAlchemy 2) doesn't convert to dict with column names; use _mapping or keys()
    out = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
    for k in ("created_at", "started_at", "finished_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out


@router.get("")
def list_jobs(
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List recent jobs (optional status filter)."""
    q = """
    SELECT
      j.job_id,
      j.job_type,
      j.target_asset_id,
      j.requested_by,
      j.status,
      j.created_at,
      j.started_at,
      j.finished_at,
      j.error,
      j.retry_count,
      a.asset_key,
      a.name AS asset_name
    FROM scan_jobs j
    LEFT JOIN assets a ON a.asset_id = j.target_asset_id
    WHERE 1=1
    """
    params = {"limit": limit}
    if status:
        q += " AND j.status = :status"
        params["status"] = status
    q += " ORDER BY j.created_at DESC LIMIT :limit"
    rows = db.execute(text(q), params).mappings().all()
    return {"items": [_serialize_job(r) for r in rows]}


@router.get("/{job_id}")
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one job with full log_output."""
    row = (
        db.execute(
            text(
                """
                SELECT
                  j.job_id,
                  j.job_type,
                  j.target_asset_id,
                  j.requested_by,
                  j.status,
                  j.created_at,
                  j.started_at,
                  j.finished_at,
                  j.error,
                  j.log_output,
                  j.retry_count,
                  a.asset_key,
                  a.name AS asset_name,
                  a.type AS asset_type,
                  a.environment AS asset_environment,
                  a.criticality AS asset_criticality,
                  a.verified AS asset_verified
                FROM scan_jobs j
                LEFT JOIN assets a ON a.asset_id = j.target_asset_id
                WHERE j.job_id = :id
                """
            ),
            {"id": job_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize_job(row)


@router.post("")
def create_job(
    payload: dict,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Enqueue a job (web_exposure or score_recompute). Analyst/admin only."""
    job_type = payload.get("job_type")
    asset_id = payload.get("target_asset_id")
    requested_by = payload.get("requested_by") or _user

    if job_type not in {"web_exposure", "score_recompute"}:
        raise HTTPException(status_code=400, detail="Invalid job_type")

    if asset_id is not None:
        exists = db.execute(
            text("SELECT 1 FROM assets WHERE asset_id = :id"), {"id": asset_id}
        ).first()
        if not exists:
            raise HTTPException(status_code=400, detail="Asset not found")

    q = text("""
      INSERT INTO scan_jobs(job_type, target_asset_id, requested_by, status)
      VALUES (:t, :aid, :rb, 'queued')
      RETURNING job_id, job_type, target_asset_id, status, created_at
    """)
    row = db.execute(q, {"t": job_type, "aid": asset_id, "rb": requested_by}).mappings().first()
    out = _serialize_job(row)
    db.commit()
    publish_scan_job(out["job_id"], job_type, asset_id, requested_by)
    return out


@router.post("/{job_id}/retry")
def retry_job(
    job_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Re-queue a failed job. Analyst/admin only."""
    row = (
        db.execute(text("SELECT job_id, status FROM scan_jobs WHERE job_id = :id"), {"id": job_id})
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    if row["status"] not in ("failed", "done"):
        raise HTTPException(status_code=400, detail="Only failed or completed jobs can be retried")
    db.execute(
        text("""
          UPDATE scan_jobs SET status = 'queued', error = NULL, log_output = NULL, started_at = NULL, finished_at = NULL, retry_count = retry_count + 1
          WHERE job_id = :id
        """),
        {"id": job_id},
    )
    db.commit()
    job_row = (
        db.execute(
            text(
                "SELECT job_type, target_asset_id, requested_by FROM scan_jobs WHERE job_id = :id"
            ),
            {"id": job_id},
        )
        .mappings()
        .first()
    )
    if job_row:
        publish_scan_job(
            job_id, job_row["job_type"], job_row["target_asset_id"], job_row["requested_by"] or ""
        )
    return {"ok": True, "status": "queued"}
