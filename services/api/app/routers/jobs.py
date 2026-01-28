from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from ..db import get_db

router = APIRouter()

@router.post("/")
def create_job(payload: dict, db: Session = Depends(get_db)):
    job_type = payload.get("job_type")  # web_exposure | score_recompute
    asset_id = payload.get("target_asset_id")
    requested_by = payload.get("requested_by", "student")

    if job_type not in {"web_exposure", "score_recompute"}:
        raise HTTPException(status_code=400, detail="Invalid job_type")

    q = text("""
      INSERT INTO scan_jobs(job_type, target_asset_id, requested_by, status)
      VALUES (:t, :aid, :rb, 'queued')
      RETURNING job_id, job_type, target_asset_id, status, created_at
    """)
    row = db.execute(q, {"t": job_type, "aid": asset_id, "rb": requested_by}).mappings().first()
    db.commit()
    return dict(row)

@router.get("/")
def list_jobs(db: Session = Depends(get_db)):
    q = text("SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT 50")
    rows = db.execute(q).mappings().all()
    return [dict(r) for r in rows]
