from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from ..db import get_db

router = APIRouter()

@router.get("/")
def list_findings(db: Session = Depends(get_db)):
    q = text("""
      SELECT f.finding_id, f.time, a.name as asset, f.category, f.title, f.severity, f.confidence
      FROM findings f
      JOIN assets a ON a.asset_id = f.asset_id
      ORDER BY f.time DESC
      LIMIT 200
    """)
    rows = db.execute(q).mappings().all()
    return [dict(r) for r in rows]
