from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from ..db import get_db
from ..verification import generate_token, verify_domain_ownership

router = APIRouter()
@router.get("/")
def list_assets(db: Session = Depends(get_db)):
    q = text("""
      SELECT asset_id, type, name, owner, verified, verification_method, verification_token, created_at
      FROM assets
      ORDER BY asset_id DESC
    """)
    rows = db.execute(q).mappings().all()
    return [dict(r) for r in rows]


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    q = text("""
      SELECT asset_id, type, name, owner, verified, verification_method, verification_token, created_at
      FROM assets
      WHERE asset_id=:id
    """)
    row = db.execute(q, {"id": asset_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    return dict(row)

@router.post("/")
def create_asset(payload: dict, db: Session = Depends(get_db)):
    asset_type = payload.get("type")
    name = payload.get("name")
    owner = payload.get("owner")

    if asset_type not in {"user", "host", "external_web", "app"}:
        raise HTTPException(status_code=400, detail="Invalid asset type")

    token = generate_token() if asset_type == "external_web" else None

    q = text("""
      INSERT INTO assets(type, name, owner, verification_token)
      VALUES (:type, :name, :owner, :token)
      RETURNING asset_id, type, name, owner, verified, verification_token
    """)
    row = db.execute(q, {"type": asset_type, "name": name, "owner": owner, "token": token}).mappings().first()
    db.commit()
    return dict(row)

@router.post("/{asset_id}/verify")
def verify_asset(asset_id: int, payload: dict, db: Session = Depends(get_db)):
    method = payload.get("method")  # "dns_txt" | "well_known"
    q = text("SELECT * FROM assets WHERE asset_id=:id")
    asset = db.execute(q, {"id": asset_id}).mappings().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset["type"] != "external_web":
        raise HTTPException(status_code=400, detail="Only external_web assets can be verified")

    ok, details = verify_domain_ownership(
        domain=asset["name"],
        token=asset["verification_token"],
        method=method,
    )
    if not ok:
        raise HTTPException(status_code=400, detail={"verified": False, "details": details})

    uq = text("UPDATE assets SET verified=true, verification_method=:m WHERE asset_id=:id RETURNING asset_id, verified, verification_method")
    row = db.execute(uq, {"m": method, "id": asset_id}).mappings().first()
    db.commit()
    return dict(row)

