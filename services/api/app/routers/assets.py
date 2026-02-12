import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..db import get_db
from .auth import require_auth
from ..verification import generate_token, verify_domain_ownership
from ..audit import log_audit
from ..request_context import request_id_ctx

router = APIRouter(prefix="/assets", tags=["assets"])

ALLOWED_TYPES = {"user", "host", "external_web", "app"}


def _as_jsonb(value) -> str:
    """Return a JSON string suitable for CAST(:metadata AS jsonb)."""
    if value is None:
        return "{}"
    if isinstance(value, str):
        # Allow passing a JSON string directly
        return value
    return json.dumps(value)


@router.get("/")
def list_assets(db: Session = Depends(get_db)):
    q = text("""
      SELECT
        asset_id,
        asset_key,
        type,
        name,
        owner,
        owner_team,
        owner_email,
        asset_type,
        environment,
        criticality,
        verified,
        verification_method,
        verification_token,
        address,
        port,
        is_active,
        tags,
        metadata,
        created_at,
        updated_at
      FROM assets
      ORDER BY asset_id DESC
    """)
    rows = db.execute(q).mappings().all()
    return [dict(r) for r in rows]


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    q = text("""
      SELECT
        asset_id,
        asset_key,
        type,
        name,
        owner,
        owner_team,
        owner_email,
        asset_type,
        environment,
        criticality,
        verified,
        verification_method,
        verification_token,
        address,
        port,
        is_active,
        tags,
        metadata,
        created_at,
        updated_at
      FROM assets
      WHERE asset_id=:id
    """)
    row = db.execute(q, {"id": asset_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    return dict(row)


@router.get("/by-key/{asset_key}")
def get_asset_by_key(asset_key: str, db: Session = Depends(get_db)):
    q = text("""
      SELECT
        asset_id,
        asset_key,
        type,
        name,
        owner,
        owner_team,
        owner_email,
        asset_type,
        environment,
        criticality,
        verified,
        verification_method,
        verification_token,
        address,
        port,
        is_active,
        tags,
        metadata,
        created_at,
        updated_at
      FROM assets
      WHERE asset_key=:k
    """)
    row = db.execute(q, {"k": asset_key}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    return dict(row)


@router.post("/")
def create_asset(payload: dict, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """
    Create asset inventory record.
    - Preserves your external_web verification_token generation
    - Fixes psycopg binding for jsonb + text[] using CAST()
    """
    asset_type = payload.get("type")
    name = payload.get("name")
    owner = payload.get("owner")
    asset_key = payload.get("asset_key")

    if asset_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Invalid asset type")
    if not name:
        raise HTTPException(status_code=400, detail="Missing name")
    if not asset_key:
        raise HTTPException(status_code=400, detail="Missing asset_key")

    token = generate_token() if asset_type == "external_web" else None

    q = text("""
      INSERT INTO assets(
        asset_key, type, name, owner,
        owner_team, owner_email,
        asset_type, environment, criticality,
        verification_token,
        address, port,
        is_active,
        tags, metadata
      )
      VALUES (
        :asset_key, :type, :name, :owner,
        :owner_team, :owner_email,
        :asset_type, :environment, :criticality,
        :token,
        :address, :port,
        :is_active,
        CAST(:tags AS text[]),
        CAST(:metadata AS jsonb)
      )
      RETURNING
        asset_id, asset_key, type, name, owner,
        verified, verification_method, verification_token,
        environment, criticality, created_at, updated_at
    """)

    params = {
        "asset_key": asset_key,
        "type": asset_type,
        "name": name,
        "owner": owner,
        "owner_team": payload.get("owner_team"),
        "owner_email": payload.get("owner_email"),
        "asset_type": payload.get("asset_type") or "service",
        "environment": payload.get("environment", "dev"),
        "criticality": payload.get("criticality", 3),
        "token": token,
        "address": payload.get("address"),
        "port": payload.get("port"),
        "is_active": payload.get("is_active", True),
        "tags": payload.get("tags", []),
        "metadata": _as_jsonb(payload.get("metadata", {})),
    }

    try:
        row = db.execute(q, params).mappings().first()
        db.commit()
        return dict(row)
    except Exception as e:
        db.rollback()
        # Return the DB error cleanly
        raise HTTPException(status_code=400, detail=f"Could not create asset: {str(e)}")


@router.patch("/by-key/{asset_key}")
def update_asset_by_key(asset_key: str, payload: dict, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """
    Partial update. We keep this safe and explicit.
    Notes:
    - asset_key is immutable here
    - tags and metadata are cast safely
    """
    exists = db.execute(
        text("SELECT asset_id FROM assets WHERE asset_key=:k"),
        {"k": asset_key}
    ).mappings().first()
    if not exists:
        raise HTTPException(status_code=404, detail="Asset not found")

    allowed = {
        "type", "name", "owner",
        "owner_team", "owner_email",
        "asset_type", "environment", "criticality",
        "verified", "verification_method", "verification_token",
        "address", "port", "is_active",
        "tags", "metadata",
    }

    fields = {k: v for k, v in payload.items() if k in allowed}
    if not fields:
        return {"ok": True, "message": "No changes"}

    if "type" in fields and fields["type"] not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Invalid asset type")

    set_parts = []
    params = {"k": asset_key}

    for k, v in fields.items():
        if k == "tags":
            set_parts.append("tags = CAST(:tags AS text[])")
            params["tags"] = v if v is not None else []
        elif k == "metadata":
            set_parts.append("metadata = CAST(:metadata AS jsonb)")
            params["metadata"] = _as_jsonb(v)
        else:
            set_parts.append(f"{k} = :{k}")
            params[k] = v

    uq = text(f"""
      UPDATE assets
      SET {", ".join(set_parts)}
      WHERE asset_key=:k
      RETURNING asset_id, asset_key, type, name, owner, environment, criticality, verified, updated_at
    """)

    try:
        row = db.execute(uq, params).mappings().first()
        log_audit(db, "asset_edit", user_name=_user, asset_key=asset_key, details=fields, request_id=request_id_ctx.get("") or None)
        db.commit()
        return dict(row)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not update asset: {str(e)}")


@router.delete("/by-key/{asset_key}")
def delete_asset_by_key(asset_key: str, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """
    Delete by asset_key. If findings references asset_id, this will fail (FK).
    """
    try:
        row = db.execute(
            text("DELETE FROM assets WHERE asset_key=:k RETURNING asset_id, asset_key"),
            {"k": asset_key}
        ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")
        db.commit()
        return {"ok": True, **dict(row)}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Could not delete asset (likely referenced by findings): {str(e)}"
        )


@router.post("/{asset_id}/verify")
def verify_asset(asset_id: int, payload: dict, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """
    Keep your original verification flow:
    Only external_web assets can be verified.
    """
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

    uq = text("""
      UPDATE assets
      SET verified=true, verification_method=:m
      WHERE asset_id=:id
      RETURNING asset_id, verified, verification_method
    """)
    try:
        row = db.execute(uq, {"m": method, "id": asset_id}).mappings().first()
        db.commit()
        return dict(row)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not verify asset: {str(e)}")
