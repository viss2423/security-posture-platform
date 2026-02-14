"""Phase B.2: Policy-as-code bundles — YAML definitions, draft/approved, evaluate against posture + findings."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import require_auth, require_role, decode_token_payload
from app.routers.auth import security
from fastapi.security import HTTPAuthorizationCredentials
from app.routers.posture import _get_filtered_posture_list
from app.policy_eval import parse_bundle_yaml, evaluate_rules

router = APIRouter(prefix="/policy", tags=["policy"])


class BundleCreate(BaseModel):
    name: str
    description: str | None = None
    definition: str


class BundleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    definition: str | None = None


def _current_role(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    if not creds:
        return "viewer"
    payload = decode_token_payload(creds.credentials)
    if not payload:
        return "viewer"
    return (payload.get("role") or "admin").lower()


@router.get("/bundles")
def list_bundles(
    status: str | None = Query(None, description="Filter by status: draft, approved"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
    role: str = Depends(_current_role),
):
    """List policy bundles. Viewers see approved only; analysts/admins see all."""
    q = "SELECT id, name, description, status, created_at, updated_at, approved_at, approved_by FROM policy_bundles WHERE 1=1"
    params = {}
    if role == "viewer":
        q += " AND status = 'approved'"
    elif status:
        q += " AND status = :status"
        params["status"] = status
    q += " ORDER BY updated_at DESC"
    rows = db.execute(text(q), params).mappings().all()
    return {
        "items": [
            {
                "id": r["id"],
                "name": r["name"],
                "description": r.get("description"),
                "status": r["status"],
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
                "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None,
                "approved_at": r["approved_at"].isoformat() if r.get("approved_at") else None,
                "approved_by": r.get("approved_by"),
            }
            for r in rows
        ],
    }


@router.get("/bundles/{bundle_id}")
def get_bundle(
    bundle_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one policy bundle by id."""
    row = db.execute(
        text("SELECT id, name, description, definition, status, created_at, updated_at, approved_at, approved_by FROM policy_bundles WHERE id = :id"),
        {"id": bundle_id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row.get("description"),
        "definition": row["definition"],
        "status": row["status"],
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        "approved_at": row["approved_at"].isoformat() if row.get("approved_at") else None,
        "approved_by": row.get("approved_by"),
    }


@router.post("/bundles")
def create_bundle(
    body: BundleCreate,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Create a new policy bundle (draft). Definition must be valid YAML with 'rules' list."""
    try:
        parse_bundle_yaml(body.definition)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    db.execute(
        text("""
            INSERT INTO policy_bundles (name, description, definition, status, updated_at)
            VALUES (:name, :description, :definition, 'draft', NOW())
        """),
        {"name": body.name, "description": body.description or "", "definition": body.definition},
    )
    db.commit()
    row = db.execute(text("SELECT id, name, status, created_at FROM policy_bundles ORDER BY id DESC LIMIT 1")).mappings().first()
    return {"id": row["id"], "name": row["name"], "status": row["status"], "created_at": row["created_at"].isoformat()}


@router.patch("/bundles/{bundle_id}")
def update_bundle(
  bundle_id: int,
  body: BundleUpdate,
  db: Session = Depends(get_db),
  _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Update a draft bundle. Approved bundles cannot be edited."""
    row = db.execute(text("SELECT id, status FROM policy_bundles WHERE id = :id"), {"id": bundle_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    if row["status"] == "approved":
        raise HTTPException(status_code=400, detail="Cannot edit an approved bundle")
    updates = []
    params = {"id": bundle_id}
    if body.name is not None:
        updates.append("name = :name")
        params["name"] = body.name
    if body.description is not None:
        updates.append("description = :description")
        params["description"] = body.description
    if body.definition is not None:
        try:
            parse_bundle_yaml(body.definition)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        updates.append("definition = :definition")
        params["definition"] = body.definition
    if not updates:
        return get_bundle(bundle_id, db=db)
    updates.append("updated_at = NOW()")
    db.execute(text(f"UPDATE policy_bundles SET {', '.join(updates)} WHERE id = :id"), params)
    db.commit()
    return get_bundle(bundle_id, db=db)


@router.post("/bundles/{bundle_id}/approve")
def approve_bundle(
  bundle_id: int,
  db: Session = Depends(get_db),
  _user: str = Depends(require_role(["admin"])),
):
    """Mark bundle as approved. Only admins."""
    row = db.execute(text("SELECT id, status FROM policy_bundles WHERE id = :id"), {"id": bundle_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    db.execute(
        text("UPDATE policy_bundles SET status = 'approved', approved_at = NOW(), approved_by = :by WHERE id = :id"),
        {"id": bundle_id, "by": _user},
    )
    db.commit()
    return {"ok": True, "status": "approved"}


@router.post("/bundles/{bundle_id}/evaluate")
def evaluate_bundle(
  bundle_id: int,
  db: Session = Depends(get_db),
  _user: str = Depends(require_auth),
):
    """Run bundle rules against current posture and findings. Returns score and per-rule results."""
    row = db.execute(
        text("SELECT id, name, definition, status FROM policy_bundles WHERE id = :id"),
        {"id": bundle_id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    try:
        rules = parse_bundle_yaml(row["definition"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    assets = _get_filtered_posture_list(db)
    findings_rows = db.execute(
        text("""
            SELECT f.finding_id, COALESCE(f.status, 'open') AS status, f.severity, a.asset_key
            FROM findings f
            LEFT JOIN assets a ON a.asset_id = f.asset_id
        """)
    ).mappings().all()
    findings_by_asset = {}
    for r in findings_rows:
        key = r.get("asset_key") or ""
        if key not in findings_by_asset:
            findings_by_asset[key] = []
        findings_by_asset[key].append({"status": r.get("status"), "severity": (r.get("severity") or "").strip().lower()})
    result = evaluate_rules(rules, assets, findings_by_asset)
    return {"bundle_id": bundle_id, "bundle_name": row["name"], **result}


@router.delete("/bundles/{bundle_id}")
def delete_bundle(
  bundle_id: int,
  db: Session = Depends(get_db),
  _user: str = Depends(require_role(["admin"])),
):
    """Delete a bundle. Only admins. Draft only (or allow approved with confirmation — we allow any)."""
    r = db.execute(text("DELETE FROM policy_bundles WHERE id = :id RETURNING id"), {"id": bundle_id})
    db.commit()
    if not r.fetchone():
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {"ok": True}
