"""Phase B.2: Policy-as-code bundles — YAML definitions, draft/approved, evaluate against posture + findings."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.policy_eval import evaluate_rules, parse_bundle_yaml
from app.request_context import request_id_ctx
from app.routers.auth import decode_token_payload, require_auth, require_role, security
from app.routers.posture import _get_filtered_posture_list

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
    row = (
        db.execute(
            text(
                "SELECT id, name, description, definition, status, created_at, updated_at, approved_at, approved_by FROM policy_bundles WHERE id = :id"
            ),
            {"id": bundle_id},
        )
        .mappings()
        .first()
    )
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
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Create a new policy bundle (draft). Definition must be valid YAML with 'rules' list."""
    try:
        parse_bundle_yaml(body.definition)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    row = (
        db.execute(
            text(
                """
                INSERT INTO policy_bundles (name, description, definition, status, updated_at)
                VALUES (:name, :description, :definition, 'draft', NOW())
                RETURNING id, name, status, created_at
                """
            ),
            {
                "name": body.name,
                "description": body.description or "",
                "definition": body.definition,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create policy bundle")
    log_audit(
        db,
        "policy_bundle.create",
        user_name=user,
        details={
            "bundle_id": int(row["id"]),
            "name": row["name"],
            "status": row["status"],
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {
        "id": row["id"],
        "name": row["name"],
        "status": row["status"],
        "created_at": row["created_at"].isoformat(),
    }


@router.patch("/bundles/{bundle_id}")
def update_bundle(
    bundle_id: int,
    body: BundleUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Update a draft bundle. Approved bundles cannot be edited."""
    row = (
        db.execute(text("SELECT id, status FROM policy_bundles WHERE id = :id"), {"id": bundle_id})
        .mappings()
        .first()
    )
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
    log_audit(
        db,
        "policy_bundle.update",
        user_name=user,
        details={
            "bundle_id": bundle_id,
            "updated_fields": sorted(
                [field for field in ("name", "description", "definition") if field in params]
            ),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return get_bundle(bundle_id, db=db)


@router.post("/bundles/{bundle_id}/approve")
def approve_bundle(
    bundle_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    """Mark bundle as approved. Only admins."""
    row = (
        db.execute(text("SELECT id, status FROM policy_bundles WHERE id = :id"), {"id": bundle_id})
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    db.execute(
        text(
            "UPDATE policy_bundles SET status = 'approved', approved_at = NOW(), approved_by = :by WHERE id = :id"
        ),
        {"id": bundle_id, "by": user},
    )
    log_audit(
        db,
        "policy_bundle.approve",
        user_name=user,
        details={"bundle_id": bundle_id},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True, "status": "approved"}


@router.post("/bundles/{bundle_id}/evaluate")
def evaluate_bundle(
    bundle_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
):
    """Run bundle rules, persist evaluation with evidence, and return the payload."""
    row = (
        db.execute(
            text(
                "SELECT id, name, definition, status, approved_by FROM policy_bundles WHERE id = :id"
            ),
            {"id": bundle_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    try:
        rules = parse_bundle_yaml(row["definition"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    assets = _get_filtered_posture_list(db)
    findings_rows = (
        db.execute(
            text("""
            SELECT
              f.finding_id,
              COALESCE(f.status, 'open') AS status,
              f.severity,
              f.category,
              f.title,
              f.source,
              f.evidence,
              f.first_seen,
              f.last_seen,
              f.time,
              a.asset_key
            FROM findings f
            LEFT JOIN assets a ON a.asset_id = f.asset_id
        """)
        )
        .mappings()
        .all()
    )
    findings_by_asset: dict[str, list[dict]] = {}
    for r in findings_rows:
        key = r.get("asset_key") or ""
        if key not in findings_by_asset:
            findings_by_asset[key] = []
        findings_by_asset[key].append(
            {
                "finding_id": r.get("finding_id"),
                "status": r.get("status"),
                "severity": (r.get("severity") or "").strip().lower(),
                "category": (r.get("category") or "").strip().lower(),
                "title": r.get("title"),
                "source": r.get("source"),
                "evidence": r.get("evidence"),
                "first_seen": r.get("first_seen").isoformat() if r.get("first_seen") else None,
                "last_seen": r.get("last_seen").isoformat() if r.get("last_seen") else None,
                "time": r.get("time").isoformat() if r.get("time") else None,
            }
        )

    result = evaluate_rules(
        rules,
        assets,
        findings_by_asset,
        bundle_approved_by=row.get("approved_by"),
    )
    payload = {"bundle_id": bundle_id, "bundle_name": row["name"], **result}
    ins = (
        db.execute(
            text("""
            INSERT INTO policy_evaluation_runs (
              bundle_id,
              evaluated_by,
              bundle_approved_by,
              score,
              violations_count,
              result_json
            )
            VALUES (
              :bundle_id,
              :evaluated_by,
              :bundle_approved_by,
              :score,
              :violations_count,
              CAST(:result_json AS jsonb)
            )
            RETURNING id, evaluated_at
        """),
            {
                "bundle_id": bundle_id,
                "evaluated_by": user,
                "bundle_approved_by": row.get("approved_by"),
                "score": result.get("score"),
                "violations_count": len(result.get("violations") or []),
                "result_json": json.dumps(payload),
            },
        )
        .mappings()
        .first()
    )
    if not ins:
        raise HTTPException(status_code=500, detail="Failed to persist policy evaluation")
    log_audit(
        db,
        "policy_bundle.evaluate",
        user_name=user,
        details={
            "bundle_id": bundle_id,
            "evaluation_id": int(ins["id"]),
            "score": result.get("score"),
            "violations_count": len(result.get("violations") or []),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {
        "evaluation_id": ins["id"],
        "evaluated_at": ins["evaluated_at"].isoformat() if ins.get("evaluated_at") else None,
        **payload,
    }


@router.get("/bundles/{bundle_id}/evaluations")
def list_bundle_evaluations(
    bundle_id: int,
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List recent persisted evaluations for one bundle (newest first)."""
    exists = (
        db.execute(
            text("SELECT id FROM policy_bundles WHERE id = :id"),
            {"id": bundle_id},
        )
        .mappings()
        .first()
    )
    if not exists:
        raise HTTPException(status_code=404, detail="Bundle not found")
    rows = (
        db.execute(
            text("""
            SELECT
              id,
              bundle_id,
              evaluated_at,
              evaluated_by,
              bundle_approved_by,
              score,
              violations_count
            FROM policy_evaluation_runs
            WHERE bundle_id = :bundle_id
            ORDER BY evaluated_at DESC
            LIMIT :limit
        """),
            {"bundle_id": bundle_id, "limit": limit},
        )
        .mappings()
        .all()
    )
    return {
        "items": [
            {
                "id": r["id"],
                "bundle_id": r["bundle_id"],
                "evaluated_at": r["evaluated_at"].isoformat() if r.get("evaluated_at") else None,
                "evaluated_by": r.get("evaluated_by"),
                "bundle_approved_by": r.get("bundle_approved_by"),
                "score": float(r["score"]) if r.get("score") is not None else None,
                "violations_count": r.get("violations_count", 0),
            }
            for r in rows
        ]
    }


@router.get("/bundles/{bundle_id}/evaluations/{evaluation_id}")
def get_bundle_evaluation(
    bundle_id: int,
    evaluation_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one persisted evaluation (full payload including evidence)."""
    row = (
        db.execute(
            text("""
            SELECT
              id,
              bundle_id,
              evaluated_at,
              evaluated_by,
              bundle_approved_by,
              score,
              violations_count,
              result_json
            FROM policy_evaluation_runs
            WHERE bundle_id = :bundle_id AND id = :evaluation_id
        """),
            {"bundle_id": bundle_id, "evaluation_id": evaluation_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    payload = row.get("result_json")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("evaluation_id", row["id"])
    payload.setdefault(
        "evaluated_at",
        row["evaluated_at"].isoformat() if row.get("evaluated_at") else None,
    )
    payload.setdefault("bundle_approved_by", row.get("bundle_approved_by"))
    return {
        "id": row["id"],
        "bundle_id": row["bundle_id"],
        "evaluated_at": row["evaluated_at"].isoformat() if row.get("evaluated_at") else None,
        "evaluated_by": row.get("evaluated_by"),
        "bundle_approved_by": row.get("bundle_approved_by"),
        "score": float(row["score"]) if row.get("score") is not None else None,
        "violations_count": row.get("violations_count", 0),
        "result": payload,
    }


@router.delete("/bundles/{bundle_id}")
def delete_bundle(
    bundle_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    """Delete a bundle. Only admins. Draft only (or allow approved with confirmation — we allow any)."""
    r = db.execute(
        text("DELETE FROM policy_bundles WHERE id = :id RETURNING id"), {"id": bundle_id}
    )
    deleted = r.fetchone()
    if not deleted:
        raise HTTPException(status_code=404, detail="Bundle not found")
    log_audit(
        db,
        "policy_bundle.delete",
        user_name=user,
        details={"bundle_id": bundle_id},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True}
