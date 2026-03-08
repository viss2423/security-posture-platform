"""AI summary versioning and analyst feedback endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/ai", tags=["ai-feedback"])

ENTITY_SUMMARY_TABLES = {
    "incident": {
        "table": "incident_ai_summaries",
        "key_column": "incident_id",
        "content_column": "summary_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
    "policy_evaluation": {
        "table": "policy_evaluation_ai_summaries",
        "key_column": "evaluation_id",
        "content_column": "summary_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
    "alert": {
        "table": "alert_ai_guidance",
        "key_column": "asset_key",
        "content_column": "guidance_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
    "job": {
        "table": "job_ai_triages",
        "key_column": "job_id",
        "content_column": "triage_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
    "asset": {
        "table": "asset_ai_diagnoses",
        "key_column": "asset_key",
        "content_column": "diagnosis_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
    "finding": {
        "table": "finding_ai_explanations",
        "key_column": "finding_id",
        "content_column": "explanation_text",
        "provider_column": "provider",
        "model_column": "model",
        "author_column": "generated_by",
        "time_column": "generated_at",
        "context_column": "context_json",
    },
}


def _safe_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _normalize_entity(entity: str) -> str:
    normalized = str(entity or "").strip().lower()
    if normalized not in ENTITY_SUMMARY_TABLES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported entity type. Use one of: {sorted(ENTITY_SUMMARY_TABLES)}",
        )
    return normalized


def _normalize_entity_key(entity: str, entity_id: str) -> str:
    key = str(entity_id or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="entity_id is required")
    key_column = ENTITY_SUMMARY_TABLES[entity]["key_column"]
    if key_column.endswith("_id"):
        if not key.isdigit():
            raise HTTPException(status_code=400, detail="entity_id must be numeric for this entity type")
        return str(int(key))
    return key


def _load_base_summary(db: Session, *, entity: str, entity_key: str) -> dict[str, Any] | None:
    config = ENTITY_SUMMARY_TABLES[entity]
    query = text(
        f"""
        SELECT
          {config['key_column']} AS entity_key,
          {config['content_column']} AS content_text,
          {config['provider_column']} AS provider,
          {config['model_column']} AS model,
          {config['author_column']} AS generated_by,
          {config['time_column']} AS generated_at,
          {config['context_column']} AS context_json
        FROM {config['table']}
        WHERE {config['key_column']} = :entity_key
        """
    )
    row = db.execute(query, {"entity_key": entity_key}).mappings().first()
    if not row:
        return None
    out = dict(row)
    generated_at = out.get("generated_at")
    if hasattr(generated_at, "isoformat"):
        out["generated_at"] = generated_at.isoformat()
    out["context_json"] = _safe_json(out.get("context_json"))
    return out


def _ensure_seed_version(db: Session, *, entity: str, entity_key: str, actor: str) -> None:
    existing = (
        db.execute(
            text(
                """
                SELECT version_id
                FROM ai_summary_versions
                WHERE entity_type = :entity_type
                  AND entity_key = :entity_key
                ORDER BY version_no DESC
                LIMIT 1
                """
            ),
            {"entity_type": entity, "entity_key": entity_key},
        )
        .mappings()
        .first()
    )
    if existing:
        return
    base = _load_base_summary(db, entity=entity, entity_key=entity_key)
    if not base:
        return
    db.execute(
        text(
            """
            INSERT INTO ai_summary_versions (
              entity_type,
              entity_key,
              version_no,
              content_text,
              provider,
              model,
              generated_by,
              source_type,
              context_json,
              evidence_json
            )
            VALUES (
              :entity_type,
              :entity_key,
              1,
              :content_text,
              :provider,
              :model,
              :generated_by,
              'seeded',
              CAST(:context_json AS jsonb),
              CAST(:evidence_json AS jsonb)
            )
            """
        ),
        {
            "entity_type": entity,
            "entity_key": entity_key,
            "content_text": str(base.get("content_text") or "").strip(),
            "provider": base.get("provider"),
            "model": base.get("model"),
            "generated_by": actor,
            "context_json": json.dumps(base.get("context_json") or {}),
            "evidence_json": json.dumps({"source": "base_summary"}),
        },
    )


def _serialize_version(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    created_at = out.get("created_at")
    if hasattr(created_at, "isoformat"):
        out["created_at"] = created_at.isoformat()
    out["context_json"] = _safe_json(out.get("context_json"))
    out["evidence_json"] = _safe_json(out.get("evidence_json"))
    return out


@router.get("/summaries/{entity}/{entity_id}/versions")
def list_summary_versions(
    entity: str,
    entity_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    entity_type = _normalize_entity(entity)
    entity_key = _normalize_entity_key(entity_type, entity_id)
    rows = (
        db.execute(
            text(
                """
                SELECT
                  version_id,
                  entity_type,
                  entity_key,
                  version_no,
                  content_text,
                  provider,
                  model,
                  generated_by,
                  source_type,
                  context_json,
                  evidence_json,
                  created_at
                FROM ai_summary_versions
                WHERE entity_type = :entity_type
                  AND entity_key = :entity_key
                ORDER BY version_no DESC
                LIMIT :limit
                """
            ),
            {"entity_type": entity_type, "entity_key": entity_key, "limit": int(limit)},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_version(dict(row)) for row in rows]}


class CreateVersionBody(BaseModel):
    content_text: str | None = None
    provider: str | None = None
    model: str | None = None
    source_type: str = "generated"
    context_json: dict[str, Any] = {}
    evidence_json: dict[str, Any] = {}


@router.post("/summaries/{entity}/{entity_id}/versions", status_code=201)
def create_summary_version(
    entity: str,
    entity_id: str,
    body: CreateVersionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    entity_type = _normalize_entity(entity)
    entity_key = _normalize_entity_key(entity_type, entity_id)
    _ensure_seed_version(db, entity=entity_type, entity_key=entity_key, actor=user)
    base = _load_base_summary(db, entity=entity_type, entity_key=entity_key)
    content_text = str(body.content_text or "").strip()
    if not content_text and base:
        content_text = str(base.get("content_text") or "").strip()
    if not content_text:
        raise HTTPException(status_code=404, detail="No AI summary exists yet for this entity")
    next_version = (
        db.execute(
            text(
                """
                SELECT COALESCE(MAX(version_no), 0) + 1 AS next_version
                FROM ai_summary_versions
                WHERE entity_type = :entity_type
                  AND entity_key = :entity_key
                """
            ),
            {"entity_type": entity_type, "entity_key": entity_key},
        )
        .mappings()
        .first()
    )
    version_no = int((next_version or {}).get("next_version") or 1)
    row = (
        db.execute(
            text(
                """
                INSERT INTO ai_summary_versions (
                  entity_type,
                  entity_key,
                  version_no,
                  content_text,
                  provider,
                  model,
                  generated_by,
                  source_type,
                  context_json,
                  evidence_json
                )
                VALUES (
                  :entity_type,
                  :entity_key,
                  :version_no,
                  :content_text,
                  :provider,
                  :model,
                  :generated_by,
                  :source_type,
                  CAST(:context_json AS jsonb),
                  CAST(:evidence_json AS jsonb)
                )
                RETURNING
                  version_id,
                  entity_type,
                  entity_key,
                  version_no,
                  content_text,
                  provider,
                  model,
                  generated_by,
                  source_type,
                  context_json,
                  evidence_json,
                  created_at
                """
            ),
            {
                "entity_type": entity_type,
                "entity_key": entity_key,
                "version_no": version_no,
                "content_text": content_text,
                "provider": body.provider or (base or {}).get("provider"),
                "model": body.model or (base or {}).get("model"),
                "generated_by": user,
                "source_type": str(body.source_type or "generated").strip().lower() or "generated",
                "context_json": json.dumps(body.context_json or (base or {}).get("context_json") or {}),
                "evidence_json": json.dumps(body.evidence_json or {}),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create version")
    out = _serialize_version(dict(row))
    log_audit(
        db,
        "ai.summary.version.create",
        user_name=user,
        details={
            "entity_type": entity_type,
            "entity_key": entity_key,
            "version_id": int(out["version_id"]),
            "version_no": int(out["version_no"]),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.get("/summaries/{entity}/{entity_id}/versions/compare")
def compare_summary_versions(
    entity: str,
    entity_id: str,
    from_version: int = Query(..., ge=1),
    to_version: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    entity_type = _normalize_entity(entity)
    entity_key = _normalize_entity_key(entity_type, entity_id)
    rows = (
        db.execute(
            text(
                """
                SELECT version_id, version_no, content_text, created_at
                FROM ai_summary_versions
                WHERE entity_type = :entity_type
                  AND entity_key = :entity_key
                  AND version_no IN (:from_version, :to_version)
                ORDER BY version_no ASC
                """
            ),
            {
                "entity_type": entity_type,
                "entity_key": entity_key,
                "from_version": int(from_version),
                "to_version": int(to_version),
            },
        )
        .mappings()
        .all()
    )
    by_version = {int(row["version_no"]): dict(row) for row in rows}
    if from_version not in by_version or to_version not in by_version:
        raise HTTPException(status_code=404, detail="One or both versions not found")
    before = by_version[from_version]
    after = by_version[to_version]
    before_text = str(before.get("content_text") or "")
    after_text = str(after.get("content_text") or "")
    before_words = len(before_text.split())
    after_words = len(after_text.split())
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "from_version": from_version,
        "to_version": to_version,
        "word_delta": after_words - before_words,
        "before_excerpt": before_text[:500],
        "after_excerpt": after_text[:500],
    }


class FeedbackBody(BaseModel):
    entity_type: str
    entity_id: str
    version_id: int | None = None
    feedback: str
    comment: str | None = None
    context_json: dict[str, Any] = {}


@router.post("/feedback", status_code=201)
def create_ai_feedback(
    body: FeedbackBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    entity_type = _normalize_entity(body.entity_type)
    entity_key = _normalize_entity_key(entity_type, body.entity_id)
    feedback = str(body.feedback or "").strip().lower()
    if feedback not in {"up", "down"}:
        raise HTTPException(status_code=400, detail="feedback must be 'up' or 'down'")
    row = (
        db.execute(
            text(
                """
                INSERT INTO ai_feedback (
                  entity_type,
                  entity_key,
                  version_id,
                  feedback,
                  comment,
                  context_json,
                  created_by
                )
                VALUES (
                  :entity_type,
                  :entity_key,
                  :version_id,
                  :feedback,
                  :comment,
                  CAST(:context_json AS jsonb),
                  :created_by
                )
                RETURNING
                  feedback_id,
                  entity_type,
                  entity_key,
                  version_id,
                  feedback,
                  comment,
                  context_json,
                  created_by,
                  created_at
                """
            ),
            {
                "entity_type": entity_type,
                "entity_key": entity_key,
                "version_id": body.version_id,
                "feedback": feedback,
                "comment": (body.comment or "").strip() or None,
                "context_json": json.dumps(body.context_json or {}),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create feedback")
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    out["context_json"] = _safe_json(out.get("context_json"))
    log_audit(
        db,
        "ai.feedback.create",
        user_name=user,
        details={
            "feedback_id": int(out["feedback_id"]),
            "entity_type": entity_type,
            "entity_key": entity_key,
            "feedback": feedback,
            "version_id": body.version_id,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.get("/feedback")
def list_ai_feedback(
    entity_type: str | None = Query(None),
    entity_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if entity_type:
        normalized_type = _normalize_entity(entity_type)
        clauses.append("entity_type = :entity_type")
        params["entity_type"] = normalized_type
        if entity_id is not None:
            clauses.append("entity_key = :entity_key")
            params["entity_key"] = _normalize_entity_key(normalized_type, entity_id)
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  feedback_id,
                  entity_type,
                  entity_key,
                  version_id,
                  feedback,
                  comment,
                  context_json,
                  created_by,
                  created_at
                FROM ai_feedback
                WHERE {where}
                ORDER BY created_at DESC, feedback_id DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        out = dict(row)
        if hasattr(out.get("created_at"), "isoformat"):
            out["created_at"] = out["created_at"].isoformat()
        out["context_json"] = _safe_json(out.get("context_json"))
        items.append(out)
    return {"items": items}


@router.get("/feedback/{feedback_id}")
def get_ai_feedback(
    feedback_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = (
        db.execute(
            text(
                """
                SELECT
                  feedback_id,
                  entity_type,
                  entity_key,
                  version_id,
                  feedback,
                  comment,
                  context_json,
                  created_by,
                  created_at
                FROM ai_feedback
                WHERE feedback_id = :feedback_id
                """
            ),
            {"feedback_id": int(feedback_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Feedback not found")
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    out["context_json"] = _safe_json(out.get("context_json"))
    return out
