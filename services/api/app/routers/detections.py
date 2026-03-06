"""Detection rule editor and test APIs."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.detections import run_detection_rule
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/detections", tags=["detections"])


def _safe_json(value: Any, *, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return default
        if isinstance(parsed, type(default)):
            return parsed
    return default


def _serialize_rule(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("created_at", "updated_at", "last_tested_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["definition_json"] = _safe_json(out.get("definition_json"), default={})
    return out


def _serialize_run(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["results_json"] = _safe_json(out.get("results_json"), default={})
    return out


class DetectionRuleBody(BaseModel):
    name: str
    description: str | None = None
    source: str | None = None
    severity: str = "medium"
    enabled: bool = True
    definition_json: dict[str, Any] = Field(default_factory=dict)


class DetectionRuleUpdateBody(BaseModel):
    description: str | None = None
    source: str | None = None
    severity: str | None = None
    enabled: bool | None = None
    definition_json: dict[str, Any] | None = None


class DetectionRuleTestBody(BaseModel):
    lookback_hours: int = 24
    create_alerts: bool = True


@router.get("/rules")
def list_detection_rules(
    include_disabled: bool = Query(False),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    where = "" if include_disabled else "WHERE enabled = TRUE"
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  rule_id, name, description, source, rule_format, severity, enabled,
                  definition_json, created_by, created_at, updated_at, last_tested_at, last_test_matches
                FROM detection_rules
                {where}
                ORDER BY updated_at DESC, rule_id DESC
                """
            )
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_rule(dict(row)) for row in rows]}


@router.post("/rules")
def create_detection_rule(
    body: DetectionRuleBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    row = (
        db.execute(
            text(
                """
                INSERT INTO detection_rules(
                  name, description, source, severity, enabled, definition_json, created_by, created_at, updated_at
                )
                VALUES (
                  :name, :description, :source, :severity, :enabled,
                  CAST(:definition_json AS jsonb), :created_by, NOW(), NOW()
                )
                RETURNING
                  rule_id, name, description, source, rule_format, severity, enabled,
                  definition_json, created_by, created_at, updated_at, last_tested_at, last_test_matches
                """
            ),
            {
                "name": name,
                "description": (body.description or "").strip() or None,
                "source": (body.source or "").strip().lower() or None,
                "severity": body.severity.strip().lower(),
                "enabled": bool(body.enabled),
                "definition_json": json.dumps(body.definition_json or {}),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create detection rule")
    return _serialize_rule(dict(row))


@router.patch("/rules/{rule_id}")
def update_detection_rule(
    rule_id: int,
    body: DetectionRuleUpdateBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    row = (
        db.execute(
            text(
                """
                SELECT rule_id, name, description, source, severity, enabled, definition_json
                FROM detection_rules
                WHERE rule_id = :rule_id
                """
            ),
            {"rule_id": rule_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    current = dict(row)
    new_definition = (
        body.definition_json
        if body.definition_json is not None
        else _safe_json(
            current.get("definition_json"),
            default={},
        )
    )
    updated = (
        db.execute(
            text(
                """
                UPDATE detection_rules
                SET
                  description = :description,
                  source = :source,
                  severity = :severity,
                  enabled = :enabled,
                  definition_json = CAST(:definition_json AS jsonb),
                  updated_at = NOW()
                WHERE rule_id = :rule_id
                RETURNING
                  rule_id, name, description, source, rule_format, severity, enabled,
                  definition_json, created_by, created_at, updated_at, last_tested_at, last_test_matches
                """
            ),
            {
                "rule_id": rule_id,
                "description": (
                    body.description if body.description is not None else current.get("description")
                ),
                "source": (
                    body.source.strip().lower()
                    if body.source is not None and body.source.strip()
                    else (current.get("source") or None)
                ),
                "severity": (
                    body.severity.strip().lower()
                    if body.severity is not None and body.severity.strip()
                    else str(current.get("severity") or "medium")
                ),
                "enabled": (
                    bool(body.enabled) if body.enabled is not None else bool(current.get("enabled"))
                ),
                "definition_json": json.dumps(new_definition or {}),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update detection rule")
    return _serialize_rule(dict(updated))


@router.post("/rules/{rule_id}/test")
def test_detection_rule(
    rule_id: int,
    body: DetectionRuleTestBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    rule_row = (
        db.execute(
            text(
                """
                SELECT
                  rule_id, name, description, source, severity, enabled, definition_json
                FROM detection_rules
                WHERE rule_id = :rule_id
                """
            ),
            {"rule_id": rule_id},
        )
        .mappings()
        .first()
    )
    if not rule_row:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    result = run_detection_rule(
        db,
        rule_row=dict(rule_row),
        lookback_hours=max(1, min(int(body.lookback_hours), 720)),
        executed_by=user,
        create_alerts=bool(body.create_alerts),
    )
    db.commit()
    return result


@router.get("/runs")
def list_detection_runs(
    rule_id: int | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if rule_id:
        clauses.append("r.rule_id = :rule_id")
        params["rule_id"] = int(rule_id)
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  r.run_id, r.rule_id, d.name AS rule_name, r.executed_by, r.lookback_hours,
                  r.status, r.matches, r.started_at, r.finished_at, r.error, r.results_json
                FROM detection_rule_runs r
                JOIN detection_rules d ON d.rule_id = r.rule_id
                WHERE {where}
                ORDER BY r.started_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_run(dict(row)) for row in rows]}
