"""Detection rule editor and test APIs."""

from __future__ import annotations

import json
import re
from typing import Any
from uuid import uuid4

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.detections import run_correlation_pass, run_correlation_rule, run_detection_rule
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/detections", tags=["detections"])
RULE_FORMATS = {"json", "yaml", "sigma"}
RULE_STAGES = {"draft", "canary", "active"}


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


def _slugify_rule_key(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return slug or "rule"


def _normalize_rule_format(value: str | None, *, fallback: str = "json") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in RULE_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported rule_format")
    return normalized


def _normalize_rule_stage(value: str | None, *, fallback: str = "active") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in RULE_STAGES:
        raise HTTPException(status_code=400, detail="Unsupported rule stage")
    return normalized


def _parse_rule_definition(
    *,
    definition_json: dict[str, Any] | None,
    definition_yaml: str | None,
    rule_format: str | None,
) -> tuple[dict[str, Any], str, str | None]:
    normalized_json = definition_json if isinstance(definition_json, dict) else {}
    yaml_blob = str(definition_yaml or "").strip() or None
    preferred_format = _normalize_rule_format(rule_format, fallback="yaml" if yaml_blob else "json")

    if preferred_format in {"yaml", "sigma"}:
        if yaml_blob:
            try:
                parsed = yaml.safe_load(yaml_blob)
            except yaml.YAMLError as exc:
                raise HTTPException(status_code=400, detail="Invalid YAML rule definition") from exc
            if parsed is None:
                parsed = {}
            if not isinstance(parsed, dict):
                raise HTTPException(
                    status_code=400, detail="YAML rule definition must be an object"
                )
            return parsed, preferred_format, yaml_blob
        if normalized_json:
            return (
                normalized_json,
                preferred_format,
                yaml.safe_dump(normalized_json, sort_keys=False),
            )
        return {}, preferred_format, None

    if normalized_json:
        return normalized_json, "json", yaml_blob
    if yaml_blob:
        try:
            parsed = yaml.safe_load(yaml_blob)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail="Invalid YAML rule definition") from exc
        if parsed is None:
            parsed = {}
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="YAML rule definition must be an object")
        return parsed, "yaml", yaml_blob
    return {}, "json", None


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
    for key in ("window_start", "window_end", "started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["results_json"] = _safe_json(out.get("results_json"), default={})
    out["snapshot_json"] = _safe_json(out.get("snapshot_json"), default={})
    return out


def _serialize_correlation_rule(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("created_at", "updated_at", "last_run_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["definition_json"] = _safe_json(out.get("definition_json"), default={})
    return out


def _serialize_correlation_run(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("window_start", "window_end", "started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["snapshot_json"] = _safe_json(out.get("snapshot_json"), default={})
    return out


class DetectionRuleBody(BaseModel):
    name: str
    description: str | None = None
    source: str | None = None
    rule_key: str | None = None
    version: int = 1
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    parent_rule_id: int | None = None
    stage: str = "active"
    rule_format: str = "json"
    severity: str = "medium"
    enabled: bool = True
    definition_json: dict[str, Any] = Field(default_factory=dict)
    definition_yaml: str | None = None


class DetectionRuleUpdateBody(BaseModel):
    description: str | None = None
    source: str | None = None
    rule_key: str | None = None
    version: int | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    parent_rule_id: int | None = None
    stage: str | None = None
    rule_format: str | None = None
    severity: str | None = None
    enabled: bool | None = None
    definition_json: dict[str, Any] | None = None
    definition_yaml: str | None = None


class DetectionRuleTestBody(BaseModel):
    lookback_hours: int = 24
    create_alerts: bool = True


class DetectionRuleSimulateBody(BaseModel):
    lookback_hours: int = 24


class CorrelationRuleBody(BaseModel):
    name: str
    description: str | None = None
    severity: str = "high"
    enabled: bool = True
    group_by: str = "asset_key"
    window_minutes: int = 60
    min_distinct_sources: int = 1
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    definition_json: dict[str, Any] = Field(default_factory=dict)


class CorrelationRuleUpdateBody(BaseModel):
    description: str | None = None
    severity: str | None = None
    enabled: bool | None = None
    group_by: str | None = None
    window_minutes: int | None = None
    min_distinct_sources: int | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    definition_json: dict[str, Any] | None = None


class CorrelationRunBody(BaseModel):
    lookback_minutes: int = 60
    create_alerts: bool = True
    run_mode: str = "manual"
    trigger_source: str = "manual"
    schedule_ref: str | None = None


def _get_rule_row(db: Session, rule_id: int) -> dict[str, Any] | None:
    row = (
        db.execute(
            text(
                """
                SELECT
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity,
                  enabled, definition_yaml, definition_json
                FROM detection_rules
                WHERE rule_id = :rule_id
                """
            ),
            {"rule_id": int(rule_id)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _get_correlation_rule_row(db: Session, correlation_rule_id: int) -> dict[str, Any] | None:
    row = (
        db.execute(
            text(
                """
                SELECT
                  correlation_rule_id,
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json,
                  created_by,
                  created_at,
                  updated_at,
                  last_run_at,
                  last_match_count
                FROM detection_correlation_rules
                WHERE correlation_rule_id = :correlation_rule_id
                """
            ),
            {"correlation_rule_id": int(correlation_rule_id)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


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
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity, enabled,
                  definition_yaml, definition_json, created_by, created_at, updated_at,
                  last_tested_at, last_test_matches
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
    definition_obj, resolved_format, resolved_yaml = _parse_rule_definition(
        definition_json=body.definition_json,
        definition_yaml=body.definition_yaml,
        rule_format=body.rule_format,
    )
    normalized_rule_key = (body.rule_key or "").strip().lower() or _slugify_rule_key(name)
    normalized_stage = _normalize_rule_stage(body.stage)
    normalized_version = max(1, int(body.version or 1))
    parent_rule_id = int(body.parent_rule_id) if body.parent_rule_id else None
    row = (
        db.execute(
            text(
                """
                INSERT INTO detection_rules(
                  name, description, source, rule_key, version, mitre_tactic, mitre_technique,
                  parent_rule_id, stage, rule_format, severity, enabled, definition_yaml,
                  definition_json, created_by, created_at, updated_at
                )
                VALUES (
                  :name, :description, :source, :rule_key, :version, :mitre_tactic, :mitre_technique,
                  :parent_rule_id, :stage, :rule_format, :severity, :enabled, :definition_yaml,
                  CAST(:definition_json AS jsonb), :created_by, NOW(), NOW()
                )
                RETURNING
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity, enabled,
                  definition_yaml, definition_json, created_by, created_at, updated_at,
                  last_tested_at, last_test_matches
                """
            ),
            {
                "name": name,
                "description": (body.description or "").strip() or None,
                "source": (body.source or "").strip().lower() or None,
                "rule_key": normalized_rule_key,
                "version": normalized_version,
                "mitre_tactic": (body.mitre_tactic or "").strip() or None,
                "mitre_technique": (body.mitre_technique or "").strip() or None,
                "parent_rule_id": parent_rule_id,
                "stage": normalized_stage,
                "rule_format": resolved_format,
                "severity": body.severity.strip().lower(),
                "enabled": bool(body.enabled),
                "definition_yaml": resolved_yaml,
                "definition_json": json.dumps(definition_obj),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create detection rule")
    out = _serialize_rule(dict(row))
    log_audit(
        db,
        "detection_rule.create",
        user_name=user,
        details={
            "rule_id": out.get("rule_id"),
            "name": out.get("name"),
            "rule_key": out.get("rule_key"),
            "version": out.get("version"),
            "stage": out.get("stage"),
            "rule_format": out.get("rule_format"),
            "source": out.get("source"),
            "severity": out.get("severity"),
            "enabled": out.get("enabled"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.patch("/rules/{rule_id}")
def update_detection_rule(
    rule_id: int,
    body: DetectionRuleUpdateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    row = (
        db.execute(
            text(
                """
                SELECT
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity,
                  enabled, definition_yaml, definition_json
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
    definition_obj, resolved_format, resolved_yaml = _parse_rule_definition(
        definition_json=(
            body.definition_json
            if body.definition_json is not None
            else _safe_json(current.get("definition_json"), default={})
        ),
        definition_yaml=(
            body.definition_yaml
            if body.definition_yaml is not None
            else str(current.get("definition_yaml") or "").strip() or None
        ),
        rule_format=(
            body.rule_format if body.rule_format is not None else current.get("rule_format")
        ),
    )
    rule_key = (
        body.rule_key.strip().lower()
        if body.rule_key is not None and body.rule_key.strip()
        else str(current.get("rule_key") or "").strip().lower()
    )
    if not rule_key:
        rule_key = _slugify_rule_key(str(current.get("name") or f"rule-{rule_id}"))
    updated = (
        db.execute(
            text(
                """
                UPDATE detection_rules
                SET
                  description = :description,
                  source = :source,
                  rule_key = :rule_key,
                  version = :version,
                  mitre_tactic = :mitre_tactic,
                  mitre_technique = :mitre_technique,
                  parent_rule_id = :parent_rule_id,
                  stage = :stage,
                  rule_format = :rule_format,
                  severity = :severity,
                  enabled = :enabled,
                  definition_yaml = :definition_yaml,
                  definition_json = CAST(:definition_json AS jsonb),
                  updated_at = NOW()
                WHERE rule_id = :rule_id
                RETURNING
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity, enabled,
                  definition_yaml, definition_json, created_by, created_at, updated_at,
                  last_tested_at, last_test_matches
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
                "rule_key": rule_key,
                "version": (
                    max(1, int(body.version))
                    if body.version is not None
                    else int(current.get("version") or 1)
                ),
                "mitre_tactic": (
                    body.mitre_tactic.strip()
                    if body.mitre_tactic is not None and body.mitre_tactic.strip()
                    else (current.get("mitre_tactic") or None)
                ),
                "mitre_technique": (
                    body.mitre_technique.strip()
                    if body.mitre_technique is not None and body.mitre_technique.strip()
                    else (current.get("mitre_technique") or None)
                ),
                "parent_rule_id": (
                    int(body.parent_rule_id)
                    if body.parent_rule_id
                    else current.get("parent_rule_id")
                ),
                "stage": (
                    _normalize_rule_stage(body.stage)
                    if body.stage is not None
                    else _normalize_rule_stage(current.get("stage"))
                ),
                "rule_format": resolved_format,
                "severity": (
                    body.severity.strip().lower()
                    if body.severity is not None and body.severity.strip()
                    else str(current.get("severity") or "medium")
                ),
                "enabled": (
                    bool(body.enabled) if body.enabled is not None else bool(current.get("enabled"))
                ),
                "definition_yaml": resolved_yaml,
                "definition_json": json.dumps(definition_obj),
            },
        )
        .mappings()
        .first()
    )
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update detection rule")
    out = _serialize_rule(dict(updated))
    log_audit(
        db,
        "detection_rule.update",
        user_name=user,
        details={
            "rule_id": out.get("rule_id"),
            "name": out.get("name"),
            "rule_key": out.get("rule_key"),
            "version": out.get("version"),
            "stage": out.get("stage"),
            "rule_format": out.get("rule_format"),
            "source": out.get("source"),
            "severity": out.get("severity"),
            "enabled": out.get("enabled"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.post("/rules/{rule_id}/clone")
def clone_detection_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    current = _get_rule_row(db, rule_id)
    if not current:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    current_name = str(current.get("name") or f"rule-{rule_id}").strip()
    current_rule_key = str(current.get("rule_key") or "").strip().lower() or _slugify_rule_key(
        current_name
    )
    next_version_row = (
        db.execute(
            text(
                """
                SELECT COALESCE(MAX(version), 0) + 1 AS next_version
                FROM detection_rules
                WHERE rule_key = :rule_key
                """
            ),
            {"rule_key": current_rule_key},
        )
        .mappings()
        .first()
        or {}
    )
    next_version = max(1, int(next_version_row.get("next_version") or 1))
    clone_name = f"{current_name} (clone v{next_version}-{uuid4().hex[:6]})"
    row = (
        db.execute(
            text(
                """
                INSERT INTO detection_rules(
                  name, description, source, rule_key, version, mitre_tactic, mitre_technique,
                  parent_rule_id, stage, rule_format, severity, enabled, definition_yaml,
                  definition_json, created_by, created_at, updated_at
                )
                VALUES (
                  :name, :description, :source, :rule_key, :version, :mitre_tactic, :mitre_technique,
                  :parent_rule_id, 'draft', :rule_format, :severity, FALSE, :definition_yaml,
                  CAST(:definition_json AS jsonb), :created_by, NOW(), NOW()
                )
                RETURNING
                  rule_id, name, description, source, rule_key, version, mitre_tactic,
                  mitre_technique, parent_rule_id, stage, rule_format, severity, enabled,
                  definition_yaml, definition_json, created_by, created_at, updated_at,
                  last_tested_at, last_test_matches
                """
            ),
            {
                "name": clone_name,
                "description": current.get("description"),
                "source": current.get("source"),
                "rule_key": current_rule_key,
                "version": next_version,
                "mitre_tactic": current.get("mitre_tactic"),
                "mitre_technique": current.get("mitre_technique"),
                "parent_rule_id": int(current.get("rule_id") or rule_id),
                "rule_format": current.get("rule_format") or "json",
                "severity": current.get("severity") or "medium",
                "definition_yaml": str(current.get("definition_yaml") or "").strip() or None,
                "definition_json": json.dumps(
                    _safe_json(current.get("definition_json"), default={}) or {}
                ),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to clone detection rule")
    out = _serialize_rule(dict(row))
    log_audit(
        db,
        "detection_rule.clone",
        user_name=user,
        details={
            "source_rule_id": int(rule_id),
            "cloned_rule_id": out.get("rule_id"),
            "rule_key": out.get("rule_key"),
            "version": out.get("version"),
            "stage": out.get("stage"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.post("/rules/{rule_id}/test")
def test_detection_rule(
    rule_id: int,
    body: DetectionRuleTestBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    rule_row = _get_rule_row(db, rule_id)
    if not rule_row:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    result = run_detection_rule(
        db,
        rule_row=rule_row,
        lookback_hours=max(1, min(int(body.lookback_hours), 720)),
        executed_by=user,
        create_alerts=bool(body.create_alerts),
        run_mode="test",
        trigger_source="manual",
    )
    log_audit(
        db,
        "detection_rule.test",
        user_name=user,
        details={
            "rule_id": int(rule_id),
            "lookback_hours": int(result.get("lookback_hours") or body.lookback_hours),
            "matches": int(result.get("matches") or 0),
            "candidate_events": int(result.get("candidate_events") or 0),
            "create_alerts": bool(body.create_alerts),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return result


@router.post("/rules/{rule_id}/simulate")
def simulate_detection_rule(
    rule_id: int,
    body: DetectionRuleSimulateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    rule_row = _get_rule_row(db, rule_id)
    if not rule_row:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    result = run_detection_rule(
        db,
        rule_row=rule_row,
        lookback_hours=max(1, min(int(body.lookback_hours), 720)),
        executed_by=user,
        create_alerts=False,
        run_mode="simulate",
        trigger_source="manual",
    )
    log_audit(
        db,
        "detection_rule.simulate",
        user_name=user,
        details={
            "rule_id": int(rule_id),
            "lookback_hours": int(result.get("lookback_hours") or body.lookback_hours),
            "matches": int(result.get("matches") or 0),
            "candidate_events": int(result.get("candidate_events") or 0),
            "snapshot_hash": str(result.get("snapshot_hash") or ""),
        },
        request_id=request_id_ctx.get(None),
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
                  r.status, r.matches, r.run_mode, r.trigger_source, r.schedule_ref,
                  r.create_alerts, r.snapshot_hash, r.snapshot_json, r.rule_version, r.rule_stage,
                  r.window_start, r.window_end, r.started_at, r.finished_at, r.error, r.results_json
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


@router.get("/coverage/mitre")
def mitre_coverage(
    lookback_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    enabled_rule_rows = (
        db.execute(
            text(
                """
                SELECT mitre_tactic, mitre_technique
                FROM detection_rules
                WHERE enabled = TRUE
                  AND stage = 'active'
                """
            )
        )
        .mappings()
        .all()
    )
    enabled_correlation_rows = (
        db.execute(
            text(
                """
                SELECT mitre_tactic, mitre_technique
                FROM detection_correlation_rules
                WHERE enabled = TRUE
                """
            )
        )
        .mappings()
        .all()
    )
    tactics: dict[str, int] = {}
    techniques: dict[str, int] = {}
    mapped_rules = 0
    total_rules = len(enabled_rule_rows) + len(enabled_correlation_rows)
    for row in [*enabled_rule_rows, *enabled_correlation_rows]:
        tactic = str(row.get("mitre_tactic") or "").strip()
        technique = str(row.get("mitre_technique") or "").strip()
        if tactic or technique:
            mapped_rules += 1
        if tactic:
            tactics[tactic] = tactics.get(tactic, 0) + 1
        if technique:
            techniques[technique] = techniques.get(technique, 0) + 1

    top_detected = (
        db.execute(
            text(
                """
                SELECT technique, COUNT(*) AS detections
                FROM (
                  SELECT jsonb_array_elements_text(mitre_techniques) AS technique
                  FROM security_alerts
                  WHERE last_seen_at >= NOW() - (:lookback_days * INTERVAL '1 day')
                ) expanded
                GROUP BY technique
                ORDER BY detections DESC, technique ASC
                LIMIT 15
                """
            ),
            {"lookback_days": int(lookback_days)},
        )
        .mappings()
        .all()
    )

    return {
        "lookback_days": int(lookback_days),
        "totals": {
            "enabled_rules": total_rules,
            "mapped_rules": mapped_rules,
            "mapping_coverage_pct": round((mapped_rules / total_rules) * 100.0, 2)
            if total_rules
            else 0.0,
            "covered_tactics": len(tactics),
            "covered_techniques": len(techniques),
        },
        "tactics": [
            {"mitre_tactic": tactic, "rule_count": count}
            for tactic, count in sorted(tactics.items(), key=lambda item: (-item[1], item[0]))
        ],
        "techniques": [
            {"mitre_technique": technique, "rule_count": count}
            for technique, count in sorted(techniques.items(), key=lambda item: (-item[1], item[0]))
        ],
        "top_detected_techniques": [
            {
                "mitre_technique": str(item.get("technique") or ""),
                "detections": int(item.get("detections") or 0),
            }
            for item in top_detected
        ],
    }


@router.get("/correlations/rules")
def list_correlation_rules(
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
                  correlation_rule_id,
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json,
                  created_by,
                  created_at,
                  updated_at,
                  last_run_at,
                  last_match_count
                FROM detection_correlation_rules
                {where}
                ORDER BY updated_at DESC, correlation_rule_id DESC
                """
            )
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_correlation_rule(dict(row)) for row in rows]}


@router.post("/correlations/rules")
def create_correlation_rule(
    body: CorrelationRuleBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    group_by = str(body.group_by or "asset_key").strip().lower() or "asset_key"
    if group_by not in {"asset_key", "source_ip", "none"}:
        raise HTTPException(status_code=400, detail="Unsupported correlation group_by")
    window_minutes = max(5, min(int(body.window_minutes), 10080))
    min_distinct_sources = max(1, min(int(body.min_distinct_sources), 25))
    row = (
        db.execute(
            text(
                """
                INSERT INTO detection_correlation_rules(
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json,
                  created_by,
                  created_at,
                  updated_at
                )
                VALUES (
                  :name,
                  :description,
                  :severity,
                  :enabled,
                  :group_by,
                  :window_minutes,
                  :min_distinct_sources,
                  :mitre_tactic,
                  :mitre_technique,
                  CAST(:definition_json AS jsonb),
                  :created_by,
                  NOW(),
                  NOW()
                )
                RETURNING
                  correlation_rule_id,
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json,
                  created_by,
                  created_at,
                  updated_at,
                  last_run_at,
                  last_match_count
                """
            ),
            {
                "name": name,
                "description": (body.description or "").strip() or None,
                "severity": str(body.severity or "high").strip().lower(),
                "enabled": bool(body.enabled),
                "group_by": group_by,
                "window_minutes": window_minutes,
                "min_distinct_sources": min_distinct_sources,
                "mitre_tactic": (body.mitre_tactic or "").strip() or None,
                "mitre_technique": (body.mitre_technique or "").strip() or None,
                "definition_json": json.dumps(body.definition_json or {}),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create correlation rule")
    out = _serialize_correlation_rule(dict(row))
    log_audit(
        db,
        "correlation_rule.create",
        user_name=user,
        details={
            "correlation_rule_id": out.get("correlation_rule_id"),
            "name": out.get("name"),
            "severity": out.get("severity"),
            "enabled": out.get("enabled"),
            "group_by": out.get("group_by"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.patch("/correlations/rules/{correlation_rule_id}")
def update_correlation_rule(
    correlation_rule_id: int,
    body: CorrelationRuleUpdateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    current = _get_correlation_rule_row(db, correlation_rule_id)
    if not current:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    group_by = (
        str(body.group_by).strip().lower()
        if body.group_by is not None
        else str(current.get("group_by") or "asset_key").strip().lower()
    )
    if group_by not in {"asset_key", "source_ip", "none"}:
        raise HTTPException(status_code=400, detail="Unsupported correlation group_by")
    definition_json = (
        body.definition_json
        if body.definition_json is not None
        else _safe_json(current.get("definition_json"), default={})
    )
    row = (
        db.execute(
            text(
                """
                UPDATE detection_correlation_rules
                SET
                  description = :description,
                  severity = :severity,
                  enabled = :enabled,
                  group_by = :group_by,
                  window_minutes = :window_minutes,
                  min_distinct_sources = :min_distinct_sources,
                  mitre_tactic = :mitre_tactic,
                  mitre_technique = :mitre_technique,
                  definition_json = CAST(:definition_json AS jsonb),
                  updated_at = NOW()
                WHERE correlation_rule_id = :correlation_rule_id
                RETURNING
                  correlation_rule_id,
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json,
                  created_by,
                  created_at,
                  updated_at,
                  last_run_at,
                  last_match_count
                """
            ),
            {
                "correlation_rule_id": int(correlation_rule_id),
                "description": body.description
                if body.description is not None
                else current.get("description"),
                "severity": (
                    str(body.severity).strip().lower()
                    if body.severity is not None and str(body.severity).strip()
                    else str(current.get("severity") or "high")
                ),
                "enabled": (
                    bool(body.enabled) if body.enabled is not None else bool(current.get("enabled"))
                ),
                "group_by": group_by,
                "window_minutes": (
                    max(5, min(int(body.window_minutes), 10080))
                    if body.window_minutes is not None
                    else int(current.get("window_minutes") or 60)
                ),
                "min_distinct_sources": (
                    max(1, min(int(body.min_distinct_sources), 25))
                    if body.min_distinct_sources is not None
                    else int(current.get("min_distinct_sources") or 1)
                ),
                "mitre_tactic": (
                    body.mitre_tactic.strip()
                    if body.mitre_tactic is not None and body.mitre_tactic.strip()
                    else (current.get("mitre_tactic") or None)
                ),
                "mitre_technique": (
                    body.mitre_technique.strip()
                    if body.mitre_technique is not None and body.mitre_technique.strip()
                    else (current.get("mitre_technique") or None)
                ),
                "definition_json": json.dumps(definition_json or {}),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to update correlation rule")
    out = _serialize_correlation_rule(dict(row))
    log_audit(
        db,
        "correlation_rule.update",
        user_name=user,
        details={
            "correlation_rule_id": out.get("correlation_rule_id"),
            "name": out.get("name"),
            "severity": out.get("severity"),
            "enabled": out.get("enabled"),
            "group_by": out.get("group_by"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.post("/correlations/rules/{correlation_rule_id}/run")
def run_correlation_rule_endpoint(
    correlation_rule_id: int,
    body: CorrelationRunBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    rule_row = _get_correlation_rule_row(db, correlation_rule_id)
    if not rule_row:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    result = run_correlation_rule(
        db,
        rule_row=rule_row,
        lookback_minutes=max(5, min(int(body.lookback_minutes), 10080)),
        executed_by=user,
        create_alerts=bool(body.create_alerts),
        run_mode=str(body.run_mode or "manual"),
        trigger_source=str(body.trigger_source or "manual"),
        schedule_ref=body.schedule_ref,
    )
    log_audit(
        db,
        "correlation_rule.run",
        user_name=user,
        details={
            "correlation_rule_id": int(correlation_rule_id),
            "run_id": result.get("run_id"),
            "lookback_minutes": int(result.get("lookback_minutes") or body.lookback_minutes),
            "matched_chains": int(result.get("matched_chains") or 0),
            "alerts_created": int(result.get("alerts_created") or 0),
            "snapshot_hash": str(result.get("snapshot_hash") or ""),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return result


@router.post("/correlations/run")
def run_all_correlations(
    body: CorrelationRunBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    result = run_correlation_pass(
        db,
        executed_by=user,
        lookback_minutes=max(5, min(int(body.lookback_minutes), 10080)),
        create_alerts=bool(body.create_alerts),
        run_mode=str(body.run_mode or "manual"),
        trigger_source=str(body.trigger_source or "manual"),
        schedule_ref=body.schedule_ref,
    )
    log_audit(
        db,
        "correlation_pass.run",
        user_name=user,
        details={
            "lookback_minutes": int(result.get("lookback_minutes") or body.lookback_minutes),
            "correlation_rule_count": int(result.get("correlation_rule_count") or 0),
            "matched_chains": int(result.get("matched_chains") or 0),
            "alerts_created": int(result.get("alerts_created") or 0),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return result


@router.get("/correlations/runs")
def list_correlation_runs(
    correlation_rule_id: int | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if correlation_rule_id is not None:
        clauses.append("r.correlation_rule_id = :correlation_rule_id")
        params["correlation_rule_id"] = int(correlation_rule_id)
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  r.run_id,
                  r.correlation_rule_id,
                  cr.name AS rule_name,
                  r.executed_by,
                  r.run_mode,
                  r.trigger_source,
                  r.schedule_ref,
                  r.lookback_minutes,
                  r.window_start,
                  r.window_end,
                  r.matched_chains,
                  r.alerts_created,
                  r.snapshot_hash,
                  r.snapshot_json,
                  r.started_at,
                  r.finished_at,
                  r.error
                FROM detection_correlation_runs r
                JOIN detection_correlation_rules cr
                  ON cr.correlation_rule_id = r.correlation_rule_id
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
    return {"items": [_serialize_correlation_run(dict(row)) for row in rows]}
