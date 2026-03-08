"""Attack surface discovery, exposures, drift, and relationships APIs."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_surface import run_attack_surface_discovery
from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])


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


def _serialize_times(row: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    out = dict(row)
    for key in keys:
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


class DiscoveryRunBody(BaseModel):
    domains: list[str] = []
    cert_salt: str | None = None


@router.post("/discovery/run")
def run_discovery(
    body: DiscoveryRunBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    normalized_domains = [
        str(item or "").strip().lower() for item in (body.domains or []) if str(item or "").strip()
    ]
    result = run_attack_surface_discovery(
        db,
        requested_by=user,
        source_job_id=None,
        domains=normalized_domains,
        cert_salt=(body.cert_salt or "").strip() or None,
    )
    log_audit(
        db,
        "attack_surface.discovery.run",
        user_name=user,
        details={
            "run_id": int(result.get("run_id") or 0),
            "domains": normalized_domains,
            "summary": result.get("summary") or {},
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return result


@router.get("/discovery/runs")
def list_discovery_runs(
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if status:
        clauses.append("status = :status")
        params["status"] = str(status).strip().lower()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  run_id,
                  status,
                  requested_by,
                  source_job_id,
                  started_at,
                  finished_at,
                  error,
                  metadata_json,
                  summary_json
                FROM attack_surface_discovery_runs
                WHERE {where}
                ORDER BY run_id DESC
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
        out = _serialize_times(dict(row), ["started_at", "finished_at"])
        out["metadata_json"] = _safe_json(out.get("metadata_json"), default={})
        out["summary_json"] = _safe_json(out.get("summary_json"), default={})
        items.append(out)
    return {"items": items}


@router.get("/discovery/runs/{run_id}")
def get_discovery_run(
    run_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = (
        db.execute(
            text(
                """
                SELECT
                  run_id,
                  status,
                  requested_by,
                  source_job_id,
                  started_at,
                  finished_at,
                  error,
                  metadata_json,
                  summary_json
                FROM attack_surface_discovery_runs
                WHERE run_id = :run_id
                """
            ),
            {"run_id": int(run_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Discovery run not found")
    out = _serialize_times(dict(row), ["started_at", "finished_at"])
    out["metadata_json"] = _safe_json(out.get("metadata_json"), default={})
    out["summary_json"] = _safe_json(out.get("summary_json"), default={})
    return out


def _latest_run_id(db: Session) -> int | None:
    row = (
        db.execute(
            text(
                """
                SELECT run_id
                FROM attack_surface_discovery_runs
                WHERE status = 'done'
                ORDER BY run_id DESC
                LIMIT 1
                """
            )
        )
        .mappings()
        .first()
    )
    return int(row["run_id"]) if row else None


@router.get("/discovery/hosts")
def list_discovered_hosts(
    run_id: int | None = Query(None),
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    target_run_id = int(run_id) if run_id else _latest_run_id(db)
    if not target_run_id:
        return {"run_id": None, "items": []}
    rows = (
        db.execute(
            text(
                """
                SELECT
                  host_id,
                  run_id,
                  asset_key,
                  hostname,
                  ip_address,
                  internet_exposed,
                  source,
                  discovered_at
                FROM attack_surface_hosts
                WHERE run_id = :run_id
                ORDER BY host_id ASC
                LIMIT :limit
                """
            ),
            {"run_id": target_run_id, "limit": int(limit)},
        )
        .mappings()
        .all()
    )
    return {
        "run_id": target_run_id,
        "items": [_serialize_times(dict(row), ["discovered_at"]) for row in rows],
    }


@router.get("/discovery/services")
def list_discovered_services(
    run_id: int | None = Query(None),
    limit: int = Query(10000, ge=1, le=50000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    target_run_id = int(run_id) if run_id else _latest_run_id(db)
    if not target_run_id:
        return {"run_id": None, "items": []}
    rows = (
        db.execute(
            text(
                """
                SELECT
                  service_id,
                  run_id,
                  host_id,
                  asset_key,
                  hostname,
                  port,
                  protocol,
                  service_name,
                  service_version,
                  discovered_at
                FROM attack_surface_services
                WHERE run_id = :run_id
                ORDER BY service_id ASC
                LIMIT :limit
                """
            ),
            {"run_id": target_run_id, "limit": int(limit)},
        )
        .mappings()
        .all()
    )
    return {
        "run_id": target_run_id,
        "items": [_serialize_times(dict(row), ["discovered_at"]) for row in rows],
    }


@router.get("/discovery/certs")
def list_discovered_certs(
    run_id: int | None = Query(None),
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    target_run_id = int(run_id) if run_id else _latest_run_id(db)
    if not target_run_id:
        return {"run_id": None, "items": []}
    rows = (
        db.execute(
            text(
                """
                SELECT
                  cert_id,
                  run_id,
                  host_id,
                  asset_key,
                  hostname,
                  common_name,
                  issuer,
                  serial_number,
                  fingerprint_sha256,
                  not_before,
                  not_after,
                  discovered_at
                FROM attack_surface_certificates
                WHERE run_id = :run_id
                ORDER BY cert_id ASC
                LIMIT :limit
                """
            ),
            {"run_id": target_run_id, "limit": int(limit)},
        )
        .mappings()
        .all()
    )
    return {
        "run_id": target_run_id,
        "items": [
            _serialize_times(dict(row), ["not_before", "not_after", "discovered_at"])
            for row in rows
        ],
    }


@router.get("/exposures")
def list_exposures(
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT
                  e.asset_key,
                  a.name AS asset_name,
                  a.environment,
                  a.criticality,
                  e.run_id,
                  e.internet_exposed,
                  e.open_port_count,
                  e.open_management_ports,
                  e.service_risk,
                  e.exposure_score,
                  e.exposure_level,
                  e.details_json,
                  e.updated_at
                FROM attack_surface_exposures e
                LEFT JOIN assets a ON a.asset_key = e.asset_key
                ORDER BY e.updated_at DESC, e.exposure_score DESC, e.asset_key ASC
                LIMIT :limit
                """
            ),
            {"limit": int(limit)},
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        out = _serialize_times(dict(row), ["updated_at"])
        out["details_json"] = _safe_json(out.get("details_json"), default={})
        items.append(out)
    return {"items": items}


@router.get("/drift")
def list_surface_drift(
    run_id: int | None = Query(None),
    event_type: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    target_run_id = int(run_id) if run_id else None
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if target_run_id:
        clauses.append("run_id = :run_id")
        params["run_id"] = target_run_id
    if event_type:
        clauses.append("event_type = :event_type")
        params["event_type"] = str(event_type).strip().lower()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  event_id,
                  run_id,
                  event_type,
                  severity,
                  asset_key,
                  hostname,
                  domain,
                  port,
                  details_json,
                  created_at
                FROM attack_surface_drift_events
                WHERE {where}
                ORDER BY event_id DESC
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
        out = _serialize_times(dict(row), ["created_at"])
        out["details_json"] = _safe_json(out.get("details_json"), default={})
        items.append(out)
    return {"items": items}


@router.get("/relationships")
def list_relationships(
    asset_key: str | None = Query(None),
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if asset_key:
        clauses.append("(source_asset_key = :asset_key OR target_asset_key = :asset_key)")
        params["asset_key"] = str(asset_key).strip()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  relationship_id,
                  source_asset_key,
                  target_asset_key,
                  relation_type,
                  confidence,
                  details_json,
                  updated_by,
                  created_at,
                  updated_at
                FROM attack_surface_relationships
                WHERE {where}
                ORDER BY updated_at DESC, relationship_id DESC
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
        out = _serialize_times(dict(row), ["created_at", "updated_at"])
        out["details_json"] = _safe_json(out.get("details_json"), default={})
        items.append(out)
    return {"items": items}


class RelationshipBody(BaseModel):
    source_asset_key: str
    target_asset_key: str
    relation_type: str
    confidence: float = 0.8
    details: dict[str, Any] = {}


@router.post("/relationships", status_code=201)
def upsert_relationship(
    body: RelationshipBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    source_asset_key = str(body.source_asset_key or "").strip()
    target_asset_key = str(body.target_asset_key or "").strip()
    relation_type = str(body.relation_type or "").strip().lower()
    if not source_asset_key or not target_asset_key or not relation_type:
        raise HTTPException(
            status_code=400,
            detail="source_asset_key, target_asset_key, and relation_type are required",
        )
    if source_asset_key == target_asset_key:
        raise HTTPException(status_code=400, detail="Relationship endpoints must differ")
    confidence = max(0.0, min(float(body.confidence), 1.0))
    row = (
        db.execute(
            text(
                """
                INSERT INTO attack_surface_relationships (
                  source_asset_key,
                  target_asset_key,
                  relation_type,
                  confidence,
                  details_json,
                  updated_by
                )
                VALUES (
                  :source_asset_key,
                  :target_asset_key,
                  :relation_type,
                  :confidence,
                  CAST(:details_json AS jsonb),
                  :updated_by
                )
                ON CONFLICT (source_asset_key, target_asset_key, relation_type) DO UPDATE
                SET
                  confidence = EXCLUDED.confidence,
                  details_json = EXCLUDED.details_json,
                  updated_by = EXCLUDED.updated_by,
                  updated_at = NOW()
                RETURNING
                  relationship_id,
                  source_asset_key,
                  target_asset_key,
                  relation_type,
                  confidence,
                  details_json,
                  updated_by,
                  created_at,
                  updated_at
                """
            ),
            {
                "source_asset_key": source_asset_key,
                "target_asset_key": target_asset_key,
                "relation_type": relation_type,
                "confidence": confidence,
                "details_json": json.dumps(body.details or {}),
                "updated_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to save relationship")
    out = _serialize_times(dict(row), ["created_at", "updated_at"])
    out["details_json"] = _safe_json(out.get("details_json"), default={})
    log_audit(
        db,
        "attack_surface.relationship.upsert",
        user_name=user,
        asset_key=source_asset_key,
        details={
            "relationship_id": int(out.get("relationship_id") or 0),
            "source_asset_key": source_asset_key,
            "target_asset_key": target_asset_key,
            "relation_type": relation_type,
            "confidence": confidence,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out
