"""Attack-lab orchestration APIs."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_lab import ATTACK_TASKS, launch_attack_lab_job
from app.db import get_db
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/attack-lab", tags=["attack-lab"])


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


def _serialize_run(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("created_at", "started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["output_json"] = _safe_json(out.get("output_json"), default={})
    return out


@router.get("/tasks")
def list_attack_tasks(_user: str = Depends(require_auth)):
    return {"items": [{"task_type": key, **value} for key, value in ATTACK_TASKS.items()]}


class AttackLabRunBody(BaseModel):
    task_type: str
    target: str
    asset_key: str | None = None


def _enqueue_attack_lab_run(
    db: Session,
    *,
    requested_by: str,
    task_type: str,
    target: str,
    asset_key: str | None,
) -> dict[str, Any]:
    task_type = task_type.strip().lower()
    target = target.strip()
    normalized_asset_key = (asset_key or "").strip() or None
    if task_type not in ATTACK_TASKS:
        raise HTTPException(status_code=400, detail="Unknown task_type")
    if not target:
        raise HTTPException(status_code=400, detail="target required")

    job_row = (
        db.execute(
            text(
                """
                INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                VALUES (
                  'attack_lab_run',
                  :requested_by,
                  'queued',
                  CAST(:job_params_json AS jsonb)
                )
                RETURNING job_id, job_type, status, created_at, job_params_json
                """
            ),
            {
                "requested_by": requested_by,
                "job_params_json": json.dumps(
                    {"task_type": task_type, "target": target, "asset_key": normalized_asset_key}
                ),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    if not job_row:
        raise HTTPException(status_code=500, detail="Failed to enqueue attack-lab job")
    job_id = int(job_row["job_id"])
    launch_attack_lab_job(job_id)
    out = dict(job_row)
    out["created_at"] = (
        out["created_at"].isoformat()
        if hasattr(out.get("created_at"), "isoformat")
        else out.get("created_at")
    )
    out["job_params_json"] = _safe_json(out.get("job_params_json"), default={})
    return out


@router.post("/run")
def start_attack_lab_run(
    body: AttackLabRunBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    return _enqueue_attack_lab_run(
        db,
        requested_by=user,
        task_type=body.task_type,
        target=body.target,
        asset_key=body.asset_key,
    )


class ScanAssetBody(BaseModel):
    asset_key: str
    task_type: str | None = None


def _target_from_asset(address: str | None, asset_key: str) -> str:
    raw_address = str(address or "").strip()
    if not raw_address:
        return asset_key
    if raw_address.startswith(("http://", "https://")):
        return raw_address
    if "://" in raw_address:
        parsed = urlparse(raw_address)
        if parsed.hostname:
            if parsed.scheme in {"http", "https"}:
                return f"{parsed.scheme}://{parsed.hostname}"
            return parsed.hostname
    return raw_address


def _default_task_for_asset(target: str, asset_key: str, requested_task: str | None) -> str:
    if requested_task and requested_task.strip().lower() in ATTACK_TASKS:
        return requested_task.strip().lower()
    if target.startswith(("http://", "https://")):
        return "web_scan"
    if "cowrie" in asset_key.lower():
        return "brute_force_sim"
    return "port_scan"


@router.post("/scan-asset")
def scan_asset_from_inventory(
    body: ScanAssetBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    asset_key = (body.asset_key or "").strip()
    if not asset_key:
        raise HTTPException(status_code=400, detail="asset_key required")
    asset = (
        db.execute(
            text(
                """
                SELECT asset_key, address, name, type, asset_type
                FROM assets
                WHERE asset_key = :asset_key
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    target = _target_from_asset(str(asset.get("address") or ""), asset_key)
    task_type = _default_task_for_asset(target, asset_key, body.task_type)
    return _enqueue_attack_lab_run(
        db,
        requested_by=user,
        task_type=task_type,
        target=target,
        asset_key=asset_key,
    )


@router.get("/runs")
def list_attack_lab_runs(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if status:
        clauses.append("status = :status")
        params["status"] = status.strip().lower()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  run_id, task_type, target_asset_id, target_asset_key, target,
                  status, requested_by, started_at, finished_at, error, output_json, created_at
                FROM attack_lab_runs
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_run(dict(row)) for row in rows]}


@router.get("/runs/{run_id}")
def get_attack_lab_run(
    run_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = (
        db.execute(
            text(
                """
                SELECT
                  run_id, task_type, target_asset_id, target_asset_key, target,
                  status, requested_by, started_at, finished_at, error, output_json, created_at
                FROM attack_lab_runs
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Attack-lab run not found")
    return _serialize_run(dict(row))
