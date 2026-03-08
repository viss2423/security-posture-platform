"""Educational cyber-range missions built on top of attack-lab jobs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_lab import launch_attack_lab_job
from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role

router = APIRouter(prefix="/cyber-range", tags=["cyber-range"])

CYBER_RANGE_MISSIONS: list[dict[str, Any]] = [
    {
        "mission_id": "verify-web-baseline-scan",
        "title": "Baseline Service Enumeration",
        "description": "Run a controlled port scan against verify-web to establish known-good exposure.",
        "asset_key": "verify-web",
        "task_type": "port_scan",
        "target": "verify-web",
        "difficulty": "beginner",
        "focus": "network_enumeration",
        "mitre_techniques": ["T1595", "T1046"],
    },
    {
        "mission_id": "juice-shop-web-hardening",
        "title": "Juice Shop Header Hardening",
        "description": "Run web exposure checks on Juice Shop and triage missing security headers.",
        "asset_key": "juice-shop",
        "task_type": "web_scan",
        "target": "juiceshop:3000",
        "difficulty": "intermediate",
        "focus": "web_application_security",
        "mitre_techniques": ["T1595", "T1190"],
    },
    {
        "mission_id": "cowrie-bruteforce-drill",
        "title": "Honeypot Brute-force Drill",
        "description": "Generate controlled Cowrie failed-login activity and validate detection coverage.",
        "asset_key": "cyberlab-demo-asset",
        "task_type": "brute_force_sim",
        "target": "127.0.0.1",
        "difficulty": "intermediate",
        "focus": "credential_access_detection",
        "mitre_techniques": ["T1110", "T1059"],
    },
]


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


def _serialize_job_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    out = dict(row)
    for key in ("created_at", "started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["job_params_json"] = _safe_json(out.get("job_params_json"), default={})
    return out


def _load_assets(db: Session, asset_keys: list[str]) -> dict[str, dict[str, Any]]:
    if not asset_keys:
        return {}
    rows = (
        db.execute(
            text(
                """
                SELECT
                  asset_key,
                  name,
                  owner,
                  environment,
                  criticality,
                  asset_type,
                  verified
                FROM assets
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                """
            ),
            {"asset_keys": list(dict.fromkeys(asset_keys))},
        )
        .mappings()
        .all()
    )
    return {str(row.get("asset_key")): dict(row) for row in rows}


def _latest_mission_jobs(db: Session) -> dict[str, dict[str, Any]]:
    rows = (
        db.execute(
            text(
                """
                SELECT
                  job_id,
                  status,
                  requested_by,
                  error,
                  created_at,
                  started_at,
                  finished_at,
                  job_params_json
                FROM scan_jobs
                WHERE job_type = 'attack_lab_run'
                  AND COALESCE(job_params_json, '{}'::jsonb) ? 'mission_id'
                ORDER BY created_at DESC
                LIMIT 300
                """
            )
        )
        .mappings()
        .all()
    )
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        params = _safe_json(row.get("job_params_json"), default={})
        mission_id = str(params.get("mission_id") or "").strip()
        if not mission_id or mission_id in out:
            continue
        out[mission_id] = _serialize_job_row(dict(row)) or {}
    return out


@router.get("/missions")
def list_cyber_range_missions(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    assets = _load_assets(db, [str(m.get("asset_key") or "") for m in CYBER_RANGE_MISSIONS])
    latest_jobs = _latest_mission_jobs(db)
    items = []
    for mission in CYBER_RANGE_MISSIONS:
        asset_key = str(mission.get("asset_key") or "")
        asset = assets.get(asset_key)
        mission_id = str(mission.get("mission_id") or "")
        items.append(
            {
                **mission,
                "asset": asset,
                "asset_available": bool(asset),
                "latest_job": latest_jobs.get(mission_id),
            }
        )
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "items": items,
    }


@router.post("/missions/{mission_id}/launch")
def launch_cyber_range_mission(
    mission_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    mission = next(
        (item for item in CYBER_RANGE_MISSIONS if str(item.get("mission_id")) == mission_id),
        None,
    )
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")

    params = {
        "mission_id": mission["mission_id"],
        "task_type": mission["task_type"],
        "target": mission["target"],
        "asset_key": mission["asset_key"],
        "source": "cyber_range",
    }
    row = (
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
                RETURNING
                  job_id,
                  job_type,
                  status,
                  requested_by,
                  created_at,
                  started_at,
                  finished_at,
                  error,
                  job_params_json
                """
            ),
            {"requested_by": user, "job_params_json": json.dumps(params)},
        )
        .mappings()
        .first()
    )
    db.commit()
    if not row:
        raise HTTPException(status_code=500, detail="Failed to enqueue mission")
    job_id = int(row["job_id"])
    log_audit(
        db,
        "cyber_range.launch",
        user_name=user,
        asset_key=str(mission.get("asset_key") or ""),
        details={
            "mission_id": mission_id,
            "job_id": job_id,
            "task_type": mission.get("task_type"),
            "target": mission.get("target"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    launch_attack_lab_job(job_id)
    payload = _serialize_job_row(dict(row))
    return {"mission_id": mission_id, "job": payload}
