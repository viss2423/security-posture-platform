"""Job runner: scan_jobs table, list/get/retry, logs. Phase B.3. Phase 1: publish to Redis stream."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_lab import launch_attack_lab_job
from app.db import get_db
from app.detections import launch_detection_rule_job
from app.queue import publish_scan_job
from app.repository_scan import launch_repository_scan_job
from app.routers.auth import require_auth, require_role
from app.settings import settings
from app.telemetry import launch_network_anomaly_job, launch_telemetry_import_job
from app.threat_intel import launch_threat_intel_refresh_job

router = APIRouter()


def _serialize_job(r) -> dict:
    # RowMapping (SQLAlchemy 2) doesn't convert to dict with column names; use _mapping or keys()
    out = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
    for k in ("created_at", "started_at", "finished_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    if isinstance(out.get("job_params_json"), str):
        try:
            out["job_params_json"] = json.loads(out["job_params_json"])
        except json.JSONDecodeError:
            out["job_params_json"] = {}
    return out


@router.get("")
def list_jobs(
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List recent jobs (optional status filter)."""
    q = """
    SELECT
      j.job_id,
      j.job_type,
      j.target_asset_id,
      j.requested_by,
      j.status,
      j.created_at,
      j.started_at,
      j.finished_at,
      j.error,
      j.retry_count,
      j.job_params_json,
      COALESCE(a.asset_key, j.job_params_json ->> 'asset_key') AS asset_key,
      COALESCE(a.name, j.job_params_json ->> 'asset_name') AS asset_name
    FROM scan_jobs j
    LEFT JOIN assets a ON a.asset_id = j.target_asset_id
    WHERE 1=1
    """
    params = {"limit": limit}
    if status:
        q += " AND j.status = :status"
        params["status"] = status
    q += " ORDER BY j.created_at DESC LIMIT :limit"
    rows = db.execute(text(q), params).mappings().all()
    return {"items": [_serialize_job(r) for r in rows]}


@router.get("/{job_id}")
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one job with full log_output."""
    row = (
        db.execute(
            text(
                """
                SELECT
                  j.job_id,
                  j.job_type,
                  j.target_asset_id,
                  j.requested_by,
                  j.status,
                  j.created_at,
                  j.started_at,
                  j.finished_at,
                  j.error,
                  j.log_output,
                  j.retry_count,
                  j.job_params_json,
                  COALESCE(a.asset_key, j.job_params_json ->> 'asset_key') AS asset_key,
                  COALESCE(a.name, j.job_params_json ->> 'asset_name') AS asset_name,
                  COALESCE(a.type, 'app') AS asset_type,
                  COALESCE(a.environment, j.job_params_json ->> 'environment') AS asset_environment,
                  COALESCE(a.criticality, j.job_params_json ->> 'criticality') AS asset_criticality,
                  a.verified AS asset_verified
                FROM scan_jobs j
                LEFT JOIN assets a ON a.asset_id = j.target_asset_id
                WHERE j.job_id = :id
                """
            ),
            {"id": job_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize_job(row)


@router.post("")
def create_job(
    payload: dict,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Enqueue a job (web_exposure, score_recompute, repository_scan, threat_intel_refresh, telemetry_import, network_anomaly_score, attack_lab_run, detection_rule_test). Analyst/admin only."""
    job_type = payload.get("job_type")
    asset_id = payload.get("target_asset_id")
    job_params = payload.get("job_params_json") or {}
    requested_by = payload.get("requested_by") or _user

    if job_type not in {
        "web_exposure",
        "score_recompute",
        "repository_scan",
        "threat_intel_refresh",
        "telemetry_import",
        "network_anomaly_score",
        "attack_lab_run",
        "detection_rule_test",
    }:
        raise HTTPException(status_code=400, detail="Invalid job_type")

    if asset_id is not None:
        exists = db.execute(
            text("SELECT 1 FROM assets WHERE asset_id = :id"), {"id": asset_id}
        ).first()
        if not exists:
            raise HTTPException(status_code=400, detail="Asset not found")
    if job_type == "repository_scan":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        job_params = {
            "path": str(job_params.get("path") or settings.REPOSITORY_SCAN_DEFAULT_PATH).strip(),
            "asset_key": str(
                job_params.get("asset_key") or settings.REPOSITORY_SCAN_DEFAULT_ASSET_KEY
            ).strip(),
            "asset_name": str(
                job_params.get("asset_name") or settings.REPOSITORY_SCAN_DEFAULT_ASSET_NAME
            ).strip(),
            "environment": str(
                job_params.get("environment") or settings.REPOSITORY_SCAN_DEFAULT_ENVIRONMENT
            ).strip(),
            "criticality": str(
                job_params.get("criticality") or settings.REPOSITORY_SCAN_DEFAULT_CRITICALITY
            ).strip(),
            "trivy_scanners": str(
                job_params.get("trivy_scanners") or settings.TRIVY_SCANNERS
            ).strip(),
            "enable_osv": bool(job_params.get("enable_osv", True)),
            "enable_trivy": bool(job_params.get("enable_trivy", True)),
        }
        if not job_params["path"]:
            raise HTTPException(status_code=400, detail="Repository scan path is required")
        if not job_params["asset_key"]:
            raise HTTPException(status_code=400, detail="Repository asset key is required")
        if not job_params["enable_osv"] and not job_params["enable_trivy"]:
            raise HTTPException(status_code=400, detail="Enable at least one scanner")
    elif job_type == "threat_intel_refresh":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        manual_iocs = job_params.get("manual_iocs")
        feeds = job_params.get("feeds")
        if manual_iocs is not None and not isinstance(manual_iocs, (list, str)):
            raise HTTPException(status_code=400, detail="manual_iocs must be a list or JSON string")
        if feeds is not None and not isinstance(feeds, (list, str)):
            raise HTTPException(status_code=400, detail="feeds must be a list or JSON string")
    elif job_type == "telemetry_import":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        source = str(job_params.get("source") or "").strip().lower()
        if not source:
            raise HTTPException(status_code=400, detail="telemetry source is required")
        file_path = str(job_params.get("file_path") or "").strip()
        if not file_path and source not in {"suricata", "zeek", "auditd", "cowrie"}:
            raise HTTPException(
                status_code=400, detail="file_path is required for this telemetry source"
            )
    elif job_type == "network_anomaly_score":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        lookback_hours = int(
            job_params.get("lookback_hours") or settings.TELEMETRY_DEFAULT_LOOKBACK_HOURS
        )
        if lookback_hours < 6 or lookback_hours > 720:
            raise HTTPException(status_code=400, detail="lookback_hours must be between 6 and 720")
    elif job_type == "attack_lab_run":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        task_type = str(job_params.get("task_type") or "").strip().lower()
        target = str(job_params.get("target") or "").strip()
        if task_type not in {"port_scan", "web_scan", "brute_force_sim"}:
            raise HTTPException(status_code=400, detail="Invalid attack-lab task_type")
        if not target:
            raise HTTPException(status_code=400, detail="attack-lab target is required")
    elif job_type == "detection_rule_test":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        rule_id = int(job_params.get("rule_id") or 0)
        if rule_id <= 0:
            raise HTTPException(status_code=400, detail="rule_id is required")

    q = text("""
      INSERT INTO scan_jobs(job_type, target_asset_id, requested_by, status, job_params_json)
      VALUES (:t, :aid, :rb, 'queued', CAST(:job_params_json AS jsonb))
      RETURNING job_id, job_type, target_asset_id, status, created_at, job_params_json
    """)
    row = (
        db.execute(
            q,
            {
                "t": job_type,
                "aid": asset_id,
                "rb": requested_by,
                "job_params_json": json.dumps(job_params),
            },
        )
        .mappings()
        .first()
    )
    out = _serialize_job(row)
    db.commit()
    if job_type == "repository_scan":
        launch_repository_scan_job(int(out["job_id"]))
    elif job_type == "threat_intel_refresh":
        launch_threat_intel_refresh_job(int(out["job_id"]))
    elif job_type == "telemetry_import":
        launch_telemetry_import_job(int(out["job_id"]))
    elif job_type == "network_anomaly_score":
        launch_network_anomaly_job(int(out["job_id"]))
    elif job_type == "attack_lab_run":
        launch_attack_lab_job(int(out["job_id"]))
    elif job_type == "detection_rule_test":
        launch_detection_rule_job(int(out["job_id"]))
    else:
        publish_scan_job(out["job_id"], job_type, asset_id, requested_by)
    return out


@router.post("/{job_id}/retry")
def retry_job(
    job_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Re-queue a failed job. Analyst/admin only."""
    row = (
        db.execute(text("SELECT job_id, status FROM scan_jobs WHERE job_id = :id"), {"id": job_id})
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    if row["status"] not in ("failed", "done"):
        raise HTTPException(status_code=400, detail="Only failed or completed jobs can be retried")
    db.execute(
        text("""
          UPDATE scan_jobs SET status = 'queued', error = NULL, log_output = NULL, started_at = NULL, finished_at = NULL, retry_count = retry_count + 1
          WHERE job_id = :id
        """),
        {"id": job_id},
    )
    db.commit()
    job_row = (
        db.execute(
            text(
                "SELECT job_type, target_asset_id, requested_by FROM scan_jobs WHERE job_id = :id"
            ),
            {"id": job_id},
        )
        .mappings()
        .first()
    )
    if job_row:
        if job_row["job_type"] == "repository_scan":
            launch_repository_scan_job(job_id)
        elif job_row["job_type"] == "threat_intel_refresh":
            launch_threat_intel_refresh_job(job_id)
        elif job_row["job_type"] == "telemetry_import":
            launch_telemetry_import_job(job_id)
        elif job_row["job_type"] == "network_anomaly_score":
            launch_network_anomaly_job(job_id)
        elif job_row["job_type"] == "attack_lab_run":
            launch_attack_lab_job(job_id)
        elif job_row["job_type"] == "detection_rule_test":
            launch_detection_rule_job(job_id)
        else:
            publish_scan_job(
                job_id,
                job_row["job_type"],
                job_row["target_asset_id"],
                job_row["requested_by"] or "",
            )
    return {"ok": True, "status": "queued"}
