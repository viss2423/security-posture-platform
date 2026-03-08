"""Job runner: scan_jobs table, list/get/retry, logs. Phase B.3. Phase 1: publish to Redis stream."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_lab import launch_attack_lab_job, run_attack_lab_job
from app.attack_surface import (
    launch_attack_surface_discovery_job,
    run_attack_surface_discovery_job,
)
from app.audit import log_audit
from app.db import SessionLocal, get_db
from app.detections import (
    launch_correlation_pass_job,
    launch_detection_rule_job,
    launch_detection_rule_scheduled_job,
    run_correlation_pass_job,
    run_detection_rule_job,
)
from app.queue import publish_scan_job
from app.request_context import request_id_ctx
from app.repository_scan import launch_repository_scan_job, run_repository_scan_job
from app.risk_scoring import backfill_finding_risk_scores, recompute_asset_findings_risk
from app.routers.auth import require_auth, require_role
from app.settings import settings
from app.telemetry import (
    launch_network_anomaly_job,
    launch_telemetry_import_job,
    run_network_anomaly_job,
    run_telemetry_import_job,
)
from app.threat_intel import launch_threat_intel_refresh_job, run_threat_intel_refresh_job

router = APIRouter()

ASYNC_JOB_TYPES = {
    "web_exposure",
    "score_recompute",
    "repository_scan",
    "threat_intel_refresh",
    "telemetry_import",
    "network_anomaly_score",
    "attack_lab_run",
    "attack_surface_discovery",
    "detection_rule_test",
    "detection_rule_schedule",
    "correlation_pass",
}
WORKER_EXECUTABLE_JOB_TYPES = {
    "score_recompute",
    "repository_scan",
    "threat_intel_refresh",
    "telemetry_import",
    "network_anomaly_score",
    "attack_lab_run",
    "attack_surface_discovery",
    "detection_rule_test",
    "detection_rule_schedule",
    "correlation_pass",
}


def _is_worker_executor(user: str) -> bool:
    normalized = (user or "").strip()
    if not normalized:
        return False
    if normalized == settings.ADMIN_USERNAME:
        return True
    return normalized in {
        settings.SCANNER_SERVICE_USERNAME,
        settings.INGESTION_SERVICE_USERNAME,
        settings.CORRELATOR_SERVICE_USERNAME,
    }


def _run_score_recompute_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'running', started_at = NOW(), finished_at = NULL, error = NULL
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        db.commit()
        row = (
            db.execute(
                text(
                    """
                    SELECT target_asset_id
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        target_asset_id = (row or {}).get("target_asset_id")
        if target_asset_id is not None:
            updated = recompute_asset_findings_risk(db, int(target_asset_id))
            summary = f"Recomputed risk for asset_id={int(target_asset_id)} findings={updated}"
        else:
            updated = backfill_finding_risk_scores(db)
            summary = f"Recomputed risk for all findings count={updated}"
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'done',
                    finished_at = NOW(),
                    log_output = COALESCE(log_output, '') || :summary || E'\n'
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id, "summary": summary},
        )
        db.commit()
    except Exception as exc:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    error = :error,
                    log_output = COALESCE(log_output, '') || :summary || E'\n'
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": job_id,
                "error": str(exc),
                "summary": f"Risk recompute failed: {exc}",
            },
        )
        db.commit()
    finally:
        db.close()


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


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None


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


@router.get("/analytics")
def jobs_analytics(
    lookback_hours: int = Query(24, ge=1, le=720),
    running_stale_minutes: int = Query(30, ge=1, le=10080),
    job_type: str | None = Query(None, description="Optional exact job_type filter"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Job reliability analytics over a lookback window."""
    normalized_job_type = (job_type or "").strip() or None
    filters = ["created_at >= NOW() - (:lookback_hours * INTERVAL '1 hour')"]
    params: dict[str, object] = {
        "lookback_hours": int(lookback_hours),
        "running_stale_minutes": int(running_stale_minutes),
    }
    if normalized_job_type:
        filters.append("job_type = :job_type")
        params["job_type"] = normalized_job_type
    where_clause = " AND ".join(filters)

    totals = (
        db.execute(
            text(
                f"""
                WITH recent_jobs AS (
                  SELECT *
                  FROM scan_jobs
                  WHERE {where_clause}
                )
                SELECT
                  COUNT(*) AS total_jobs,
                  COUNT(*) FILTER (WHERE status = 'queued') AS queued_jobs,
                  COUNT(*) FILTER (WHERE status = 'running') AS running_jobs,
                  COUNT(*) FILTER (WHERE status = 'done') AS done_jobs,
                  COUNT(*) FILTER (WHERE status = 'failed') AS failed_jobs,
                  COUNT(*) FILTER (
                    WHERE status = 'running'
                      AND started_at IS NOT NULL
                      AND started_at <= NOW() - (:running_stale_minutes * INTERVAL '1 minute')
                  ) AS stale_running_jobs,
                  COUNT(*) FILTER (WHERE retry_count > 0) AS retried_jobs,
                  COUNT(*) FILTER (
                    WHERE status IN ('done', 'failed')
                      AND started_at IS NOT NULL
                      AND finished_at IS NOT NULL
                  ) AS completed_jobs
                FROM recent_jobs
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )

    duration_stats = (
        db.execute(
            text(
                f"""
                WITH recent_jobs AS (
                  SELECT *
                  FROM scan_jobs
                  WHERE {where_clause}
                ),
                durations AS (
                  SELECT EXTRACT(EPOCH FROM (finished_at - started_at)) AS duration_seconds
                  FROM recent_jobs
                  WHERE started_at IS NOT NULL
                    AND finished_at IS NOT NULL
                    AND status IN ('done', 'failed')
                )
                SELECT
                  AVG(duration_seconds) AS avg_duration_seconds,
                  MAX(duration_seconds) AS max_duration_seconds,
                  percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_seconds) AS p95_duration_seconds
                FROM durations
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )

    queue_age_row = (
        db.execute(
            text(
                f"""
                WITH recent_jobs AS (
                  SELECT *
                  FROM scan_jobs
                  WHERE {where_clause}
                )
                SELECT
                  EXTRACT(EPOCH FROM (NOW() - MIN(created_at))) / 60.0 AS oldest_queued_minutes
                FROM recent_jobs
                WHERE status = 'queued'
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )

    by_type_rows = (
        db.execute(
            text(
                f"""
                WITH recent_jobs AS (
                  SELECT *
                  FROM scan_jobs
                  WHERE {where_clause}
                ),
                summary AS (
                  SELECT
                    job_type,
                    COUNT(*) AS total_jobs,
                    COUNT(*) FILTER (WHERE status = 'queued') AS queued_jobs,
                    COUNT(*) FILTER (WHERE status = 'running') AS running_jobs,
                    COUNT(*) FILTER (WHERE status = 'done') AS done_jobs,
                    COUNT(*) FILTER (WHERE status = 'failed') AS failed_jobs,
                    COUNT(*) FILTER (WHERE retry_count > 0) AS retried_jobs,
                    AVG(
                      EXTRACT(EPOCH FROM (finished_at - started_at))
                    ) FILTER (
                      WHERE started_at IS NOT NULL
                        AND finished_at IS NOT NULL
                        AND status IN ('done', 'failed')
                    ) AS avg_duration_seconds,
                    MAX(
                      EXTRACT(EPOCH FROM (finished_at - started_at))
                    ) FILTER (
                      WHERE started_at IS NOT NULL
                        AND finished_at IS NOT NULL
                        AND status IN ('done', 'failed')
                    ) AS max_duration_seconds
                  FROM recent_jobs
                  GROUP BY job_type
                ),
                p95 AS (
                  SELECT
                    job_type,
                    percentile_cont(0.95) WITHIN GROUP (
                      ORDER BY EXTRACT(EPOCH FROM (finished_at - started_at))
                    ) AS p95_duration_seconds
                  FROM recent_jobs
                  WHERE started_at IS NOT NULL
                    AND finished_at IS NOT NULL
                    AND status IN ('done', 'failed')
                  GROUP BY job_type
                )
                SELECT
                  s.job_type,
                  s.total_jobs,
                  s.queued_jobs,
                  s.running_jobs,
                  s.done_jobs,
                  s.failed_jobs,
                  s.retried_jobs,
                  s.avg_duration_seconds,
                  p.p95_duration_seconds,
                  s.max_duration_seconds
                FROM summary s
                LEFT JOIN p95 p ON p.job_type = s.job_type
                ORDER BY s.total_jobs DESC, s.job_type ASC
                """
            ),
            params,
        )
        .mappings()
        .all()
    )

    total_jobs = int(totals.get("total_jobs") or 0)
    done_jobs = int(totals.get("done_jobs") or 0)
    failed_jobs = int(totals.get("failed_jobs") or 0)
    completed_jobs = int(totals.get("completed_jobs") or 0)
    success_rate_pct = round((done_jobs / completed_jobs) * 100.0, 2) if completed_jobs else 0.0
    failure_rate_pct = round((failed_jobs / completed_jobs) * 100.0, 2) if completed_jobs else 0.0

    by_job_type: list[dict[str, object]] = []
    for row in by_type_rows:
        row_done = int(row.get("done_jobs") or 0)
        row_failed = int(row.get("failed_jobs") or 0)
        row_completed = row_done + row_failed
        by_job_type.append(
            {
                "job_type": str(row.get("job_type") or ""),
                "total_jobs": int(row.get("total_jobs") or 0),
                "queued_jobs": int(row.get("queued_jobs") or 0),
                "running_jobs": int(row.get("running_jobs") or 0),
                "done_jobs": row_done,
                "failed_jobs": row_failed,
                "retried_jobs": int(row.get("retried_jobs") or 0),
                "success_rate_pct": round((row_done / row_completed) * 100.0, 2)
                if row_completed
                else 0.0,
                "failure_rate_pct": round((row_failed / row_completed) * 100.0, 2)
                if row_completed
                else 0.0,
                "avg_duration_seconds": _as_float(row.get("avg_duration_seconds")),
                "p95_duration_seconds": _as_float(row.get("p95_duration_seconds")),
                "max_duration_seconds": _as_float(row.get("max_duration_seconds")),
            }
        )

    return {
        "window": {
            "lookback_hours": int(lookback_hours),
            "running_stale_minutes": int(running_stale_minutes),
            "job_type": normalized_job_type,
        },
        "totals": {
            "total_jobs": total_jobs,
            "queued_jobs": int(totals.get("queued_jobs") or 0),
            "running_jobs": int(totals.get("running_jobs") or 0),
            "stale_running_jobs": int(totals.get("stale_running_jobs") or 0),
            "done_jobs": done_jobs,
            "failed_jobs": failed_jobs,
            "completed_jobs": completed_jobs,
            "retried_jobs": int(totals.get("retried_jobs") or 0),
            "success_rate_pct": success_rate_pct,
            "failure_rate_pct": failure_rate_pct,
            "oldest_queued_minutes": _as_float(queue_age_row.get("oldest_queued_minutes")),
            "avg_duration_seconds": _as_float(duration_stats.get("avg_duration_seconds")),
            "p95_duration_seconds": _as_float(duration_stats.get("p95_duration_seconds")),
            "max_duration_seconds": _as_float(duration_stats.get("max_duration_seconds")),
        },
        "by_job_type": by_job_type,
    }


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
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Enqueue a job (web_exposure, score_recompute, repository_scan, threat_intel_refresh, telemetry_import, network_anomaly_score, attack_lab_run, attack_surface_discovery, detection_rule_test, detection_rule_schedule, correlation_pass). Analyst/admin only."""
    job_type = payload.get("job_type")
    asset_id = payload.get("target_asset_id")
    job_params = payload.get("job_params_json") or {}
    requested_by = payload.get("requested_by") or user

    if job_type not in ASYNC_JOB_TYPES:
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
        if not file_path and source not in {"suricata", "zeek", "auditd", "authlog", "cowrie"}:
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
    elif job_type == "attack_surface_discovery":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        domains = job_params.get("domains")
        if domains is not None and not isinstance(domains, list):
            raise HTTPException(status_code=400, detail="domains must be a list")
        cert_salt = job_params.get("cert_salt")
        if cert_salt is not None and not isinstance(cert_salt, str):
            raise HTTPException(status_code=400, detail="cert_salt must be a string")
    elif job_type in {"detection_rule_test", "detection_rule_schedule"}:
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        rule_id = int(job_params.get("rule_id") or 0)
        if rule_id <= 0:
            raise HTTPException(status_code=400, detail="rule_id is required")
        lookback_hours = int(job_params.get("lookback_hours") or 24)
        if lookback_hours < 1 or lookback_hours > 720:
            raise HTTPException(status_code=400, detail="lookback_hours must be between 1 and 720")
    elif job_type == "correlation_pass":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        lookback_minutes = int(job_params.get("lookback_minutes") or 60)
        if lookback_minutes < 5 or lookback_minutes > 10080:
            raise HTTPException(status_code=400, detail="lookback_minutes must be between 5 and 10080")
        correlation_rule_id = job_params.get("correlation_rule_id")
        if correlation_rule_id is not None:
            try:
                numeric_rule_id = int(correlation_rule_id)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="correlation_rule_id must be an integer") from exc
            if numeric_rule_id <= 0:
                raise HTTPException(status_code=400, detail="correlation_rule_id must be positive")

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
    log_audit(
        db,
        "job.create",
        user_name=user,
        asset_key=out.get("asset_key"),
        details={
            "job_id": out.get("job_id"),
            "job_type": out.get("job_type"),
            "target_asset_id": out.get("target_asset_id"),
            "requested_by": requested_by,
        },
        request_id=request_id_ctx.get(None),
    )
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
    elif job_type == "attack_surface_discovery":
        launch_attack_surface_discovery_job(int(out["job_id"]))
    elif job_type == "detection_rule_test":
        launch_detection_rule_job(int(out["job_id"]))
    elif job_type == "detection_rule_schedule":
        launch_detection_rule_scheduled_job(int(out["job_id"]))
    elif job_type == "correlation_pass":
        launch_correlation_pass_job(int(out["job_id"]))
    else:
        publish_scan_job(out["job_id"], job_type, asset_id, requested_by)
    return out


@router.post("/{job_id}/retry")
def retry_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
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
    log_audit(
        db,
        "job.retry",
        user_name=user,
        details={"job_id": job_id, "previous_status": row["status"]},
        request_id=request_id_ctx.get(None),
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
        elif job_row["job_type"] == "attack_surface_discovery":
            launch_attack_surface_discovery_job(job_id)
        elif job_row["job_type"] == "detection_rule_test":
            launch_detection_rule_job(job_id)
        elif job_row["job_type"] == "detection_rule_schedule":
            launch_detection_rule_scheduled_job(job_id)
        elif job_row["job_type"] == "correlation_pass":
            launch_correlation_pass_job(job_id)
        else:
            publish_scan_job(
                job_id,
                job_row["job_type"],
                job_row["target_asset_id"],
                job_row["requested_by"] or "",
            )
    return {"ok": True, "status": "queued"}


@router.post("/{job_id}/execute")
def execute_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """
    Worker execution endpoint for queued/running jobs that are executed in the API runtime.
    This is intended for service identities; human use is restricted to admin.
    """
    if not _is_worker_executor(user):
        raise HTTPException(status_code=403, detail="Worker executor access required")

    row = (
        db.execute(
            text(
                """
                SELECT job_id, job_type, status, requested_by
                FROM scan_jobs
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    job_type = str(row["job_type"] or "")
    status = str(row["status"] or "")
    if job_type not in WORKER_EXECUTABLE_JOB_TYPES:
        raise HTTPException(status_code=400, detail=f"job_type_not_worker_executable:{job_type}")
    if status not in {"queued", "running"}:
        return {
            "ok": True,
            "job_id": int(row["job_id"]),
            "job_type": job_type,
            "status": status,
            "skipped": True,
        }

    dispatchers = {
        "score_recompute": _run_score_recompute_job,
        "repository_scan": run_repository_scan_job,
        "threat_intel_refresh": run_threat_intel_refresh_job,
        "telemetry_import": run_telemetry_import_job,
        "network_anomaly_score": run_network_anomaly_job,
        "attack_lab_run": run_attack_lab_job,
        "attack_surface_discovery": run_attack_surface_discovery_job,
        "detection_rule_test": run_detection_rule_job,
        "detection_rule_schedule": run_detection_rule_job,
        "correlation_pass": run_correlation_pass_job,
    }
    runner = dispatchers.get(job_type)
    if not runner:
        raise HTTPException(status_code=400, detail=f"job_runner_missing:{job_type}")

    log_audit(
        db,
        "job.execute",
        user_name=user,
        details={
            "job_id": int(row["job_id"]),
            "job_type": job_type,
            "requested_by": row.get("requested_by"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    runner(int(row["job_id"]))

    updated = (
        db.execute(
            text(
                """
                SELECT status, error, finished_at
                FROM scan_jobs
                WHERE job_id = :job_id
                """
            ),
            {"job_id": int(row["job_id"])},
        )
        .mappings()
        .first()
    )
    if not updated:
        raise HTTPException(status_code=500, detail="Job disappeared after execution")

    return {
        "ok": True,
        "job_id": int(row["job_id"]),
        "job_type": job_type,
        "status": str(updated.get("status") or ""),
        "error": updated.get("error"),
        "finished_at": (
            updated.get("finished_at").isoformat()
            if hasattr(updated.get("finished_at"), "isoformat")
            else None
        ),
    }
