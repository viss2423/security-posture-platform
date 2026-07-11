"""Job runner: scan_jobs table, list/get/retry, logs. Phase B.3. Phase 1: publish to Redis stream."""

import json
import time
from uuid import uuid4

import requests
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.attack_lab import launch_attack_lab_job, run_attack_lab_job
from app.attack_surface import (
    launch_attack_surface_discovery_job,
    run_attack_surface_discovery_job,
)
from app.audit import log_audit
from app.aws_iam_connector import launch_aws_iam_posture_job, run_aws_iam_posture_job
from app.db import SessionLocal, get_db
from app.detections import (
    launch_correlation_pass_job,
    launch_detection_rule_job,
    launch_detection_rule_scheduled_job,
    run_correlation_pass_job,
    run_detection_rule_job,
)
from app.github_connector import launch_github_posture_job, run_github_posture_job
from app.queue import publish_scan_job
from app.repository_scan import launch_repository_scan_job, run_repository_scan_job
from app.request_context import current_tenant_id, request_id_ctx
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
internal_router = APIRouter(prefix="/internal/jobs", tags=["internal-jobs"])

ASYNC_JOB_TYPES = {
    "aws_iam_posture",
    "github_posture",
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
    "aws_iam_posture",
    "github_posture",
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

SAFE_HEADERS_TO_CHECK = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


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


def _require_worker_executor(user: str) -> str:
    if not _is_worker_executor(user):
        raise HTTPException(status_code=403, detail="Worker executor access required")
    return user


def _job_claim_timeout_seconds() -> int:
    return max(int(getattr(settings, "MAX_SCAN_DURATION_SECONDS", 900)) + 60, 300)


def _append_job_log(db: Session, job_id: int, log_line: str) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
            SET log_output = COALESCE(log_output, '') || :log_line || E'\n'
            WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "log_line": log_line},
    )


def _mark_job_terminal(
    db: Session,
    job_id: int,
    *,
    status: str,
    error: str | None = None,
    log_line: str | None = None,
    clear_claim: bool = False,
) -> None:
    if log_line:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = :status,
                    finished_at = NOW(),
                    error = :error,
                    log_output = COALESCE(log_output, '') || :log_line || E'\n',
                    claimed_by = CASE WHEN :clear_claim THEN NULL ELSE claimed_by END,
                    claim_token = CASE WHEN :clear_claim THEN NULL ELSE claim_token END,
                    last_heartbeat_at = CASE WHEN :clear_claim THEN NULL ELSE last_heartbeat_at END
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": job_id,
                "status": status,
                "error": error,
                "log_line": log_line,
                "clear_claim": clear_claim,
            },
        )
    else:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = :status,
                    finished_at = NOW(),
                    error = :error,
                    claimed_by = CASE WHEN :clear_claim THEN NULL ELSE claimed_by END,
                    claim_token = CASE WHEN :clear_claim THEN NULL ELSE claim_token END,
                    last_heartbeat_at = CASE WHEN :clear_claim THEN NULL ELSE last_heartbeat_at END
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": job_id,
                "status": status,
                "error": error,
                "clear_claim": clear_claim,
            },
        )


def _clear_job_claim(db: Session, job_id: int) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
            SET claimed_by = NULL,
                claim_token = NULL,
                last_heartbeat_at = NULL
            WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id},
    )


def _scan_external_web(asset_name: str) -> dict[str, object]:
    http_url = f"http://{asset_name}/"
    https_url = f"https://{asset_name}/"
    results: dict[str, object] = {
        "reachable_http": False,
        "reachable_https": False,
        "missing_headers": [],
    }

    try:
        requests.get(http_url, timeout=6, allow_redirects=True)  # nosemgrep
        results["reachable_http"] = True
    except Exception:
        pass

    try:
        response = requests.get(https_url, timeout=8, allow_redirects=True)
        results["reachable_https"] = True
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        missing_headers: list[str] = []
        for header_name in SAFE_HEADERS_TO_CHECK:
            if header_name not in headers_lower:
                missing_headers.append(header_name)
        results["missing_headers"] = missing_headers
    except Exception:
        pass

    return results


def _run_web_exposure_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'running',
                    started_at = COALESCE(started_at, NOW()),
                    finished_at = NULL,
                    error = NULL
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        db.commit()

        job_row = (
            db.execute(
                text(
                    """
                    SELECT
                      j.target_asset_id,
                      a.asset_id,
                      a.name,
                      a.type,
                      a.verified
                    FROM scan_jobs j
                    LEFT JOIN assets a ON a.asset_id = j.target_asset_id
                    WHERE j.job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        asset_id = (job_row or {}).get("asset_id")
        if asset_id is None:
            _mark_job_terminal(
                db,
                job_id,
                status="failed",
                error="Asset not found",
                log_line="Asset not found",
            )
            db.commit()
            return

        asset_type = str((job_row or {}).get("type") or "")
        if asset_type != "external_web":
            _mark_job_terminal(
                db,
                job_id,
                status="failed",
                error="Target is not external_web",
                log_line="Target is not external_web",
            )
            db.commit()
            return

        if settings.REQUIRE_DOMAIN_VERIFICATION and not bool((job_row or {}).get("verified")):
            _mark_job_terminal(
                db,
                job_id,
                status="failed",
                error="Domain not verified",
                log_line="Domain not verified",
            )
            db.commit()
            return

        asset_name = str((job_row or {}).get("name") or "").strip()
        _append_job_log(
            db,
            job_id,
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Started web exposure scan for asset_id={asset_id}",
        )
        _append_job_log(db, job_id, f"Scanning {asset_name} ...")
        db.commit()

        started_at = time.time()
        scan = _scan_external_web(asset_name)
        elapsed = time.time() - started_at
        _append_job_log(
            db,
            job_id,
            (
                "Scan completed in "
                f"{elapsed:.1f}s: HTTPS={scan['reachable_https']}, "
                f"missing_headers={len(scan['missing_headers'])}"
            ),
        )

        evidence = json.dumps({"scan": scan, "elapsed_seconds": elapsed}, indent=2)
        if not bool(scan["reachable_https"]):
            db.execute(
                text(
                    """
                    INSERT INTO findings(
                      asset_id,
                      category,
                      title,
                      severity,
                      confidence,
                      evidence,
                      remediation
                    )
                    VALUES(
                      :asset_id,
                      'transport',
                      'HTTPS not reachable',
                      'high',
                      'high',
                      :evidence,
                      'Ensure HTTPS is enabled and reachable. Configure TLS and redirect HTTP to HTTPS.'
                    )
                    """
                ),
                {"asset_id": int(asset_id), "evidence": evidence},
            )
            _append_job_log(db, job_id, "Finding: HTTPS not reachable")
        missing_headers = scan["missing_headers"]
        if isinstance(missing_headers, list) and missing_headers:
            db.execute(
                text(
                    """
                    INSERT INTO findings(
                      asset_id,
                      category,
                      title,
                      severity,
                      confidence,
                      evidence,
                      remediation
                    )
                    VALUES(
                      :asset_id,
                      'headers',
                      :title,
                      'medium',
                      'high',
                      :evidence,
                      'Add recommended security headers (HSTS, CSP, X-Frame-Options, etc.) via your web server/CDN configuration.'
                    )
                    """
                ),
                {
                    "asset_id": int(asset_id),
                    "title": f"Missing security headers: {', '.join(str(item) for item in missing_headers)}",
                    "evidence": evidence,
                },
            )
            _append_job_log(db, job_id, f"Finding: Missing headers {missing_headers}")

        _mark_job_terminal(db, job_id, status="done", log_line="Done")
        db.commit()
    except Exception as exc:
        _mark_job_terminal(
            db,
            job_id,
            status="failed",
            error=str(exc),
            log_line=f"Web exposure job failed: {exc}",
        )
        db.commit()
    finally:
        db.close()


def _load_internal_job_state(db: Session, job_id: int) -> dict | None:
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
                  j.retry_count,
                  j.created_at,
                  j.started_at,
                  j.finished_at,
                  j.error,
                  j.claimed_by,
                  j.claim_token,
                  j.last_heartbeat_at,
                  j.job_params_json
                FROM scan_jobs j
                WHERE j.job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    out = dict(row)
    for key in ("created_at", "started_at", "finished_at", "last_heartbeat_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


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
    for k in ("created_at", "started_at", "finished_at", "last_heartbeat_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    if isinstance(out.get("job_params_json"), str):
        try:
            out["job_params_json"] = json.loads(out["job_params_json"])
        except json.JSONDecodeError:
            out["job_params_json"] = {}
    return out


def _dispatch_queued_job(
    *,
    job_id: int,
    job_type: str,
    target_asset_id: int | None,
    requested_by: str,
) -> None:
    if job_type == "repository_scan":
        launch_repository_scan_job(job_id)
    elif job_type == "threat_intel_refresh":
        launch_threat_intel_refresh_job(job_id)
    elif job_type == "telemetry_import":
        launch_telemetry_import_job(job_id)
    elif job_type == "network_anomaly_score":
        launch_network_anomaly_job(job_id)
    elif job_type == "attack_lab_run":
        launch_attack_lab_job(job_id)
    elif job_type == "attack_surface_discovery":
        launch_attack_surface_discovery_job(job_id)
    elif job_type == "detection_rule_test":
        launch_detection_rule_job(job_id)
    elif job_type == "detection_rule_schedule":
        launch_detection_rule_scheduled_job(job_id)
    elif job_type == "correlation_pass":
        launch_correlation_pass_job(job_id)
    elif job_type == "github_posture":
        launch_github_posture_job(job_id)
    elif job_type == "aws_iam_posture":
        launch_aws_iam_posture_job(job_id)
    else:
        publish_scan_job(job_id, job_type, target_asset_id, requested_by or "")


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
            text(  # nosemgrep
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
            text(  # nosemgrep
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
            text(  # nosemgrep
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
            text(  # nosemgrep
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


@router.post("/maintenance/recover-stale")
def recover_stale_jobs(
    payload: dict | None = Body(default=None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    """Requeue stale running jobs whose heartbeat has expired."""
    request = payload or {}
    running_stale_minutes = max(int(request.get("running_stale_minutes") or 30), 1)
    limit = max(min(int(request.get("limit") or 50), 200), 1)
    dry_run = bool(request.get("dry_run", False))
    stale_where = """
        status = 'running'
        AND (
          last_heartbeat_at IS NULL
          OR last_heartbeat_at <= NOW() - (:running_stale_minutes * INTERVAL '1 minute')
        )
    """
    select_sql = text(  # nosemgrep
        f"""
        SELECT
          job_id,
          job_type,
          target_asset_id,
          requested_by,
          status,
          retry_count,
          created_at,
          started_at,
          finished_at,
          error,
          claimed_by,
          claim_token,
          last_heartbeat_at,
          job_params_json
        FROM scan_jobs
        WHERE {stale_where}
        ORDER BY COALESCE(last_heartbeat_at, started_at, created_at) ASC
        LIMIT :limit
        """
    )
    stale_rows = [
        _serialize_job(row)
        for row in db.execute(
            select_sql,
            {
                "running_stale_minutes": running_stale_minutes,
                "limit": limit,
            },
        )
        .mappings()
        .all()
    ]
    if dry_run or not stale_rows:
        return {
            "ok": True,
            "dry_run": dry_run,
            "running_stale_minutes": running_stale_minutes,
            "recovered_count": 0 if dry_run else len(stale_rows),
            "jobs": stale_rows,
        }

    recovered_rows = [
        _serialize_job(row)
        for row in db.execute(
            text(  # nosemgrep
                f"""
                WITH stale AS (
                  SELECT job_id
                  FROM scan_jobs
                  WHERE {stale_where}
                  ORDER BY COALESCE(last_heartbeat_at, started_at, created_at) ASC
                  LIMIT :limit
                )
                UPDATE scan_jobs j
                SET status = 'queued',
                    started_at = NULL,
                    finished_at = NULL,
                    error = COALESCE(NULLIF(j.error, ''), 'recovered_stale_running_job'),
                    retry_count = j.retry_count + 1,
                    log_output = COALESCE(j.log_output, '') || :log_line || E'\\n',
                    claimed_by = NULL,
                    claim_token = NULL,
                    last_heartbeat_at = NULL
                FROM stale
                WHERE j.job_id = stale.job_id
                RETURNING
                  j.job_id,
                  j.job_type,
                  j.target_asset_id,
                  j.requested_by,
                  j.status,
                  j.retry_count,
                  j.created_at,
                  j.started_at,
                  j.finished_at,
                  j.error,
                  j.claimed_by,
                  j.claim_token,
                  j.last_heartbeat_at,
                  j.job_params_json
                """
            ),
            {
                "running_stale_minutes": running_stale_minutes,
                "limit": limit,
                "log_line": (
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"recovered stale running job via maintenance runbook by {user}"
                ),
            },
        )
        .mappings()
        .all()
    ]
    db.commit()
    for row in recovered_rows:
        _dispatch_queued_job(
            job_id=int(row["job_id"]),
            job_type=str(row["job_type"] or ""),
            target_asset_id=row.get("target_asset_id"),
            requested_by=str(row.get("requested_by") or ""),
        )
    log_audit(
        db,
        "job.recover_stale",
        user_name=user,
        details={
            "running_stale_minutes": running_stale_minutes,
            "recovered_count": len(recovered_rows),
            "job_ids": [int(row["job_id"]) for row in recovered_rows],
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {
        "ok": True,
        "dry_run": False,
        "running_stale_minutes": running_stale_minutes,
        "recovered_count": len(recovered_rows),
        "jobs": recovered_rows,
    }


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
            raise HTTPException(
                status_code=400, detail="lookback_minutes must be between 5 and 10080"
            )
        correlation_rule_id = job_params.get("correlation_rule_id")
        if correlation_rule_id is not None:
            try:
                numeric_rule_id = int(correlation_rule_id)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=400, detail="correlation_rule_id must be an integer"
                ) from exc
            if numeric_rule_id <= 0:
                raise HTTPException(status_code=400, detail="correlation_rule_id must be positive")
    elif job_type == "github_posture":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        scope_type = str(job_params.get("scope_type") or "user").strip().lower()
        if scope_type not in {"user", "org"}:
            raise HTTPException(status_code=400, detail="scope_type must be 'user' or 'org'")
        scope = str(job_params.get("scope") or "").strip()
        if scope_type == "org" and not scope:
            raise HTTPException(
                status_code=400, detail="scope (org name) is required for org scans"
            )
        max_repos = int(job_params.get("max_repos") or settings.GITHUB_MAX_REPOS)
        job_params = {
            "scope_type": scope_type,
            "scope": scope,
            "max_repos": max(1, min(max_repos, 500)),
        }
    elif job_type == "aws_iam_posture":
        if not isinstance(job_params, dict):
            raise HTTPException(status_code=400, detail="job_params_json must be an object")
        forbidden = {
            "access_key",
            "access_key_id",
            "aws_access_key_id",
            "secret_key",
            "secret_access_key",
            "aws_secret_access_key",
            "session_token",
            "aws_session_token",
        }
        if forbidden.intersection({str(k).strip().lower() for k in job_params}):
            raise HTTPException(
                status_code=400,
                detail="AWS credentials must be configured server-side, not passed in job params",
            )
        region = str(job_params.get("region") or "").strip()
        asset_key = str(job_params.get("asset_key") or "").strip()
        job_params = {}
        if region:
            job_params["region"] = region
        if asset_key:
            job_params["asset_key"] = asset_key

    q = text("""
      INSERT INTO scan_jobs(org_id, job_type, target_asset_id, requested_by, status, job_params_json)
      VALUES (:org_id, :t, :aid, :rb, 'queued', CAST(:job_params_json AS jsonb))
      RETURNING job_id, job_type, target_asset_id, status, created_at, job_params_json
    """)
    row = (
        db.execute(
            q,
            {
                "org_id": current_tenant_id(),
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
    elif job_type == "github_posture":
        launch_github_posture_job(int(out["job_id"]))
    elif job_type == "aws_iam_posture":
        launch_aws_iam_posture_job(int(out["job_id"]))
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
          UPDATE scan_jobs
          SET status = 'queued',
              error = NULL,
              log_output = NULL,
              started_at = NULL,
              finished_at = NULL,
              retry_count = retry_count + 1,
              claimed_by = NULL,
              claim_token = NULL,
              last_heartbeat_at = NULL
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
        _dispatch_queued_job(
            job_id=job_id,
            job_type=str(job_row["job_type"] or ""),
            target_asset_id=job_row["target_asset_id"],
            requested_by=str(job_row["requested_by"] or ""),
        )
    return {"ok": True, "status": "queued"}


@internal_router.post("/{job_id}/claim")
def claim_job(
    job_id: int,
    payload: dict | None = Body(default=None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    worker_user = _require_worker_executor(user)
    request = payload or {}
    worker_id = str(request.get("worker_id") or worker_user).strip() or worker_user
    claim_token = str(uuid4())
    timeout_seconds = _job_claim_timeout_seconds()
    claim_log = (
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] claimed by {worker_id}"
        f" timeout={timeout_seconds}s"
    )

    claimed_row = (
        db.execute(
            text(
                """
                UPDATE scan_jobs j
                SET status = 'running',
                    started_at = CASE
                      WHEN j.status = 'queued' OR j.started_at IS NULL THEN NOW()
                      ELSE j.started_at
                    END,
                    finished_at = NULL,
                    error = NULL,
                    retry_count = CASE WHEN j.status = 'running' THEN j.retry_count + 1 ELSE j.retry_count END,
                    claimed_by = :worker_id,
                    claim_token = :claim_token,
                    last_heartbeat_at = NOW(),
                    log_output = COALESCE(j.log_output, '') || :claim_log || E'\n'
                WHERE j.job_id = :job_id
                  AND j.job_type IN (
                    'web_exposure',
                    'score_recompute',
                    'repository_scan',
                    'threat_intel_refresh',
                    'telemetry_import',
                    'network_anomaly_score',
                    'attack_lab_run',
                    'attack_surface_discovery',
                    'detection_rule_test',
                    'detection_rule_schedule',
                    'correlation_pass',
                    'aws_iam_posture',
                    'github_posture'
                  )
                  AND (
                    j.status = 'queued'
                    OR (
                      j.status = 'running'
                      AND (
                        j.last_heartbeat_at IS NULL
                        OR j.last_heartbeat_at <= NOW() - (:timeout_seconds * INTERVAL '1 second')
                      )
                    )
                  )
                RETURNING
                  j.job_id,
                  j.job_type,
                  j.target_asset_id,
                  j.requested_by,
                  j.status,
                  j.retry_count,
                  j.claimed_by,
                  j.claim_token,
                  j.last_heartbeat_at,
                  j.job_params_json
                """
            ),
            {
                "job_id": job_id,
                "worker_id": worker_id,
                "claim_token": claim_token,
                "timeout_seconds": timeout_seconds,
                "claim_log": claim_log,
            },
        )
        .mappings()
        .first()
    )
    if claimed_row:
        db.commit()
        body = _serialize_job(claimed_row)
        body["claimed"] = True
        body["acknowledge"] = False
        return body

    state = _load_internal_job_state(db, job_id)
    if not state:
        raise HTTPException(status_code=404, detail="Job not found")
    state.pop("claim_token", None)
    state["claimed"] = False
    state["acknowledge"] = state.get("status") in {"done", "failed"}
    return state


@internal_router.post("/{job_id}/heartbeat")
def heartbeat_job(
    job_id: int,
    payload: dict | None = Body(default=None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    worker_user = _require_worker_executor(user)
    request = payload or {}
    claim_token = str(request.get("claim_token") or "").strip()
    if not claim_token:
        raise HTTPException(status_code=400, detail="claim_token required")
    worker_id = str(request.get("worker_id") or worker_user).strip() or worker_user
    log_line = str(request.get("log_line") or "").strip()

    updated = (
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET last_heartbeat_at = NOW(),
                    log_output = CASE
                      WHEN :log_line = '' THEN log_output
                      ELSE COALESCE(log_output, '') || :log_line || E'\n'
                    END
                WHERE job_id = :job_id
                  AND status = 'running'
                  AND claim_token = :claim_token
                  AND claimed_by = :worker_id
                RETURNING job_id, job_type, status, last_heartbeat_at
                """
            ),
            {
                "job_id": job_id,
                "claim_token": claim_token,
                "worker_id": worker_id,
                "log_line": log_line,
            },
        )
        .mappings()
        .first()
    )
    if updated:
        db.commit()
        body = _serialize_job(updated)
        body["acknowledge"] = False
        return body

    state = _load_internal_job_state(db, job_id)
    if not state:
        raise HTTPException(status_code=404, detail="Job not found")
    if state.get("status") in {"done", "failed"}:
        state.pop("claim_token", None)
        state["acknowledge"] = True
        return state
    raise HTTPException(status_code=409, detail="Job claim is no longer valid")


@internal_router.post("/{job_id}/complete")
def complete_job(
    job_id: int,
    payload: dict | None = Body(default=None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    worker_user = _require_worker_executor(user)
    request = payload or {}
    claim_token = str(request.get("claim_token") or "").strip()
    if not claim_token:
        raise HTTPException(status_code=400, detail="claim_token required")
    worker_id = str(request.get("worker_id") or worker_user).strip() or worker_user
    log_line = str(request.get("log_line") or "").strip()

    updated = (
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'done',
                    finished_at = NOW(),
                    error = NULL,
                    log_output = CASE
                      WHEN :log_line = '' THEN log_output
                      ELSE COALESCE(log_output, '') || :log_line || E'\n'
                    END,
                    claimed_by = NULL,
                    claim_token = NULL,
                    last_heartbeat_at = NULL
                WHERE job_id = :job_id
                  AND status IN ('queued', 'running', 'done')
                  AND claim_token = :claim_token
                  AND claimed_by = :worker_id
                RETURNING job_id, job_type, status, finished_at
                """
            ),
            {
                "job_id": job_id,
                "claim_token": claim_token,
                "worker_id": worker_id,
                "log_line": log_line,
            },
        )
        .mappings()
        .first()
    )
    if updated:
        db.commit()
        body = _serialize_job(updated)
        body["acknowledge"] = True
        return body

    state = _load_internal_job_state(db, job_id)
    if not state:
        raise HTTPException(status_code=404, detail="Job not found")
    state.pop("claim_token", None)
    if state.get("status") in {"done", "failed"}:
        state["acknowledge"] = True
        return state
    raise HTTPException(status_code=409, detail="Job claim is no longer valid")


@internal_router.post("/{job_id}/fail")
def fail_job(
    job_id: int,
    payload: dict | None = Body(default=None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    worker_user = _require_worker_executor(user)
    request = payload or {}
    claim_token = str(request.get("claim_token") or "").strip()
    if not claim_token:
        raise HTTPException(status_code=400, detail="claim_token required")
    worker_id = str(request.get("worker_id") or worker_user).strip() or worker_user
    error = str(request.get("error") or "worker_execution_failed").strip()
    retryable = bool(request.get("retryable"))
    log_line = str(request.get("log_line") or error).strip()

    state = _load_internal_job_state(db, job_id)
    if not state:
        raise HTTPException(status_code=404, detail="Job not found")
    if state.get("status") in {"done", "failed"}:
        state.pop("claim_token", None)
        state["acknowledge"] = True
        state["requeued"] = False
        state["existing_terminal"] = True
        return state
    if state.get("claim_token") != claim_token or state.get("claimed_by") != worker_id:
        raise HTTPException(status_code=409, detail="Job claim is no longer valid")

    if retryable:
        updated = (
            db.execute(
                text(
                    """
                    UPDATE scan_jobs
                    SET status = 'queued',
                        started_at = NULL,
                        finished_at = NULL,
                        error = :error,
                        retry_count = retry_count + 1,
                        log_output = COALESCE(log_output, '') || :log_line || E'\n',
                        claimed_by = NULL,
                        claim_token = NULL,
                        last_heartbeat_at = NULL
                    WHERE job_id = :job_id
                    RETURNING job_id, job_type, status, retry_count
                    """
                ),
                {
                    "job_id": job_id,
                    "error": error,
                    "log_line": log_line,
                },
            )
            .mappings()
            .first()
        )
        db.commit()
        body = _serialize_job(updated)
        body["acknowledge"] = False
        body["requeued"] = True
        body["existing_terminal"] = False
        return body

    updated = (
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    error = :error,
                    log_output = COALESCE(log_output, '') || :log_line || E'\n',
                    claimed_by = NULL,
                    claim_token = NULL,
                    last_heartbeat_at = NULL
                WHERE job_id = :job_id
                RETURNING job_id, job_type, status, finished_at, error
                """
            ),
            {
                "job_id": job_id,
                "error": error,
                "log_line": log_line,
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    body = _serialize_job(updated)
    body["acknowledge"] = True
    body["requeued"] = False
    body["existing_terminal"] = False
    return body


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
    _require_worker_executor(user)

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
        "web_exposure": _run_web_exposure_job,
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
        "aws_iam_posture": run_aws_iam_posture_job,
        "github_posture": run_github_posture_job,
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
    updated_status = str(updated.get("status") or "")
    if updated_status in {"done", "failed"}:
        _clear_job_claim(db, int(row["job_id"]))
        db.commit()

    return {
        "ok": True,
        "job_id": int(row["job_id"]),
        "job_type": job_type,
        "status": updated_status,
        "error": updated.get("error"),
        "finished_at": (
            updated.get("finished_at").isoformat()
            if hasattr(updated.get("finished_at"), "isoformat")
            else None
        ),
    }
