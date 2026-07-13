"""Workspace posture scan history helpers.

These helpers run inside the same tenant-bound DB session as the connector runner. That keeps
history rows, connector timestamps, and credential access under the existing RLS context.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text

logger = logging.getLogger("secplat.scan_history")

SCHEDULES = {"off", "hourly", "daily", "weekly"}
TRIGGERED_BY = {"manual", "scheduled"}


def normalize_schedule(value: str | None) -> str | None:
    if value is None:
        return None
    schedule = str(value).strip().lower()
    if not schedule:
        return None
    if schedule not in SCHEDULES:
        raise ValueError("schedule must be one of: off, hourly, daily, weekly")
    return schedule


def normalize_triggered_by(value: Any) -> str:
    triggered_by = str(value or "manual").strip().lower()
    return triggered_by if triggered_by in TRIGGERED_BY else "manual"


def record_scan_started(
    db,
    *,
    job_id: int,
    provider: str,
    connector_id: int | None,
    triggered_by: str,
) -> None:
    try:
        db.execute(
            text(
                """
                INSERT INTO scan_history
                  (workspace_id, connector, provider, job_id, started_at, status, triggered_by)
                SELECT
                  org_id,
                  :connector,
                  :provider,
                  job_id,
                  COALESCE(started_at, NOW()),
                  'running',
                  :triggered_by
                FROM scan_jobs
                WHERE job_id = :job_id
                ON CONFLICT (job_id) WHERE job_id IS NOT NULL DO UPDATE
                  SET started_at = EXCLUDED.started_at,
                      finished_at = NULL,
                      status = 'running',
                      findings_count = NULL,
                      triggered_by = EXCLUDED.triggered_by
                """
            ),
            {
                "job_id": int(job_id),
                "connector": str(connector_id) if connector_id is not None else None,
                "provider": provider,
                "triggered_by": normalize_triggered_by(triggered_by),
            },
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001 - history must not abort the scan
        db.rollback()
        logger.warning("scan_history_start_failed job_id=%s error=%s", job_id, exc)


def record_scan_finished(
    db,
    *,
    job_id: int,
    connector_id: int | None,
    ok: bool,
    findings_count: int | None,
) -> None:
    try:
        status = "done" if ok else "failed"
        db.execute(
            text(
                """
                UPDATE scan_history
                   SET finished_at = NOW(),
                       status = :status,
                       findings_count = :findings_count
                 WHERE job_id = :job_id
                """
            ),
            {"job_id": int(job_id), "status": status, "findings_count": findings_count},
        )
        if connector_id is not None:
            db.execute(
                text(
                    """
                    UPDATE user_credentials
                       SET last_used_at = NOW(),
                           last_scanned_at = NOW(),
                           next_scan_at = CASE schedule
                             WHEN 'hourly' THEN NOW() + INTERVAL '1 hour'
                             WHEN 'daily' THEN NOW() + INTERVAL '1 day'
                             WHEN 'weekly' THEN NOW() + INTERVAL '1 week'
                             ELSE NULL
                           END
                     WHERE credential_id = :credential_id
                    """
                ),
                {"credential_id": int(connector_id)},
            )
        db.commit()
    except Exception as exc:  # noqa: BLE001 - history must not abort the scan
        db.rollback()
        logger.warning("scan_history_finish_failed job_id=%s error=%s", job_id, exc)
