"""Interval scan-trigger engine.

Finds connectors whose ``next_scan_at <= now()`` and whose ``schedule != 'off'``,
creates scan jobs and enqueues them via the existing per-provider launch functions.
Respects per-workspace credential isolation and is idempotent (no double-queue if a
scan is already running on the same connector).

Design
------

The engine runs in the API process as a background asyncio loop (wired into
``main.py``'s lifespan) so it inherits the same DB role and Redis connectivity the
rest of the API already has.  It binds each workspace tenant in turn via
``tenant_id_ctx``, making every ``user_credentials`` read and ``scan_jobs`` write
RLS-scoped to the owning workspace.  The existing ``launch_*_posture_job`` functions
handle Redis publishing; the existing ``run_*_posture_job`` runners already call
``record_scan_started`` / ``record_scan_finished``, which advance ``last_scanned_at``
and ``next_scan_at``.

Idempotency
-----------

Before enqueuing we check for a ``scan_jobs`` row with the same ``credential_id``
that is still ``queued`` or ``running``.  This is scoped to the workspace tenant, so a
running scan in workspace-A never blocks a scheduled scan in workspace-B even if both
happen to share the same credential_id value (which they can't because of the
(org_id, credential_id) PK, but the guard is still correct).
"""

from __future__ import annotations

import json
import logging

from sqlalchemy import text

from .aws_iam_connector import launch_aws_iam_posture_job
from .db import SessionLocal
from .github_connector import launch_github_posture_job
from .request_context import tenant_id_ctx

logger = logging.getLogger("secplat.scheduled_scans")


def trigger_scheduled_scans() -> int:
    """Find due connectors across all workspaces and enqueue scans.

    Returns the number of scan jobs that were enqueued this cycle.
    A return of 0 means no connector was due (or every due connector already
    has a scan queued/running).
    """
    db = SessionLocal()
    enqueued = 0
    try:
        # Discover workspaces that have at least one scheduled connector.
        # The ``users`` table is NOT RLS-protected (auth is cross-tenant), so
        # this query sees every self-serve workspace without needing SECURITY
        # DEFINER.  We bind each in turn, which means a workspace that has
        # been deactivated (no user rows) is harmlessly skipped.
        workspaces = (
            db.execute(
                text(
                    "SELECT DISTINCT workspace_id FROM users "
                    "WHERE workspace_id IS NOT NULL "
                    "  AND workspace_id <> '' "
                    "ORDER BY workspace_id"
                )
            )
            .mappings()
            .all()
        )

        for ws in workspaces:
            tenant = str(ws["workspace_id"] or "").strip()
            if not tenant:
                continue

            token = tenant_id_ctx.set(tenant)
            try:
                # Now scoped to this workspace, list connectors whose schedule
                # says they're due.  RLS on user_credentials ensures we only
                # see rows belonging to *this* workspace.
                due = (
                    db.execute(
                        text(
                            """
                            SELECT credential_id, provider, scope_type, scope
                            FROM user_credentials
                            WHERE schedule IS NOT NULL
                              AND schedule != 'off'
                              AND next_scan_at IS NOT NULL
                              AND next_scan_at <= NOW()
                            ORDER BY next_scan_at
                            """
                        )
                    )
                    .mappings()
                    .all()
                )

                for connector in due:
                    credential_id = int(connector["credential_id"])
                    provider = str(connector.get("provider") or "").strip().lower()

                    # Idempotency: skip if a scan is already queued or running
                    # for this connector within this workspace.
                    already_running = db.execute(
                        text(
                            """
                            SELECT 1 FROM scan_jobs
                            WHERE job_params_json->>'credential_id' = :cid
                              AND status IN ('queued', 'running')
                            LIMIT 1
                            """
                        ),
                        {"cid": str(credential_id)},
                    ).first()
                    if already_running:
                        continue

                    # ── Build job params (mirrors /workspace/scans) ──────
                    if provider == "github":
                        job_type = "github_posture"
                        scope_type = str(connector.get("scope_type") or "user").strip().lower()
                        scope = str(connector.get("scope") or "").strip()
                        job_params = {
                            "credential_id": credential_id,
                            "scope_type": scope_type,
                            "scope": scope,
                            "max_repos": 100,
                            "triggered_by": "scheduled",
                        }
                    elif provider == "aws":
                        job_type = "aws_iam_posture"
                        region = str(connector.get("scope") or "us-east-1").strip().lower()
                        job_params = {
                            "credential_id": credential_id,
                            "region": region,
                            "triggered_by": "scheduled",
                        }
                    else:
                        logger.warning(
                            "scheduled_scan_unknown_provider credential_id=%s provider=%s",
                            credential_id,
                            provider,
                        )
                        continue

                    # ── Create the scan_job row ──────────────────────────
                    row = (
                        db.execute(
                            text(
                                """
                                INSERT INTO scan_jobs
                                  (org_id, job_type, requested_by, status, job_params_json)
                                VALUES
                                  (:org_id, :job_type, 'scheduled', 'queued',
                                   CAST(:params AS jsonb))
                                RETURNING job_id
                                """
                            ),
                            {
                                "org_id": tenant,
                                "job_type": job_type,
                                "params": json.dumps(job_params),
                            },
                        )
                        .mappings()
                        .first()
                    )
                    job_id = int(row["job_id"])
                    db.commit()

                    logger.info(
                        "scheduled_scan_enqueued job_id=%s provider=%s tenant=%s",
                        job_id,
                        provider,
                        tenant,
                    )

                    # ── Publish to Redis for the worker ──────────────────
                    if provider == "github":
                        launch_github_posture_job(job_id)
                    else:
                        launch_aws_iam_posture_job(job_id)

                    enqueued += 1

            finally:
                tenant_id_ctx.reset(token)
    finally:
        db.close()

    if enqueued:
        logger.info("scheduled_scan_cycle_done enqueued=%d", enqueued)
    return enqueued
