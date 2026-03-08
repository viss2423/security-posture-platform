"""Automation action execution helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .alert_enricher import (
    build_alert_enrichment,
    fetch_alert_related_events,
    get_security_alert_by_id,
)
from .notification_service import send_slack_notification


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


def _serialize_datetimes(payload: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    out = dict(payload)
    for key in keys:
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def _asset_context(db: Session, asset_key: str | None) -> dict[str, Any]:
    if not asset_key:
        return {}
    row = (
        db.execute(
            text(
                """
                SELECT asset_key, name, owner, environment, criticality, type, verified
                FROM assets
                WHERE asset_key = :asset_key
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not row:
        return {}
    return {
        "asset_key": row.get("asset_key"),
        "asset_name": row.get("name"),
        "owner": row.get("owner"),
        "environment": row.get("environment"),
        "criticality": row.get("criticality"),
        "asset_type": row.get("type"),
        "verified": row.get("verified"),
    }


def _action_enrich_alert(
    db: Session,
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    alert_id = int(params.get("alert_id") or trigger_payload.get("alert_id") or 0)
    if alert_id <= 0:
        raise ValueError("enrich_alert_missing_alert_id")
    alert_row = get_security_alert_by_id(db, alert_id)
    if not alert_row:
        raise ValueError("enrich_alert_alert_not_found")
    related_events = fetch_alert_related_events(
        db,
        alert_row=alert_row,
        lookback_hours=max(1, min(int(params.get("lookback_hours") or 24), 168)),
        limit=max(1, min(int(params.get("limit") or 25), 200)),
    )
    context = _asset_context(db, str(alert_row.get("asset_key") or "").strip() or None)
    enrichment = build_alert_enrichment(
        alert_row=alert_row,
        asset_context=context,
        related_events=related_events,
    )
    return (
        {
            "alert_id": alert_id,
            "effective_severity": enrichment.get("severity_analysis", {}).get("effective_severity"),
            "effective_score": enrichment.get("severity_analysis", {}).get("effective_score"),
            "related_events": len(related_events),
            "recommended_next_steps": enrichment.get("recommended_next_steps") or [],
        },
        None,
    )


def _create_incident_record(
    db: Session,
    *,
    title: str,
    severity: str,
    requested_by: str,
    asset_keys: list[str],
    alert_ids: list[int],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident = (
        db.execute(
            text(
                """
                INSERT INTO incidents (title, severity, status, assigned_to, updated_at, metadata)
                VALUES (:title, :severity, 'new', :assigned_to, NOW(), CAST(:metadata AS jsonb))
                RETURNING id, incident_key, title, severity, status, assigned_to, created_at, updated_at
                """
            ),
            {
                "title": title,
                "severity": severity,
                "assigned_to": None,
                "metadata": json.dumps(metadata or {}),
            },
        )
        .mappings()
        .first()
    )
    if not incident:
        raise ValueError("automation_create_incident_failed")
    incident_id = int(incident["id"])
    linked_asset_keys: set[str] = set()
    for asset_key in asset_keys:
        normalized = str(asset_key or "").strip()
        if not normalized:
            continue
        db.execute(
            text(
                """
                INSERT INTO incident_alerts (incident_id, asset_key, added_by)
                VALUES (:incident_id, :asset_key, :added_by)
                ON CONFLICT (incident_id, asset_key) DO NOTHING
                """
            ),
            {"incident_id": incident_id, "asset_key": normalized, "added_by": requested_by},
        )
        linked_asset_keys.add(normalized)
    for alert_id in alert_ids:
        row = (
            db.execute(
                text("SELECT alert_id, asset_key FROM security_alerts WHERE alert_id = :alert_id"),
                {"alert_id": int(alert_id)},
            )
            .mappings()
            .first()
        )
        if not row:
            continue
        resolved_asset_key = str(row.get("asset_key") or f"event:{int(alert_id)}")
        db.execute(
            text(
                """
                INSERT INTO incident_alerts (incident_id, asset_key, alert_id, added_by)
                VALUES (:incident_id, :asset_key, :alert_id, :added_by)
                ON CONFLICT (incident_id, asset_key) DO NOTHING
                """
            ),
            {
                "incident_id": incident_id,
                "asset_key": resolved_asset_key,
                "alert_id": int(alert_id),
                "added_by": requested_by,
            },
        )
        linked_asset_keys.add(resolved_asset_key)
    return {
        "incident_id": incident_id,
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "linked_asset_keys": sorted(linked_asset_keys),
    }


def _action_create_incident(
    db: Session,
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
    actor: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    severity = str(params.get("severity") or "high").strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "high"
    alert_ids: list[int] = []
    if isinstance(params.get("alert_ids"), list):
        alert_ids.extend(int(item) for item in params["alert_ids"] if str(item).isdigit())
    if str(params.get("alert_id") or "").isdigit():
        alert_ids.append(int(params["alert_id"]))
    if str(trigger_payload.get("alert_id") or "").isdigit():
        alert_ids.append(int(trigger_payload["alert_id"]))
    deduped_alert_ids = sorted(set(alert_ids))
    asset_keys: list[str] = []
    if isinstance(params.get("asset_keys"), list):
        asset_keys.extend(str(item) for item in params["asset_keys"])
    if params.get("asset_key"):
        asset_keys.append(str(params["asset_key"]))
    if trigger_payload.get("asset_key"):
        asset_keys.append(str(trigger_payload["asset_key"]))
    normalized_asset_keys = sorted(
        {str(item or "").strip() for item in asset_keys if str(item or "").strip()}
    )
    title = str(params.get("title") or "").strip()
    if not title:
        if normalized_asset_keys:
            title = f"Automation incident for {normalized_asset_keys[0]}"
        elif deduped_alert_ids:
            title = f"Automation incident from alert {deduped_alert_ids[0]}"
        else:
            title = "Automation incident"
    result = _create_incident_record(
        db,
        title=title,
        severity=severity,
        requested_by=actor,
        asset_keys=normalized_asset_keys,
        alert_ids=deduped_alert_ids,
        metadata={"automation": True, "trigger_payload": trigger_payload},
    )
    return result, None


def _action_notify_slack(
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    text_value = str(params.get("message") or "").strip()
    if not text_value:
        trigger = str(
            trigger_payload.get("trigger") or trigger_payload.get("event_type") or "automation"
        )
        text_value = f"SecPlat automation action executed for trigger '{trigger}'."
    result = send_slack_notification(text=text_value)
    return result, None


def _action_create_jira(
    db: Session,
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    from .routers.incidents import _jira_create_issue

    incident_id = int(params.get("incident_id") or trigger_payload.get("incident_id") or 0)
    project_key = str(params.get("project_key") or "").strip().upper()
    if incident_id <= 0:
        raise ValueError("create_jira_missing_incident_id")
    incident = (
        db.execute(
            text(
                """
                SELECT id, title, severity, status, metadata
                FROM incidents
                WHERE id = :incident_id
                """
            ),
            {"incident_id": incident_id},
        )
        .mappings()
        .first()
    )
    if not incident:
        raise ValueError("create_jira_incident_not_found")
    alerts = (
        db.execute(
            text("SELECT asset_key FROM incident_alerts WHERE incident_id = :incident_id"),
            {"incident_id": incident_id},
        )
        .mappings()
        .all()
    )
    incident_payload = dict(incident)
    incident_payload["alerts"] = [{"asset_key": row.get("asset_key")} for row in alerts]
    from .settings import settings

    frontend_url = (settings.FRONTEND_URL or "http://localhost:3000").rstrip("/")
    target_project = project_key or (settings.JIRA_PROJECT_KEY or "").strip().upper()
    if not target_project:
        raise ValueError("create_jira_missing_project_key")
    issue_key, browse_url = _jira_create_issue(incident_payload, target_project, frontend_url)
    metadata = _safe_json(incident_payload.get("metadata"), default={})
    metadata.update({"jira_issue_key": issue_key, "jira_issue_url": browse_url})
    db.execute(
        text(
            "UPDATE incidents SET metadata = CAST(:metadata AS jsonb), updated_at = NOW() WHERE id = :incident_id"
        ),
        {"metadata": json.dumps(metadata), "incident_id": incident_id},
    )
    return {"incident_id": incident_id, "issue_key": issue_key, "url": browse_url}, None


def _action_tag_asset(
    db: Session,
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    asset_key = str(params.get("asset_key") or trigger_payload.get("asset_key") or "").strip()
    tag = str(params.get("tag") or "under_investigation").strip()
    if not asset_key:
        raise ValueError("tag_asset_missing_asset_key")
    if not tag:
        raise ValueError("tag_asset_missing_tag")
    before = (
        db.execute(
            text("SELECT tags FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not before:
        raise ValueError("tag_asset_asset_not_found")
    previous_tags = list(before.get("tags") or [])
    row = (
        db.execute(
            text(
                """
                UPDATE assets
                SET tags = CASE
                  WHEN :tag = ANY(COALESCE(tags, ARRAY[]::text[])) THEN COALESCE(tags, ARRAY[]::text[])
                  ELSE array_append(COALESCE(tags, ARRAY[]::text[]), :tag)
                END
                WHERE asset_key = :asset_key
                RETURNING tags
                """
            ),
            {"asset_key": asset_key, "tag": tag},
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("tag_asset_update_failed")
    tags = list(row.get("tags") or [])
    rollback_payload = {
        "rollback_type": "asset_tags_restore",
        "payload": {
            "asset_key": asset_key,
            "previous_tags": previous_tags,
        },
    }
    return {"asset_key": asset_key, "tag": tag, "tags": tags}, rollback_payload


def _action_run_job(
    db: Session,
    *,
    params: dict[str, Any],
    actor: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    job_type = str(params.get("job_type") or "").strip()
    if not job_type:
        raise ValueError("run_job_missing_job_type")
    target_asset_id = params.get("target_asset_id")
    if target_asset_id is not None:
        try:
            target_asset_id = int(target_asset_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("run_job_invalid_target_asset_id") from exc
    job_params = params.get("job_params_json")
    if not isinstance(job_params, dict):
        job_params = {}
    row = (
        db.execute(
            text(
                """
                INSERT INTO scan_jobs(job_type, target_asset_id, requested_by, status, job_params_json)
                VALUES (:job_type, :target_asset_id, :requested_by, 'queued', CAST(:job_params_json AS jsonb))
                RETURNING job_id, job_type, target_asset_id, requested_by, status, created_at, job_params_json
                """
            ),
            {
                "job_type": job_type,
                "target_asset_id": target_asset_id,
                "requested_by": actor,
                "job_params_json": json.dumps(job_params),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("run_job_insert_failed")
    return _serialize_datetimes(dict(row), ["created_at"]), None


def _action_suppress_duplicates(
    db: Session,
    *,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    dedupe_key = (
        str(params.get("dedupe_key") or trigger_payload.get("dedupe_key") or "").strip().lower()
    )
    if not dedupe_key:
        raise ValueError("suppress_duplicates_missing_dedupe_key")
    minutes = max(5, min(int(params.get("minutes") or 60), 60 * 24))
    until = datetime.now(UTC) + timedelta(minutes=minutes)
    rows = (
        db.execute(
            text(
                """
                SELECT alert_id, status, suppressed_until
                FROM security_alerts
                WHERE dedupe_key = :dedupe_key
                  AND status IN ('firing', 'acked', 'suppressed')
                """
            ),
            {"dedupe_key": dedupe_key},
        )
        .mappings()
        .all()
    )
    if not rows:
        return {"dedupe_key": dedupe_key, "suppressed": 0}, None
    db.execute(
        text(
            """
            UPDATE security_alerts
            SET
              status = 'suppressed',
              suppressed_until = :until,
              suppression_reason = COALESCE(suppression_reason, 'automation_playbook'),
              updated_at = NOW()
            WHERE dedupe_key = :dedupe_key
              AND status IN ('firing', 'acked', 'suppressed')
            """
        ),
        {"dedupe_key": dedupe_key, "until": until},
    )
    rollback_payload = {
        "rollback_type": "suppress_duplicates_restore",
        "payload": {
            "alerts": [
                {
                    "alert_id": int(row.get("alert_id") or 0),
                    "status": row.get("status"),
                    "suppressed_until": (
                        row.get("suppressed_until").isoformat()
                        if hasattr(row.get("suppressed_until"), "isoformat")
                        else row.get("suppressed_until")
                    ),
                }
                for row in rows
                if int(row.get("alert_id") or 0) > 0
            ]
        },
    }
    return {
        "dedupe_key": dedupe_key,
        "suppressed": len(rows),
        "until": until.isoformat(),
    }, rollback_payload


def _execute_action_handler(
    db: Session,
    *,
    action_type: str,
    params: dict[str, Any],
    trigger_payload: dict[str, Any],
    actor: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    normalized = str(action_type or "").strip().lower()
    if normalized == "enrich_alert":
        return _action_enrich_alert(db, params=params, trigger_payload=trigger_payload)
    if normalized == "create_incident":
        return _action_create_incident(
            db, params=params, trigger_payload=trigger_payload, actor=actor
        )
    if normalized == "notify_slack":
        return _action_notify_slack(params=params, trigger_payload=trigger_payload)
    if normalized == "create_jira":
        return _action_create_jira(db, params=params, trigger_payload=trigger_payload)
    if normalized == "tag_asset":
        return _action_tag_asset(db, params=params, trigger_payload=trigger_payload)
    if normalized == "run_job":
        return _action_run_job(db, params=params, actor=actor)
    if normalized == "suppress_duplicates":
        return _action_suppress_duplicates(db, params=params, trigger_payload=trigger_payload)
    raise ValueError(f"unsupported_action_type:{normalized}")


def execute_run_action(
    db: Session,
    *,
    run_action_id: int,
    actor: str,
    trigger_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    action_row = (
        db.execute(
            text(
                """
                SELECT
                  run_action_id,
                  run_id,
                  action_type,
                  status,
                  params_json
                FROM automation_run_actions
                WHERE run_action_id = :run_action_id
                """
            ),
            {"run_action_id": int(run_action_id)},
        )
        .mappings()
        .first()
    )
    if not action_row:
        raise ValueError("automation_run_action_not_found")
    current_status = str(action_row.get("status") or "").strip().lower()
    if current_status in {"done", "rolled_back"}:
        return {
            "run_action_id": int(action_row["run_action_id"]),
            "status": current_status,
            "skipped": True,
        }

    params = _safe_json(action_row.get("params_json"), default={})
    effective_trigger_payload = dict(trigger_payload or {})
    if not effective_trigger_payload:
        run_row = (
            db.execute(
                text("SELECT trigger_payload_json FROM automation_runs WHERE run_id = :run_id"),
                {"run_id": int(action_row["run_id"])},
            )
            .mappings()
            .first()
        )
        effective_trigger_payload = _safe_json(
            (run_row or {}).get("trigger_payload_json"),
            default={},
        )

    db.execute(
        text(
            """
            UPDATE automation_run_actions
            SET status = 'running', started_at = NOW(), error = NULL
            WHERE run_action_id = :run_action_id
            """
        ),
        {"run_action_id": int(run_action_id)},
    )
    try:
        result, rollback_payload = _execute_action_handler(
            db,
            action_type=str(action_row.get("action_type") or ""),
            params=params,
            trigger_payload=effective_trigger_payload,
            actor=actor,
        )
        db.execute(
            text(
                """
                UPDATE automation_run_actions
                SET
                  status = 'done',
                  result_json = CAST(:result_json AS jsonb),
                  finished_at = NOW(),
                  error = NULL
                WHERE run_action_id = :run_action_id
                """
            ),
            {
                "run_action_id": int(run_action_id),
                "result_json": json.dumps(result or {}),
            },
        )
        if rollback_payload:
            db.execute(
                text(
                    """
                    INSERT INTO automation_rollbacks (
                      run_action_id,
                      rollback_type,
                      rollback_payload_json,
                      status,
                      requested_by
                    )
                    VALUES (
                      :run_action_id,
                      :rollback_type,
                      CAST(:rollback_payload_json AS jsonb),
                      'pending',
                      :requested_by
                    )
                    ON CONFLICT (run_action_id) DO UPDATE
                    SET
                      rollback_type = EXCLUDED.rollback_type,
                      rollback_payload_json = EXCLUDED.rollback_payload_json,
                      status = 'pending',
                      requested_by = EXCLUDED.requested_by,
                      executed_by = NULL,
                      executed_at = NULL,
                      error = NULL
                    """
                ),
                {
                    "run_action_id": int(run_action_id),
                    "rollback_type": str(rollback_payload.get("rollback_type") or "").strip(),
                    "rollback_payload_json": json.dumps(rollback_payload.get("payload") or {}),
                    "requested_by": actor,
                },
            )
        return {
            "run_action_id": int(run_action_id),
            "status": "done",
            "result": result,
            "rollback_created": bool(rollback_payload),
        }
    except Exception as exc:
        db.execute(
            text(
                """
                UPDATE automation_run_actions
                SET status = 'failed', error = :error, finished_at = NOW()
                WHERE run_action_id = :run_action_id
                """
            ),
            {"run_action_id": int(run_action_id), "error": str(exc)},
        )
        return {
            "run_action_id": int(run_action_id),
            "status": "failed",
            "error": str(exc),
        }


def update_run_status(db: Session, *, run_id: int) -> str:
    rows = (
        db.execute(
            text(
                """
                SELECT status
                FROM automation_run_actions
                WHERE run_id = :run_id
                """
            ),
            {"run_id": int(run_id)},
        )
        .mappings()
        .all()
    )
    statuses = {str(row.get("status") or "").strip().lower() for row in rows}
    if not statuses:
        run_status = "done"
    elif "failed" in statuses:
        run_status = "failed"
    elif "pending_approval" in statuses:
        run_status = "pending_approval"
    elif statuses.issubset({"done", "rolled_back"}):
        run_status = "done"
    elif "rejected" in statuses and statuses.issubset({"rejected"}):
        run_status = "rejected"
    else:
        run_status = "running"
    db.execute(
        text(
            """
            UPDATE automation_runs
            SET
              status = :status,
              finished_at = CASE
                WHEN :status IN ('done', 'failed', 'rejected') THEN NOW()
                ELSE finished_at
              END
            WHERE run_id = :run_id
            """
        ),
        {"run_id": int(run_id), "status": run_status},
    )
    return run_status


__all__ = ["execute_run_action", "update_run_status"]
