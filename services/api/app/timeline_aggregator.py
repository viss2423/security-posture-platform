"""Unified incident timeline aggregation across investigation signals."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


def _coerce_json_value(value: Any, *, default: Any) -> Any:
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


def _as_iso(value: Any) -> str | None:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if value is None:
        return None
    return str(value)


def _incident_asset_keys(db: Session, incident_id: int) -> list[str]:
    rows = (
        db.execute(
            text(
                """
                SELECT DISTINCT asset_key
                FROM incident_alerts
                WHERE incident_id = :incident_id
                  AND asset_key IS NOT NULL
                  AND asset_key <> ''
                ORDER BY asset_key ASC
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )
    return [str(row.get("asset_key") or "").strip() for row in rows if row.get("asset_key")]


def build_incident_timeline(
    db: Session,
    *,
    incident_id: int,
    lookback_hours: int = 48,
    source_limit: int = 120,
    source_types: set[str] | None = None,
    event_types: set[str] | None = None,
    limit_total: int | None = None,
) -> list[dict[str, Any]]:
    """Return a stable, source-attributed timeline for an incident."""
    normalized_limit = max(20, min(int(source_limit), 500))
    lookback = max(1, min(int(lookback_hours), 720))
    since = datetime.now(UTC) - timedelta(hours=lookback)

    notes = (
        db.execute(
            text(
                """
                SELECT id, incident_id, event_type, author, body, details, created_at
                FROM incident_notes
                WHERE incident_id = :incident_id
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )
    checklist = (
        db.execute(
            text(
                """
                SELECT item_id, incident_id, title, done, done_by, done_at, created_by, created_at, updated_at
                FROM incident_checklist_items
                WHERE incident_id = :incident_id
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )
    decisions = (
        db.execute(
            text(
                """
                SELECT decision_id, incident_id, decision, rationale, decided_by, details, created_at
                FROM incident_decisions
                WHERE incident_id = :incident_id
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )
    evidence = (
        db.execute(
            text(
                """
                SELECT evidence_id, incident_id, evidence_type, ref_id, relation, summary, details, added_by, created_at
                FROM incident_evidence
                WHERE incident_id = :incident_id
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )

    asset_keys = _incident_asset_keys(db, int(incident_id))
    alerts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    telemetry_events: list[dict[str, Any]] = []
    asset_jobs: list[dict[str, Any]] = []
    if asset_keys:
        alerts = [
            dict(row)
            for row in (
                db.execute(
                    text(
                        """
                        SELECT
                          sa.alert_id,
                          sa.asset_key,
                          sa.source,
                          sa.title,
                          sa.severity,
                          sa.status,
                          sa.event_count,
                          sa.first_seen_at,
                          sa.last_seen_at
                        FROM security_alerts sa
                        WHERE sa.asset_key = ANY(CAST(:asset_keys AS text[]))
                          AND COALESCE(sa.last_seen_at, sa.first_seen_at, sa.created_at) >= :since
                        ORDER BY COALESCE(sa.last_seen_at, sa.first_seen_at, sa.created_at) DESC
                        LIMIT :limit
                        """
                    ),
                    {"asset_keys": asset_keys, "since": since, "limit": normalized_limit},
                )
                .mappings()
                .all()
            )
        ]
        findings = [
            dict(row)
            for row in (
                db.execute(
                    text(
                        """
                        SELECT
                          f.finding_id,
                          a.asset_key,
                          f.title,
                          f.severity,
                          f.source,
                          COALESCE(f.status, 'open') AS status,
                          COALESCE(f.last_seen, f.time, f.first_seen) AS observed_at
                        FROM findings f
                        JOIN assets a ON a.asset_id = f.asset_id
                        WHERE a.asset_key = ANY(CAST(:asset_keys AS text[]))
                        ORDER BY COALESCE(f.last_seen, f.time, f.first_seen) DESC NULLS LAST
                        LIMIT :limit
                        """
                    ),
                    {"asset_keys": asset_keys, "limit": normalized_limit},
                )
                .mappings()
                .all()
            )
        ]
        telemetry_events = [
            dict(row)
            for row in (
                db.execute(
                    text(
                        """
                        SELECT
                          event_id,
                          asset_key,
                          source,
                          event_type,
                          severity,
                          event_time,
                          src_ip,
                          domain,
                          COALESCE(payload_json ->> 'process', payload_json ->> 'process_name') AS process_name,
                          collector
                        FROM security_events
                        WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                          AND event_time >= :since
                        ORDER BY event_time DESC
                        LIMIT :limit
                        """
                    ),
                    {"asset_keys": asset_keys, "since": since, "limit": normalized_limit},
                )
                .mappings()
                .all()
            )
        ]
        asset_jobs = [
            dict(row)
            for row in (
                db.execute(
                    text(
                        """
                        SELECT
                          sj.job_id,
                          sj.job_type,
                          sj.status,
                          sj.requested_by,
                          sj.error,
                          COALESCE(sj.finished_at, sj.started_at, sj.created_at) AS observed_at
                        FROM scan_jobs sj
                        JOIN assets a ON a.asset_id = sj.target_asset_id
                        WHERE a.asset_key = ANY(CAST(:asset_keys AS text[]))
                          AND COALESCE(sj.finished_at, sj.started_at, sj.created_at) >= :since
                        ORDER BY COALESCE(sj.finished_at, sj.started_at, sj.created_at) DESC
                        LIMIT :limit
                        """
                    ),
                    {"asset_keys": asset_keys, "since": since, "limit": normalized_limit},
                )
                .mappings()
                .all()
            )
        ]

    incident_alerts = [
        dict(row)
        for row in (
            db.execute(
                text(
                    """
                    SELECT
                      ia.alert_id,
                      ia.asset_key,
                      sa.source,
                      sa.title,
                      sa.severity,
                      sa.status,
                      sa.event_count,
                      sa.first_seen_at,
                      sa.last_seen_at
                    FROM incident_alerts ia
                    JOIN security_alerts sa ON sa.alert_id = ia.alert_id
                    WHERE ia.incident_id = :incident_id
                    ORDER BY COALESCE(sa.last_seen_at, sa.first_seen_at, sa.created_at) DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id": int(incident_id), "limit": normalized_limit},
            )
            .mappings()
            .all()
        )
    ]

    incident_job_evidence = [
        dict(row)
        for row in (
            db.execute(
                text(
                    """
                    SELECT
                      ie.evidence_id,
                      ie.ref_id,
                      ie.summary,
                      ie.details,
                      ie.added_by,
                      ie.created_at,
                      sj.job_id,
                      sj.job_type,
                      sj.status,
                      sj.requested_by,
                      sj.error,
                      COALESCE(sj.finished_at, sj.started_at, sj.created_at) AS observed_at
                    FROM incident_evidence ie
                    LEFT JOIN scan_jobs sj
                      ON ie.evidence_type = 'job'
                     AND ie.ref_id ~ '^[0-9]+$'
                     AND sj.job_id = CAST(ie.ref_id AS INTEGER)
                    WHERE ie.incident_id = :incident_id
                      AND ie.evidence_type = 'job'
                    ORDER BY ie.created_at DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id": int(incident_id), "limit": normalized_limit},
            )
            .mappings()
            .all()
        )
    ]

    incident_id_text = str(int(incident_id))
    automation_actions = [
        dict(row)
        for row in (
            db.execute(
                text(
                    """
                    SELECT
                      ara.run_action_id,
                      ara.action_type,
                      ara.risk_tier,
                      ara.status,
                      ara.error,
                      ara.params_json,
                      ara.result_json,
                      ara.created_at,
                      ara.started_at,
                      ara.finished_at,
                      ar.run_id,
                      ar.playbook_id,
                      ar.trigger_source,
                      ar.requested_by
                    FROM automation_run_actions ara
                    JOIN automation_runs ar ON ar.run_id = ara.run_id
                    WHERE (ar.trigger_payload_json ->> 'incident_id') = :incident_id_text
                       OR (ara.result_json ->> 'incident_id') = :incident_id_text
                    ORDER BY COALESCE(ara.finished_at, ara.started_at, ara.created_at) DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id_text": incident_id_text, "limit": normalized_limit},
            )
            .mappings()
            .all()
        )
    ]

    rollback_actions = [
        dict(row)
        for row in (
            db.execute(
                text(
                    """
                    SELECT
                      rb.rollback_id,
                      rb.rollback_type,
                      rb.status,
                      rb.requested_by,
                      rb.executed_by,
                      rb.error,
                      rb.created_at,
                      rb.executed_at,
                      ara.run_action_id,
                      ara.action_type,
                      ar.run_id
                    FROM automation_rollbacks rb
                    JOIN automation_run_actions ara ON ara.run_action_id = rb.run_action_id
                    JOIN automation_runs ar ON ar.run_id = ara.run_id
                    WHERE (ar.trigger_payload_json ->> 'incident_id') = :incident_id_text
                       OR (ara.result_json ->> 'incident_id') = :incident_id_text
                    ORDER BY COALESCE(rb.executed_at, rb.created_at) DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id_text": incident_id_text, "limit": normalized_limit},
            )
            .mappings()
            .all()
        )
    ]

    events: list[dict[str, Any]] = []
    for row in notes:
        details = _coerce_json_value(row.get("details"), default={})
        events.append(
            {
                "id": int(row.get("id") or 0),
                "incident_id": int(incident_id),
                "event_type": str(row.get("event_type") or "note"),
                "author": row.get("author"),
                "body": row.get("body"),
                "details": details,
                "created_at": _as_iso(row.get("created_at")),
                "source_type": "note",
                "source_id": f"note:{int(row.get('id') or 0)}",
            }
        )
    for row in checklist:
        created_at = row.get("done_at") or row.get("created_at")
        events.append(
            {
                "id": f"checklist:{int(row.get('item_id') or 0)}",
                "incident_id": int(incident_id),
                "event_type": "checklist_done" if bool(row.get("done")) else "checklist_added",
                "author": row.get("done_by") or row.get("created_by"),
                "body": row.get("title"),
                "details": {
                    "item_id": int(row.get("item_id") or 0),
                    "title": row.get("title"),
                    "done": bool(row.get("done")),
                    "done_by": row.get("done_by"),
                    "done_at": _as_iso(row.get("done_at")),
                    "created_by": row.get("created_by"),
                    "created_at": _as_iso(row.get("created_at")),
                    "updated_at": _as_iso(row.get("updated_at")),
                },
                "created_at": _as_iso(created_at),
                "source_type": "checklist",
                "source_id": f"checklist:{int(row.get('item_id') or 0)}",
            }
        )
    for row in decisions:
        details = _coerce_json_value(row.get("details"), default={})
        events.append(
            {
                "id": f"decision:{int(row.get('decision_id') or 0)}",
                "incident_id": int(incident_id),
                "event_type": "decision",
                "author": row.get("decided_by"),
                "body": row.get("decision"),
                "details": {
                    "decision_id": int(row.get("decision_id") or 0),
                    "decision": row.get("decision"),
                    "rationale": row.get("rationale"),
                    "details": details,
                },
                "created_at": _as_iso(row.get("created_at")),
                "source_type": "decision",
                "source_id": f"decision:{int(row.get('decision_id') or 0)}",
            }
        )
    for row in evidence:
        details = _coerce_json_value(row.get("details"), default={})
        evidence_id = int(row.get("evidence_id") or 0)
        evidence_type = str(row.get("evidence_type") or "other")
        ref_id = str(row.get("ref_id") or "")
        body = row.get("summary") or f"Evidence {evidence_type}:{ref_id}"
        events.append(
            {
                "id": f"evidence:{evidence_id}",
                "incident_id": int(incident_id),
                "event_type": "evidence_linked",
                "author": row.get("added_by"),
                "body": body,
                "details": {
                    "evidence_id": evidence_id,
                    "evidence_type": evidence_type,
                    "ref_id": ref_id,
                    "relation": row.get("relation"),
                    "summary": row.get("summary"),
                    "details": details,
                },
                "created_at": _as_iso(row.get("created_at")),
                "source_type": "evidence",
                "source_id": f"evidence:{evidence_id}",
            }
        )

    combined_alert_rows: dict[int, dict[str, Any]] = {}
    for row in alerts + incident_alerts:
        alert_id = int(row.get("alert_id") or 0)
        if alert_id <= 0:
            continue
        existing = combined_alert_rows.get(alert_id)
        if existing is None:
            combined_alert_rows[alert_id] = row
            continue
        current_seen = existing.get("last_seen_at") or existing.get("first_seen_at")
        candidate_seen = row.get("last_seen_at") or row.get("first_seen_at")
        if str(candidate_seen or "") > str(current_seen or ""):
            combined_alert_rows[alert_id] = row
    for row in combined_alert_rows.values():
        alert_id = int(row.get("alert_id") or 0)
        observed = row.get("last_seen_at") or row.get("first_seen_at")
        asset_key = str(row.get("asset_key") or "")
        events.append(
            {
                "id": f"alert:{alert_id}",
                "incident_id": int(incident_id),
                "event_type": "alert_activity",
                "author": "system",
                "body": row.get("title") or f"Security alert {alert_id}",
                "details": {
                    "alert_id": alert_id,
                    "asset_key": asset_key,
                    "severity": row.get("severity"),
                    "status": row.get("status"),
                    "source": row.get("source"),
                    "event_count": int(row.get("event_count") or 0),
                },
                "created_at": _as_iso(observed),
                "source_type": "alert",
                "source_id": f"security_alert:{alert_id}",
            }
        )
    for row in findings:
        finding_id = int(row.get("finding_id") or 0)
        events.append(
            {
                "id": f"finding:{finding_id}",
                "incident_id": int(incident_id),
                "event_type": "finding_activity",
                "author": "system",
                "body": row.get("title") or f"Finding {finding_id}",
                "details": {
                    "finding_id": finding_id,
                    "asset_key": row.get("asset_key"),
                    "severity": row.get("severity"),
                    "status": row.get("status"),
                    "source": row.get("source"),
                },
                "created_at": _as_iso(row.get("observed_at")),
                "source_type": "finding",
                "source_id": f"finding:{finding_id}",
            }
        )
    for row in telemetry_events:
        event_id = int(row.get("event_id") or 0)
        source = str(row.get("source") or "telemetry")
        event_type = str(row.get("event_type") or "")
        events.append(
            {
                "id": f"log:{event_id}",
                "incident_id": int(incident_id),
                "event_type": "telemetry_event",
                "author": "collector",
                "body": f"{source}:{event_type}".strip(":"),
                "details": {
                    "event_id": event_id,
                    "asset_key": row.get("asset_key"),
                    "source": source,
                    "event_type": event_type,
                    "severity": row.get("severity"),
                    "src_ip": row.get("src_ip"),
                    "domain": row.get("domain"),
                    "process": row.get("process_name"),
                    "collector": row.get("collector"),
                },
                "created_at": _as_iso(row.get("event_time")),
                "source_type": "log",
                "source_id": f"security_event:{event_id}",
            }
        )
    for row in asset_jobs:
        job_id = int(row.get("job_id") or 0)
        events.append(
            {
                "id": f"job:{job_id}",
                "incident_id": int(incident_id),
                "event_type": "job_activity",
                "author": row.get("requested_by") or "system",
                "body": f"Job {row.get('job_type') or 'job'} {row.get('status') or 'queued'}",
                "details": {
                    "job_id": job_id,
                    "job_type": row.get("job_type"),
                    "status": row.get("status"),
                    "error": row.get("error"),
                },
                "created_at": _as_iso(row.get("observed_at")),
                "source_type": "job",
                "source_id": f"scan_job:{job_id}",
            }
        )
    for row in incident_job_evidence:
        evidence_id = int(row.get("evidence_id") or 0)
        job_id = int(row.get("job_id") or 0)
        details = _coerce_json_value(row.get("details"), default={})
        events.append(
            {
                "id": f"job-evidence:{evidence_id}",
                "incident_id": int(incident_id),
                "event_type": "job_linked",
                "author": row.get("added_by") or row.get("requested_by") or "system",
                "body": row.get("summary") or f"Linked job {job_id or row.get('ref_id')}",
                "details": {
                    "evidence_id": evidence_id,
                    "job_id": job_id if job_id > 0 else None,
                    "job_type": row.get("job_type"),
                    "status": row.get("status"),
                    "error": row.get("error"),
                    "evidence_details": details,
                },
                "created_at": _as_iso(row.get("observed_at") or row.get("created_at")),
                "source_type": "job",
                "source_id": f"incident_evidence:{evidence_id}",
            }
        )
    for row in automation_actions:
        run_action_id = int(row.get("run_action_id") or 0)
        params_json = _coerce_json_value(row.get("params_json"), default={})
        result_json = _coerce_json_value(row.get("result_json"), default={})
        events.append(
            {
                "id": f"automation:{run_action_id}",
                "incident_id": int(incident_id),
                "event_type": "automation_action",
                "author": row.get("requested_by") or "automation",
                "body": f"Automation {row.get('action_type') or 'action'} {row.get('status') or 'pending'}",
                "details": {
                    "run_action_id": run_action_id,
                    "run_id": int(row.get("run_id") or 0),
                    "playbook_id": int(row.get("playbook_id") or 0),
                    "trigger_source": row.get("trigger_source"),
                    "action_type": row.get("action_type"),
                    "risk_tier": row.get("risk_tier"),
                    "status": row.get("status"),
                    "error": row.get("error"),
                    "params_json": params_json,
                    "result_json": result_json,
                },
                "created_at": _as_iso(
                    row.get("finished_at") or row.get("started_at") or row.get("created_at")
                ),
                "source_type": "automation",
                "source_id": f"automation_run_action:{run_action_id}",
            }
        )
    for row in rollback_actions:
        rollback_id = int(row.get("rollback_id") or 0)
        run_action_id = int(row.get("run_action_id") or 0)
        events.append(
            {
                "id": f"response:{rollback_id}",
                "incident_id": int(incident_id),
                "event_type": "response_rollback",
                "author": row.get("executed_by") or row.get("requested_by") or "automation",
                "body": f"Rollback {row.get('rollback_type') or 'action'} {row.get('status') or 'pending'}",
                "details": {
                    "rollback_id": rollback_id,
                    "run_id": int(row.get("run_id") or 0),
                    "run_action_id": run_action_id,
                    "action_type": row.get("action_type"),
                    "rollback_type": row.get("rollback_type"),
                    "status": row.get("status"),
                    "error": row.get("error"),
                },
                "created_at": _as_iso(row.get("executed_at") or row.get("created_at")),
                "source_type": "response",
                "source_id": f"automation_rollback:{rollback_id}",
            }
        )

    def _sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(item.get("created_at") or ""),
            str(item.get("source_type") or ""),
            str(item.get("id") or ""),
        )

    events.sort(key=_sort_key)
    if source_types:
        allowed_sources = {str(item).strip().lower() for item in source_types if str(item).strip()}
        events = [
            item
            for item in events
            if str(item.get("source_type") or "").strip().lower() in allowed_sources
        ]
    if event_types:
        allowed_events = {str(item).strip().lower() for item in event_types if str(item).strip()}
        events = [
            item
            for item in events
            if str(item.get("event_type") or "").strip().lower() in allowed_events
        ]
    if limit_total is not None:
        limited = max(1, min(int(limit_total), 5000))
        events = events[:limited]
    return events
