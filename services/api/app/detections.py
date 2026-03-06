"""Detection-rule execution against telemetry events."""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .alerts_v2 import upsert_security_alert
from .db import SessionLocal

logger = logging.getLogger("secplat.detections")

ALLOWED_FIELDS = {
    "source",
    "event_type",
    "asset_key",
    "severity",
    "src_ip",
    "dst_ip",
    "domain",
    "url",
    "protocol",
    "ti_match",
}
ALLOWED_OPERATORS = {"eq", "neq", "contains", "in", "gt", "gte", "lt", "lte", "is_true", "is_false"}


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


def _condition_matches(value: Any, condition: dict[str, Any]) -> bool:
    op = str(condition.get("op") or "eq").strip().lower()
    target = condition.get("value")
    if op == "is_true":
        return bool(value) is True
    if op == "is_false":
        return bool(value) is False
    if value is None:
        return False
    if op == "eq":
        return str(value).lower() == str(target).lower()
    if op == "neq":
        return str(value).lower() != str(target).lower()
    if op == "contains":
        return str(target).lower() in str(value).lower()
    if op == "in":
        if isinstance(target, list):
            normalized = {str(item).lower() for item in target}
            return str(value).lower() in normalized
        return False
    if op in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(value)
            right = float(target)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right
    return False


def _event_matches_rule(event: dict[str, Any], definition: dict[str, Any]) -> bool:
    conditions = definition.get("conditions") or []
    if not isinstance(conditions, list) or not conditions:
        return False
    mode = str(definition.get("condition_mode") or "all").strip().lower()
    checks: list[bool] = []
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        field = str(condition.get("field") or "").strip()
        op = str(condition.get("op") or "eq").strip().lower()
        if field not in ALLOWED_FIELDS or op not in ALLOWED_OPERATORS:
            checks.append(False)
            continue
        checks.append(_condition_matches(event.get(field), condition))
    if not checks:
        return False
    if mode == "any":
        return any(checks)
    return all(checks)


def _fetch_candidate_events(
    db: Session,
    *,
    lookback_hours: int,
    source: str | None,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    since = datetime.now(UTC) - timedelta(hours=max(1, lookback_hours))
    params: dict[str, Any] = {"since": since, "limit": max(100, min(limit, 20000))}
    where_clause = "event_time >= :since"
    if source:
        where_clause += " AND source = :source"
        params["source"] = source
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  event_id, source, event_type, asset_key, severity, src_ip, dst_ip,
                  domain, url, protocol, ti_match, event_time, payload_json
                FROM security_events
                WHERE {where_clause}
                ORDER BY event_time DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    out = []
    for row in rows:
        item = dict(row)
        if hasattr(item.get("event_time"), "isoformat"):
            item["event_time"] = item["event_time"].isoformat()
        item["payload_json"] = _safe_json(item.get("payload_json"), default={})
        out.append(item)
    return out


def run_detection_rule(
    db: Session,
    *,
    rule_row: dict[str, Any],
    lookback_hours: int = 24,
    executed_by: str | None = None,
    create_alerts: bool = False,
) -> dict[str, Any]:
    definition = _safe_json(rule_row.get("definition_json"), default={})
    source_filter = (
        rule_row.get("source") or definition.get("source") or ""
    ).strip().lower() or None
    candidates = _fetch_candidate_events(
        db,
        lookback_hours=lookback_hours,
        source=source_filter,
    )
    matches = [event for event in candidates if _event_matches_rule(event, definition)]
    run_row = (
        db.execute(
            text(
                """
                INSERT INTO detection_rule_runs(
                  rule_id, executed_by, lookback_hours, status, matches, started_at, finished_at, results_json
                )
                VALUES (
                  :rule_id, :executed_by, :lookback_hours, 'done', :matches, :started_at, NOW(),
                  CAST(:results_json AS jsonb)
                )
                RETURNING run_id
                """
            ),
            {
                "rule_id": int(rule_row["rule_id"]),
                "executed_by": executed_by,
                "lookback_hours": int(lookback_hours),
                "matches": len(matches),
                "started_at": datetime.now(UTC),
                "results_json": json.dumps(
                    {
                        "matched_event_ids": [int(event["event_id"]) for event in matches[:200]],
                        "sample_matches": matches[:30],
                    }
                ),
            },
        )
        .mappings()
        .first()
    )
    db.execute(
        text(
            """
            UPDATE detection_rules
            SET last_tested_at = NOW(),
                last_test_matches = :matches,
                updated_at = NOW()
            WHERE rule_id = :rule_id
            """
        ),
        {"rule_id": int(rule_row["rule_id"]), "matches": len(matches)},
    )

    generated_alert = None
    if create_alerts and matches:
        first_asset_key = next(
            (str(event.get("asset_key") or "") for event in matches if event.get("asset_key")), None
        )
        generated_alert = upsert_security_alert(
            db,
            source="detection_rule",
            alert_type="rule_match",
            title=f"Detection rule matched: {rule_row.get('name')}",
            description=f"Rule matched {len(matches)} telemetry events in the last {lookback_hours}h.",
            dedupe_key=f"rule:{int(rule_row['rule_id'])}:{datetime.now(UTC).strftime('%Y%m%d%H')}",
            severity=str(rule_row.get("severity") or "medium"),
            asset_key=first_asset_key or None,
            context_json={
                "rule_id": int(rule_row["rule_id"]),
                "rule_name": rule_row.get("name"),
                "match_count": len(matches),
                "lookback_hours": lookback_hours,
            },
            payload_json={"sample_matches": matches[:10]},
        )

    result = {
        "rule_id": int(rule_row["rule_id"]),
        "run_id": int(run_row["run_id"]) if run_row else None,
        "lookback_hours": int(lookback_hours),
        "candidate_events": len(candidates),
        "matches": len(matches),
        "sample_matches": matches[:20],
        "generated_alert": generated_alert,
    }
    return result


def run_detection_rule_job(job_id: int) -> None:
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
        job_row = (
            db.execute(
                text(
                    """
                    SELECT job_id, requested_by, COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not job_row:
            raise ValueError("detection_job_not_found")
        params = _safe_json(job_row.get("job_params_json"), default={})
        rule_id = int(params.get("rule_id") or 0)
        lookback_hours = int(params.get("lookback_hours") or 24)
        if rule_id <= 0:
            raise ValueError("detection_rule_id_required")
        rule_row = (
            db.execute(
                text(
                    """
                    SELECT rule_id, name, description, source, severity, enabled, definition_json
                    FROM detection_rules
                    WHERE rule_id = :rule_id
                    """
                ),
                {"rule_id": rule_id},
            )
            .mappings()
            .first()
        )
        if not rule_row:
            raise ValueError("detection_rule_not_found")
        result = run_detection_rule(
            db,
            rule_row=dict(rule_row),
            lookback_hours=lookback_hours,
            executed_by=str(job_row.get("requested_by") or "analyst"),
            create_alerts=True,
        )
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
            {
                "job_id": job_id,
                "summary": f"Detection rule run completed: rule_id={rule_id} matches={result['matches']}",
            },
        )
        db.commit()
    except Exception as exc:
        logger.exception("detection_rule_job_failed job_id=%s", job_id)
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'failed', finished_at = NOW(), error = :error
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id, "error": str(exc)},
        )
        db.commit()
    finally:
        db.close()


def launch_detection_rule_job(job_id: int) -> None:
    thread = threading.Thread(
        target=run_detection_rule_job,
        args=(job_id,),
        name=f"detection-rule-job-{job_id}",
        daemon=True,
    )
    thread.start()
