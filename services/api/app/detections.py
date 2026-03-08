"""Detection-rule execution against telemetry events."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from sqlalchemy import text
from sqlalchemy.orm import Session

from .alerts_v2 import upsert_security_alert
from .db import SessionLocal
from .queue import publish_scan_job

logger = logging.getLogger("secplat.detections")
RUN_MODES = {"test", "simulate", "scheduled"}
CORRELATION_GROUPS = {"asset_key", "source_ip", "none"}
CORRELATION_RUN_MODES = {"manual", "job", "scheduled"}

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


def _load_rule_definition(rule_row: dict[str, Any]) -> dict[str, Any]:
    definition = _safe_json(rule_row.get("definition_json"), default={})
    if isinstance(definition, dict) and definition:
        return definition
    yaml_blob = str(rule_row.get("definition_yaml") or "").strip()
    if yaml_blob:
        try:
            parsed = yaml.safe_load(yaml_blob)
        except yaml.YAMLError:
            logger.warning(
                "detection_rule_yaml_parse_failed rule_id=%s",
                rule_row.get("rule_id"),
                exc_info=True,
            )
            return {}
        if isinstance(parsed, dict):
            return parsed
    return definition if isinstance(definition, dict) else {}


def _fetch_candidate_events(
    db: Session,
    *,
    window_start: datetime,
    window_end: datetime,
    source: str | None,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "since": window_start,
        "until": window_end,
        "limit": max(100, min(limit, 20000)),
    }
    where_clause = "event_time >= :since AND event_time <= :until"
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
                ORDER BY event_time DESC, event_id DESC
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


def _normalize_run_mode(value: str | None, *, fallback: str = "test") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in RUN_MODES:
        return fallback
    return normalized


def _normalize_trigger_source(value: str | None, *, fallback: str = "manual") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in {"manual", "job", "scheduler"}:
        return fallback
    return normalized


def _deterministic_match_snapshot(
    *,
    rule_row: dict[str, Any],
    lookback_hours: int,
    window_start: datetime,
    window_end: datetime,
    matches: list[dict[str, Any]],
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    sorted_matches = sorted(matches, key=lambda item: int(item.get("event_id") or 0))
    matched_event_ids = [int(item.get("event_id") or 0) for item in sorted_matches]
    fingerprints: list[dict[str, Any]] = []
    for item in sorted_matches[:200]:
        fingerprints.append(
            {
                "event_id": int(item.get("event_id") or 0),
                "event_time": item.get("event_time"),
                "source": item.get("source"),
                "event_type": item.get("event_type"),
                "asset_key": item.get("asset_key"),
                "severity": item.get("severity"),
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "domain": item.get("domain"),
                "url": item.get("url"),
                "protocol": item.get("protocol"),
                "ti_match": bool(item.get("ti_match")),
            }
        )
    snapshot = {
        "snapshot_version": 1,
        "rule_id": int(rule_row.get("rule_id") or 0),
        "rule_key": str(rule_row.get("rule_key") or ""),
        "rule_version": int(rule_row.get("version") or 1),
        "rule_stage": str(rule_row.get("stage") or ""),
        "lookback_hours": int(lookback_hours),
        "window_start": window_start.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "window_end": window_end.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "match_count": len(sorted_matches),
        "matched_event_ids": matched_event_ids,
        "fingerprints": fingerprints,
    }
    snapshot_blob = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    snapshot_hash = hashlib.sha256(snapshot_blob.encode("utf-8")).hexdigest()
    return snapshot, snapshot_hash, sorted_matches


def run_detection_rule(
    db: Session,
    *,
    rule_row: dict[str, Any],
    lookback_hours: int = 24,
    executed_by: str | None = None,
    create_alerts: bool = False,
    run_mode: str = "test",
    trigger_source: str = "manual",
    schedule_ref: str | None = None,
) -> dict[str, Any]:
    normalized_run_mode = _normalize_run_mode(run_mode, fallback="test")
    normalized_trigger_source = _normalize_trigger_source(trigger_source, fallback="manual")
    if normalized_run_mode == "simulate":
        create_alerts = False
    effective_lookback = max(1, int(lookback_hours))
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(hours=effective_lookback)
    definition = _load_rule_definition(rule_row)
    source_filter = (
        rule_row.get("source") or definition.get("source") or ""
    ).strip().lower() or None
    candidates = _fetch_candidate_events(
        db,
        window_start=window_start,
        window_end=window_end,
        source=source_filter,
    )
    matches = [event for event in candidates if _event_matches_rule(event, definition)]
    snapshot_json, snapshot_hash, sorted_matches = _deterministic_match_snapshot(
        rule_row=rule_row,
        lookback_hours=effective_lookback,
        window_start=window_start,
        window_end=window_end,
        matches=matches,
    )
    run_row = (
        db.execute(
            text(
                """
                INSERT INTO detection_rule_runs(
                  rule_id, executed_by, lookback_hours, status, matches, run_mode, trigger_source,
                  schedule_ref, create_alerts, snapshot_hash, snapshot_json, rule_version, rule_stage,
                  window_start, window_end, started_at, finished_at, results_json
                )
                VALUES (
                  :rule_id, :executed_by, :lookback_hours, 'done', :matches, :run_mode, :trigger_source,
                  :schedule_ref, :create_alerts, :snapshot_hash, CAST(:snapshot_json AS jsonb), :rule_version,
                  :rule_stage, :window_start, :window_end, :started_at, NOW(), CAST(:results_json AS jsonb)
                )
                RETURNING run_id
                """
            ),
            {
                "rule_id": int(rule_row["rule_id"]),
                "executed_by": executed_by,
                "lookback_hours": effective_lookback,
                "matches": len(sorted_matches),
                "run_mode": normalized_run_mode,
                "trigger_source": normalized_trigger_source,
                "schedule_ref": str(schedule_ref or "").strip() or None,
                "create_alerts": bool(create_alerts),
                "snapshot_hash": snapshot_hash,
                "snapshot_json": json.dumps(snapshot_json),
                "rule_version": int(rule_row.get("version") or 1),
                "rule_stage": str(rule_row.get("stage") or "") or None,
                "window_start": window_start,
                "window_end": window_end,
                "started_at": window_end,
                "results_json": json.dumps(
                    {
                        "snapshot_hash": snapshot_hash,
                        "run_mode": normalized_run_mode,
                        "trigger_source": normalized_trigger_source,
                        "schedule_ref": str(schedule_ref or "").strip() or None,
                        "window_start": window_start.astimezone(UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "window_end": window_end.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                        "matched_event_ids": [
                            int(event["event_id"]) for event in sorted_matches[:500]
                        ],
                        "sample_matches": sorted_matches[:30],
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
        {"rule_id": int(rule_row["rule_id"]), "matches": len(sorted_matches)},
    )

    generated_alert = None
    if create_alerts and sorted_matches:
        first_asset_key = next(
            (
                str(event.get("asset_key") or "")
                for event in sorted_matches
                if event.get("asset_key")
            ),
            None,
        )
        generated_alert = upsert_security_alert(
            db,
            source="detection_rule",
            alert_type="rule_match",
            title=f"Detection rule matched: {rule_row.get('name')}",
            description=(
                f"Rule matched {len(sorted_matches)} telemetry events in the last {effective_lookback}h."
            ),
            dedupe_key=f"rule:{int(rule_row['rule_id'])}:{datetime.now(UTC).strftime('%Y%m%d%H')}",
            severity=str(rule_row.get("severity") or "medium"),
            asset_key=first_asset_key or None,
            context_json={
                "rule_id": int(rule_row["rule_id"]),
                "rule_name": rule_row.get("name"),
                "rule_key": rule_row.get("rule_key"),
                "rule_version": rule_row.get("version"),
                "rule_stage": rule_row.get("stage"),
                "run_mode": normalized_run_mode,
                "trigger_source": normalized_trigger_source,
                "schedule_ref": str(schedule_ref or "").strip() or None,
                "snapshot_hash": snapshot_hash,
                "match_count": len(sorted_matches),
                "lookback_hours": effective_lookback,
            },
            payload_json={"sample_matches": sorted_matches[:10]},
        )

    result = {
        "rule_id": int(rule_row["rule_id"]),
        "run_id": int(run_row["run_id"]) if run_row else None,
        "lookback_hours": effective_lookback,
        "run_mode": normalized_run_mode,
        "trigger_source": normalized_trigger_source,
        "schedule_ref": str(schedule_ref or "").strip() or None,
        "create_alerts": bool(create_alerts),
        "candidate_events": len(candidates),
        "matches": len(sorted_matches),
        "snapshot_hash": snapshot_hash,
        "snapshot_json": snapshot_json,
        "sample_matches": sorted_matches[:20],
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
                    SELECT
                      job_id,
                      job_type,
                      requested_by,
                      COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
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
        job_type = str(job_row.get("job_type") or "detection_rule_test").strip().lower()
        run_mode = _normalize_run_mode(
            str(params.get("run_mode") or "").strip().lower()
            or ("scheduled" if job_type == "detection_rule_schedule" else "test"),
            fallback="scheduled" if job_type == "detection_rule_schedule" else "test",
        )
        trigger_source = _normalize_trigger_source(
            str(params.get("trigger_source") or "").strip().lower()
            or ("scheduler" if job_type == "detection_rule_schedule" else "job"),
            fallback="scheduler" if job_type == "detection_rule_schedule" else "job",
        )
        schedule_ref = str(params.get("schedule_ref") or "").strip() or None
        create_alerts = bool(params.get("create_alerts", run_mode != "simulate"))
        if run_mode == "simulate":
            create_alerts = False
        if rule_id <= 0:
            raise ValueError("detection_rule_id_required")
        rule_row = (
            db.execute(
                text(
                    """
                    SELECT
                      rule_id, name, description, source, rule_key, version, mitre_tactic,
                      mitre_technique, parent_rule_id, stage, rule_format, severity,
                      enabled, definition_yaml, definition_json
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
            create_alerts=create_alerts,
            run_mode=run_mode,
            trigger_source=trigger_source,
            schedule_ref=schedule_ref,
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
                "summary": (
                    "Detection rule run completed: "
                    f"rule_id={rule_id} mode={result.get('run_mode')} "
                    f"matches={result['matches']} snapshot={result.get('snapshot_hash')}"
                ),
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


def _launch_detection_job(job_id: int, *, queued_job_type: str) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT target_asset_id, requested_by
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
            logger.warning("detection_rule_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    published = publish_scan_job(
        int(job_id),
        queued_job_type,
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    )
    if not published:
        logger.warning(
            "detection_rule_enqueue_failed job_id=%s job_type=%s", job_id, queued_job_type
        )


def launch_detection_rule_job(job_id: int) -> None:
    _launch_detection_job(job_id, queued_job_type="detection_rule_test")


def launch_detection_rule_scheduled_job(job_id: int) -> None:
    _launch_detection_job(job_id, queued_job_type="detection_rule_schedule")


def _normalize_correlation_group(value: Any, *, fallback: str = "asset_key") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in CORRELATION_GROUPS:
        return fallback
    return normalized


def _normalize_correlation_run_mode(value: Any, *, fallback: str = "manual") -> str:
    normalized = str(value or fallback).strip().lower() or fallback
    if normalized not in CORRELATION_RUN_MODES:
        return fallback
    return normalized


def _safe_positive_int(value: Any, *, fallback: int, minimum: int = 1, maximum: int = 10080) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        numeric = fallback
    if numeric < minimum:
        return minimum
    if numeric > maximum:
        return maximum
    return numeric


def _alert_source_ip(alert: dict[str, Any]) -> str | None:
    context = _safe_json(alert.get("context_json"), default={})
    if isinstance(context, dict):
        src_ip = str(context.get("src_ip") or "").strip()
        if src_ip:
            return src_ip
    payload = _safe_json(alert.get("payload_json"), default={})
    if isinstance(payload, dict):
        src_ip = str(payload.get("src_ip") or "").strip()
        if src_ip:
            return src_ip
    return None


def _correlation_group_key(alert: dict[str, Any], group_by: str) -> str:
    if group_by == "none":
        return "global"
    if group_by == "source_ip":
        return _alert_source_ip(alert) or "unknown"
    asset_key = str(alert.get("asset_key") or "").strip()
    return asset_key or "unassigned"


def _fetch_correlation_alerts(
    db: Session,
    *,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    rows = (
        db.execute(
            text(
                """
                SELECT
                  alert_id,
                  source,
                  alert_type,
                  severity,
                  asset_key,
                  event_count,
                  first_seen_at,
                  last_seen_at,
                  context_json,
                  payload_json,
                  mitre_techniques
                FROM security_alerts
                WHERE last_seen_at >= :window_start
                  AND last_seen_at <= :window_end
                  AND status <> 'resolved'
                ORDER BY last_seen_at DESC, alert_id DESC
                LIMIT 10000
                """
            ),
            {"window_start": window_start, "window_end": window_end},
        )
        .mappings()
        .all()
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["context_json"] = _safe_json(item.get("context_json"), default={})
        item["payload_json"] = _safe_json(item.get("payload_json"), default={})
        item["mitre_techniques"] = _safe_json(item.get("mitre_techniques"), default=[])
        for key in ("first_seen_at", "last_seen_at"):
            value = item.get(key)
            if hasattr(value, "isoformat"):
                item[key] = value.isoformat()
        out.append(item)
    return out


def _correlation_step_matches(alert: dict[str, Any], step: dict[str, Any]) -> bool:
    source = str(step.get("source") or "").strip().lower()
    if source and str(alert.get("source") or "").strip().lower() != source:
        return False
    alert_type = str(step.get("alert_type") or "").strip().lower()
    if alert_type and str(alert.get("alert_type") or "").strip().lower() != alert_type:
        return False
    severity = step.get("severity")
    if severity:
        if isinstance(severity, list):
            allowed = {str(item).strip().lower() for item in severity if str(item).strip()}
            if allowed and str(alert.get("severity") or "").strip().lower() not in allowed:
                return False
        else:
            if str(alert.get("severity") or "").strip().lower() != str(severity).strip().lower():
                return False
    min_event_count = _safe_positive_int(
        step.get("min_event_count"), fallback=1, minimum=1, maximum=100000
    )
    try:
        event_count = int(alert.get("event_count") or 1)
    except (TypeError, ValueError):
        event_count = 1
    if event_count < min_event_count:
        return False
    return True


def run_correlation_rule(
    db: Session,
    *,
    rule_row: dict[str, Any],
    lookback_minutes: int | None = None,
    executed_by: str | None = None,
    create_alerts: bool = True,
    run_mode: str = "manual",
    trigger_source: str = "manual",
    schedule_ref: str | None = None,
) -> dict[str, Any]:
    rule_definition = _safe_json(rule_row.get("definition_json"), default={})
    group_by = _normalize_correlation_group(
        rule_row.get("group_by") or rule_definition.get("group_by") or "asset_key",
        fallback="asset_key",
    )
    effective_lookback = _safe_positive_int(
        lookback_minutes
        or rule_row.get("window_minutes")
        or rule_definition.get("window_minutes")
        or 60,
        fallback=60,
        minimum=5,
        maximum=10080,
    )
    min_distinct_sources = _safe_positive_int(
        rule_row.get("min_distinct_sources") or rule_definition.get("min_distinct_sources") or 1,
        fallback=1,
        minimum=1,
        maximum=25,
    )
    normalized_run_mode = _normalize_correlation_run_mode(run_mode, fallback="manual")
    normalized_trigger_source = _normalize_trigger_source(trigger_source, fallback="manual")

    steps_raw = rule_definition.get("steps")
    steps: list[dict[str, Any]] = []
    if isinstance(steps_raw, list):
        for item in steps_raw:
            if isinstance(item, dict):
                steps.append(item)
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(minutes=effective_lookback)
    candidates = _fetch_correlation_alerts(
        db,
        window_start=window_start,
        window_end=window_end,
    )

    grouped_alerts: dict[str, list[dict[str, Any]]] = {}
    for alert in candidates:
        key = _correlation_group_key(alert, group_by)
        grouped_alerts.setdefault(key, []).append(alert)

    matched_chains: list[dict[str, Any]] = []
    for group_key, alerts in grouped_alerts.items():
        if not steps:
            continue
        chain_step_counts: list[dict[str, Any]] = []
        chain_alert_ids: set[int] = set()
        for idx, step in enumerate(steps, start=1):
            min_count = _safe_positive_int(
                step.get("min_count"), fallback=1, minimum=1, maximum=1000
            )
            matched = [alert for alert in alerts if _correlation_step_matches(alert, step)]
            if len(matched) < min_count:
                chain_step_counts = []
                chain_alert_ids = set()
                break
            chain_step_counts.append(
                {
                    "step": idx,
                    "min_count": min_count,
                    "matched_count": len(matched),
                    "source": str(step.get("source") or ""),
                    "alert_type": str(step.get("alert_type") or ""),
                }
            )
            for matched_alert in matched:
                chain_alert_ids.add(int(matched_alert.get("alert_id") or 0))
        if not chain_step_counts:
            continue
        distinct_sources = len(
            {
                str(alert.get("source") or "").strip().lower()
                for alert in alerts
                if int(alert.get("alert_id") or 0) in chain_alert_ids
            }
        )
        if distinct_sources < min_distinct_sources:
            continue
        matched_chains.append(
            {
                "group_key": group_key,
                "group_by": group_by,
                "distinct_sources": distinct_sources,
                "step_counts": chain_step_counts,
                "matched_alert_ids": sorted(chain_alert_ids),
            }
        )

    ordered_chains = sorted(
        matched_chains,
        key=lambda item: (str(item.get("group_key") or ""), str(item.get("group_by") or "")),
    )
    snapshot_json = {
        "snapshot_version": 1,
        "correlation_rule_id": int(rule_row.get("correlation_rule_id") or 0),
        "lookback_minutes": int(effective_lookback),
        "window_start": window_start.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "window_end": window_end.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "matched_chains": ordered_chains,
    }
    snapshot_blob = json.dumps(snapshot_json, sort_keys=True, separators=(",", ":"), default=str)
    snapshot_hash = hashlib.sha256(snapshot_blob.encode("utf-8")).hexdigest()

    run_row = (
        db.execute(
            text(
                """
                INSERT INTO detection_correlation_runs(
                  correlation_rule_id, executed_by, run_mode, trigger_source, schedule_ref,
                  lookback_minutes, window_start, window_end, matched_chains, alerts_created,
                  snapshot_hash, snapshot_json, started_at, finished_at
                )
                VALUES (
                  :correlation_rule_id, :executed_by, :run_mode, :trigger_source, :schedule_ref,
                  :lookback_minutes, :window_start, :window_end, :matched_chains, 0,
                  :snapshot_hash, CAST(:snapshot_json AS jsonb), :started_at, NOW()
                )
                RETURNING run_id
                """
            ),
            {
                "correlation_rule_id": int(rule_row.get("correlation_rule_id") or 0),
                "executed_by": executed_by,
                "run_mode": normalized_run_mode,
                "trigger_source": normalized_trigger_source,
                "schedule_ref": str(schedule_ref or "").strip() or None,
                "lookback_minutes": int(effective_lookback),
                "window_start": window_start,
                "window_end": window_end,
                "matched_chains": len(ordered_chains),
                "snapshot_hash": snapshot_hash,
                "snapshot_json": json.dumps(snapshot_json),
                "started_at": window_end,
            },
        )
        .mappings()
        .first()
    )
    run_id = int(run_row["run_id"]) if run_row else None
    alerts_created = 0
    if create_alerts:
        for chain in ordered_chains:
            group_key = str(chain.get("group_key") or "")
            dedupe_key = (
                f"corr:{int(rule_row.get('correlation_rule_id') or 0)}:"
                f"{group_key}:{window_end.strftime('%Y%m%d%H%M')}"
            )
            asset_key = (
                group_key
                if group_by == "asset_key" and group_key not in {"", "unassigned"}
                else None
            )
            mitre_techniques = [str(rule_row.get("mitre_technique") or "").strip()]
            mitre_techniques = [item for item in mitre_techniques if item]
            alert = upsert_security_alert(
                db,
                source="correlation_engine",
                alert_type="correlation_chain",
                title=f"Correlation chain matched: {rule_row.get('name')}",
                description=(
                    f"Matched {len(chain.get('matched_alert_ids') or [])} alerts "
                    f"across {int(chain.get('distinct_sources') or 0)} sources"
                ),
                dedupe_key=dedupe_key,
                severity=str(rule_row.get("severity") or "high"),
                asset_key=asset_key,
                ti_match=False,
                mitre_techniques=mitre_techniques,
                context_json={
                    "correlation_rule_id": int(rule_row.get("correlation_rule_id") or 0),
                    "correlation_rule_name": rule_row.get("name"),
                    "group_by": group_by,
                    "group_key": group_key,
                    "step_counts": chain.get("step_counts") or [],
                    "matched_alert_ids": chain.get("matched_alert_ids") or [],
                    "snapshot_hash": snapshot_hash,
                    "run_id": run_id,
                },
                payload_json={
                    "chain": chain,
                    "window_start": snapshot_json["window_start"],
                    "window_end": snapshot_json["window_end"],
                },
            )
            if alert:
                alerts_created += 1

    db.execute(
        text(
            """
            UPDATE detection_correlation_runs
            SET alerts_created = :alerts_created
            WHERE run_id = :run_id
            """
        ),
        {"run_id": run_id, "alerts_created": alerts_created},
    )
    db.execute(
        text(
            """
            UPDATE detection_correlation_rules
            SET last_run_at = NOW(),
                last_match_count = :last_match_count,
                updated_at = NOW()
            WHERE correlation_rule_id = :correlation_rule_id
            """
        ),
        {
            "correlation_rule_id": int(rule_row.get("correlation_rule_id") or 0),
            "last_match_count": len(ordered_chains),
        },
    )
    return {
        "correlation_rule_id": int(rule_row.get("correlation_rule_id") or 0),
        "run_id": run_id,
        "run_mode": normalized_run_mode,
        "trigger_source": normalized_trigger_source,
        "schedule_ref": str(schedule_ref or "").strip() or None,
        "lookback_minutes": int(effective_lookback),
        "candidate_alerts": len(candidates),
        "matched_chains": len(ordered_chains),
        "alerts_created": alerts_created,
        "snapshot_hash": snapshot_hash,
        "snapshot_json": snapshot_json,
        "sample_chains": ordered_chains[:20],
    }


def run_correlation_pass(
    db: Session,
    *,
    executed_by: str | None = None,
    lookback_minutes: int = 60,
    create_alerts: bool = True,
    run_mode: str = "job",
    trigger_source: str = "job",
    schedule_ref: str | None = None,
    correlation_rule_id: int | None = None,
) -> dict[str, Any]:
    clauses = ["enabled = TRUE"]
    params: dict[str, Any] = {}
    if correlation_rule_id is not None:
        clauses.append("correlation_rule_id = :correlation_rule_id")
        params["correlation_rule_id"] = int(correlation_rule_id)
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  correlation_rule_id,
                  name,
                  description,
                  severity,
                  enabled,
                  group_by,
                  window_minutes,
                  min_distinct_sources,
                  mitre_tactic,
                  mitre_technique,
                  definition_json
                FROM detection_correlation_rules
                WHERE {where}
                ORDER BY correlation_rule_id ASC
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    per_rule_runs: list[dict[str, Any]] = []
    for row in rows:
        summary = run_correlation_rule(
            db,
            rule_row=dict(row),
            lookback_minutes=lookback_minutes,
            executed_by=executed_by,
            create_alerts=create_alerts,
            run_mode=run_mode,
            trigger_source=trigger_source,
            schedule_ref=schedule_ref,
        )
        per_rule_runs.append(summary)
    return {
        "lookback_minutes": int(lookback_minutes),
        "correlation_rule_count": len(rows),
        "matched_chains": int(sum(int(item.get("matched_chains") or 0) for item in per_rule_runs)),
        "alerts_created": int(sum(int(item.get("alerts_created") or 0) for item in per_rule_runs)),
        "rules": per_rule_runs,
    }


def run_correlation_pass_job(job_id: int) -> None:
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
                    SELECT
                      job_id,
                      job_type,
                      requested_by,
                      COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
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
            raise ValueError("correlation_job_not_found")
        params = _safe_json(job_row.get("job_params_json"), default={})
        lookback_minutes = _safe_positive_int(
            params.get("lookback_minutes"), fallback=60, minimum=5, maximum=10080
        )
        correlation_rule_id = params.get("correlation_rule_id")
        if correlation_rule_id is not None:
            correlation_rule_id = int(correlation_rule_id)
        job_type = str(job_row.get("job_type") or "correlation_pass").strip().lower()
        run_mode = _normalize_correlation_run_mode(
            str(params.get("run_mode") or "").strip().lower() or ("job"),
            fallback="job",
        )
        trigger_source = _normalize_trigger_source(
            str(params.get("trigger_source") or "").strip().lower()
            or ("scheduler" if run_mode == "scheduled" else "job"),
            fallback="scheduler" if run_mode == "scheduled" else "job",
        )
        schedule_ref = str(params.get("schedule_ref") or "").strip() or None
        create_alerts = bool(params.get("create_alerts", True))
        result = run_correlation_pass(
            db,
            executed_by=str(job_row.get("requested_by") or "analyst"),
            lookback_minutes=lookback_minutes,
            create_alerts=create_alerts,
            run_mode=run_mode,
            trigger_source=trigger_source,
            schedule_ref=schedule_ref,
            correlation_rule_id=correlation_rule_id,
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
                "summary": (
                    "Correlation pass completed: "
                    f"rules={result.get('correlation_rule_count')} "
                    f"matches={result.get('matched_chains')} "
                    f"alerts_created={result.get('alerts_created')}"
                ),
            },
        )
        db.commit()
    except Exception as exc:
        logger.exception("correlation_pass_job_failed job_id=%s", job_id)
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


def launch_correlation_pass_job(job_id: int) -> None:
    _launch_detection_job(job_id, queued_job_type="correlation_pass")
