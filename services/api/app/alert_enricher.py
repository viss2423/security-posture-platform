"""Alert enrichment service helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .dedupe_service import summarize_alert_deduplication
from .severity_engine import compute_effective_alert_severity


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


def get_security_alert_by_id(db: Session, alert_id: int) -> dict[str, Any] | None:
    row = (
        db.execute(
            text(
                """
                SELECT *
                FROM security_alerts
                WHERE alert_id = :alert_id
                """
            ),
            {"alert_id": int(alert_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    out = dict(row)
    out["payload_json"] = _safe_json(out.get("payload_json"), default={})
    out["context_json"] = _safe_json(out.get("context_json"), default={})
    out["mitre_techniques"] = _safe_json(out.get("mitre_techniques"), default=[])
    return out


def _related_ips(alert_row: dict[str, Any]) -> list[str]:
    payload = alert_row.get("payload_json") or {}
    context = alert_row.get("context_json") or {}
    values = [
        payload.get("src_ip"),
        payload.get("source_ip"),
        payload.get("dst_ip"),
        payload.get("dest_ip"),
        context.get("src_ip"),
        context.get("source_ip"),
        context.get("dst_ip"),
        context.get("dest_ip"),
    ]
    out: list[str] = []
    for value in values:
        text_value = str(value or "").strip()
        if text_value and text_value not in out:
            out.append(text_value)
    return out


def fetch_alert_related_events(
    db: Session,
    *,
    alert_row: dict[str, Any],
    lookback_hours: int = 24,
    limit: int = 50,
) -> list[dict[str, Any]]:
    bounded_hours = max(1, min(int(lookback_hours), 168))
    bounded_limit = max(1, min(int(limit), 200))
    start_time = datetime.now(UTC) - timedelta(hours=bounded_hours)
    asset_key = str(alert_row.get("asset_key") or "").strip()
    ips = _related_ips(alert_row)

    params: dict[str, Any] = {"start_time": start_time, "limit": bounded_limit}
    related_filters: list[str] = []
    if asset_key:
        related_filters.append("asset_key = :asset_key")
        params["asset_key"] = asset_key

    if ips:
        ip_params = []
        for idx, value in enumerate(ips):
            key = f"ip{idx}"
            params[key] = value
            ip_params.append(f":{key}")
        ip_clause = ", ".join(ip_params)
        related_filters.append(f"(src_ip IN ({ip_clause}) OR dst_ip IN ({ip_clause}))")

    if related_filters:
        where_sql = f"event_time >= :start_time AND ({' OR '.join(related_filters)})"
    else:
        where_sql = "event_time >= :start_time"
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  event_id,
                  source,
                  event_type,
                  asset_key,
                  severity,
                  src_ip,
                  src_port,
                  dst_ip,
                  dst_port,
                  domain,
                  protocol,
                  event_time,
                  ti_match,
                  ti_source,
                  anomaly_score,
                  payload_json
                FROM security_events
                WHERE {where_sql}
                ORDER BY event_time DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if hasattr(item.get("event_time"), "isoformat"):
            item["event_time"] = item["event_time"].isoformat()
        item["payload_json"] = _safe_json(item.get("payload_json"), default={})
        events.append(item)
    return events


def _suggest_next_steps(
    *,
    severity: dict[str, Any],
    ti_match: bool,
    open_incident_count: int,
    maintenance_active: bool,
    suppression_active: bool,
    related_events_count: int,
) -> list[str]:
    steps: list[str] = []
    effective = str(severity.get("effective_severity") or "medium")
    if effective in {"critical", "high"}:
        steps.append("Escalate to incident triage and assign an owner.")
    if ti_match:
        steps.append("Validate IOC hit against the matched source and scope impacted assets.")
    if related_events_count > 0:
        steps.append("Review related events for confirming signals and attacker progression.")
    if open_incident_count > 0:
        steps.append("Link this alert to the active incident workflow to avoid duplicate handling.")
    if maintenance_active or suppression_active:
        steps.append("Confirm this activity is expected within maintenance/suppression window.")
    if not steps:
        steps.append("Acknowledge and continue monitoring for recurrence.")
    return steps[:5]


def build_alert_enrichment(
    *,
    alert_row: dict[str, Any],
    asset_context: dict[str, Any] | None,
    related_events: list[dict[str, Any]],
) -> dict[str, Any]:
    context = dict(asset_context or {})
    anomaly_score = None
    for event in related_events:
        if event.get("anomaly_score") is not None:
            anomaly_score = event.get("anomaly_score")
            break

    severity = compute_effective_alert_severity(
        base_severity=alert_row.get("severity"),
        asset_criticality=context.get("criticality"),
        ti_match=bool(alert_row.get("ti_match")),
        anomaly_score=anomaly_score,
        recurrence_count=int(alert_row.get("event_count") or 1),
        top_risk_score=context.get("top_risk_score"),
        active_finding_count=context.get("active_finding_count"),
        open_incident_count=context.get("open_incident_count"),
        maintenance_active=bool(context.get("maintenance_active")),
        suppression_active=bool(context.get("suppression_rule_active")),
    )

    recurrence = summarize_alert_deduplication(alert_row)
    recommendations = _suggest_next_steps(
        severity=severity,
        ti_match=bool(alert_row.get("ti_match")),
        open_incident_count=int(context.get("open_incident_count") or 0),
        maintenance_active=bool(context.get("maintenance_active")),
        suppression_active=bool(context.get("suppression_rule_active")),
        related_events_count=len(related_events),
    )

    return {
        "alert_id": int(alert_row.get("alert_id") or 0),
        "alert_key": alert_row.get("alert_key"),
        "source": alert_row.get("source"),
        "title": alert_row.get("title"),
        "description": alert_row.get("description"),
        "asset_key": alert_row.get("asset_key"),
        "severity": alert_row.get("severity"),
        "status": alert_row.get("status"),
        "ti_match": bool(alert_row.get("ti_match")),
        "ti_source": alert_row.get("ti_source"),
        "mitre_techniques": alert_row.get("mitre_techniques") or [],
        "event_count": int(alert_row.get("event_count") or 1),
        "first_seen_at": alert_row.get("first_seen_at").isoformat()
        if hasattr(alert_row.get("first_seen_at"), "isoformat")
        else alert_row.get("first_seen_at"),
        "last_seen_at": alert_row.get("last_seen_at").isoformat()
        if hasattr(alert_row.get("last_seen_at"), "isoformat")
        else alert_row.get("last_seen_at"),
        "asset_context": context,
        "severity_analysis": severity,
        "recurrence": recurrence,
        "related_events": related_events,
        "recommended_next_steps": recommendations,
    }


__all__ = [
    "build_alert_enrichment",
    "fetch_alert_related_events",
    "get_security_alert_by_id",
]
