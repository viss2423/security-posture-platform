"""Event-centric alert model (alerts_v2) used by telemetry, detections, and attack-lab."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

VALID_ALERT_STATUSES = {"firing", "acked", "suppressed", "resolved"}
VALID_ALERT_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def normalize_alert_severity(value: Any) -> str:
    if value is None:
        return "medium"
    if isinstance(value, (int, float)):
        numeric = int(value)
        if numeric <= 1:
            return "critical"
        if numeric == 2:
            return "high"
        if numeric == 3:
            return "medium"
        if numeric == 4:
            return "low"
        return "info"
    normalized = str(value).strip().lower()
    if normalized in VALID_ALERT_SEVERITIES:
        return normalized
    if normalized.isdigit():
        return normalize_alert_severity(int(normalized))
    return "medium"


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


def alert_key_for(source: str, dedupe_key: str) -> str:
    source_text = (source or "unknown").strip().lower()
    dedupe_text = (dedupe_key or "").strip().lower()
    digest = hashlib.sha1(f"{source_text}:{dedupe_text}".encode()).hexdigest()
    return f"alrt-{digest}"


def _resolve_asset(
    db: Session, *, asset_key: str | None, asset_id: int | None
) -> tuple[int | None, str | None]:
    if asset_id:
        row = (
            db.execute(
                text("SELECT asset_id, asset_key FROM assets WHERE asset_id = :asset_id"),
                {"asset_id": int(asset_id)},
            )
            .mappings()
            .first()
        )
        if row:
            return int(row["asset_id"]), str(row["asset_key"])
    normalized_key = (asset_key or "").strip()
    if not normalized_key:
        return None, None
    row = (
        db.execute(
            text("SELECT asset_id, asset_key FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": normalized_key},
        )
        .mappings()
        .first()
    )
    if row:
        return int(row["asset_id"]), str(row["asset_key"])
    return None, normalized_key


def serialize_security_alert(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in (
        "first_seen_at",
        "last_seen_at",
        "acknowledged_at",
        "suppressed_until",
        "resolved_at",
        "created_at",
        "updated_at",
    ):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["mitre_techniques"] = _safe_json(out.get("mitre_techniques"), default=[])
    out["payload_json"] = _safe_json(out.get("payload_json"), default={})
    out["context_json"] = _safe_json(out.get("context_json"), default={})
    return out


def upsert_security_alert(
    db: Session,
    *,
    source: str,
    title: str,
    description: str | None = None,
    dedupe_key: str,
    alert_type: str = "detection",
    severity: Any = "medium",
    asset_key: str | None = None,
    asset_id: int | None = None,
    event_time: datetime | None = None,
    ti_match: bool = False,
    ti_source: str | None = None,
    mitre_techniques: list[str] | None = None,
    payload_json: dict[str, Any] | None = None,
    context_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    observed_at = event_time or now
    normalized_source = (source or "unknown").strip().lower() or "unknown"
    normalized_dedupe = (dedupe_key or "").strip().lower() or f"{normalized_source}:{title}"
    alert_key = alert_key_for(normalized_source, normalized_dedupe)
    normalized_severity = normalize_alert_severity(severity)
    resolved_asset_id, resolved_asset_key = _resolve_asset(
        db,
        asset_key=asset_key,
        asset_id=asset_id,
    )

    row = (
        db.execute(
            text(
                """
                INSERT INTO security_alerts(
                  alert_key, dedupe_key, source, alert_type, asset_id, asset_key, severity, status,
                  title, description, event_count, first_seen_at, last_seen_at,
                  ti_match, ti_source, mitre_techniques, payload_json, context_json,
                  created_at, updated_at
                )
                VALUES (
                  :alert_key, :dedupe_key, :source, :alert_type, :asset_id, :asset_key, :severity, 'firing',
                  :title, :description, 1, :observed_at, :observed_at,
                  :ti_match, :ti_source, CAST(:mitre_techniques AS jsonb),
                  CAST(:payload_json AS jsonb), CAST(:context_json AS jsonb),
                  :now, :now
                )
                ON CONFLICT (alert_key) DO UPDATE
                SET
                  source = EXCLUDED.source,
                  alert_type = EXCLUDED.alert_type,
                  asset_id = EXCLUDED.asset_id,
                  asset_key = EXCLUDED.asset_key,
                  severity = EXCLUDED.severity,
                  title = EXCLUDED.title,
                  description = COALESCE(EXCLUDED.description, security_alerts.description),
                  event_count = security_alerts.event_count + 1,
                  last_seen_at = GREATEST(security_alerts.last_seen_at, EXCLUDED.last_seen_at),
                  ti_match = security_alerts.ti_match OR EXCLUDED.ti_match,
                  ti_source = COALESCE(EXCLUDED.ti_source, security_alerts.ti_source),
                  mitre_techniques = EXCLUDED.mitre_techniques,
                  payload_json = EXCLUDED.payload_json,
                  context_json = EXCLUDED.context_json,
                  status = CASE
                    WHEN security_alerts.status = 'resolved' THEN 'firing'
                    WHEN security_alerts.status = 'suppressed' AND security_alerts.suppressed_until IS NOT NULL
                         AND security_alerts.suppressed_until < :now THEN 'firing'
                    ELSE security_alerts.status
                  END,
                  updated_at = :now
                RETURNING *
                """
            ),
            {
                "alert_key": alert_key,
                "dedupe_key": normalized_dedupe,
                "source": normalized_source,
                "alert_type": (alert_type or "detection").strip().lower(),
                "asset_id": resolved_asset_id,
                "asset_key": resolved_asset_key,
                "severity": normalized_severity,
                "title": (title or "Security alert").strip() or "Security alert",
                "description": (description or "").strip() or None,
                "observed_at": observed_at,
                "ti_match": bool(ti_match),
                "ti_source": (ti_source or "").strip() or None,
                "mitre_techniques": json.dumps(list(dict.fromkeys(mitre_techniques or []))),
                "payload_json": json.dumps(payload_json or {}),
                "context_json": json.dumps(context_json or {}),
                "now": now,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("security_alert_upsert_failed")
    return serialize_security_alert(dict(row))


def transition_security_alert(
    db: Session,
    *,
    alert_id: int,
    action: str,
    user_name: str | None = None,
    reason: str | None = None,
    until: datetime | None = None,
    assigned_to: str | None = None,
) -> dict[str, Any] | None:
    now = datetime.now(UTC)
    normalized_action = (action or "").strip().lower()
    if normalized_action not in {"ack", "suppress", "resolve", "assign", "reopen"}:
        raise ValueError("invalid_alert_action")

    if normalized_action == "ack":
        stmt = text(
            """
            UPDATE security_alerts
            SET status = 'acked',
                acknowledged_by = :user_name,
                acknowledged_at = :now,
                suppression_reason = COALESCE(:reason, suppression_reason),
                updated_at = :now
            WHERE alert_id = :alert_id
            RETURNING *
            """
        )
        params = {"alert_id": alert_id, "user_name": user_name, "reason": reason, "now": now}
    elif normalized_action == "suppress":
        if until is None:
            raise ValueError("suppressed_until_required")
        stmt = text(
            """
            UPDATE security_alerts
            SET status = 'suppressed',
                suppression_reason = COALESCE(:reason, suppression_reason),
                suppressed_until = :until,
                updated_at = :now
            WHERE alert_id = :alert_id
            RETURNING *
            """
        )
        params = {"alert_id": alert_id, "reason": reason, "until": until, "now": now}
    elif normalized_action == "resolve":
        stmt = text(
            """
            UPDATE security_alerts
            SET status = 'resolved',
                resolved_by = :user_name,
                resolved_at = :now,
                updated_at = :now
            WHERE alert_id = :alert_id
            RETURNING *
            """
        )
        params = {"alert_id": alert_id, "user_name": user_name, "now": now}
    elif normalized_action == "assign":
        stmt = text(
            """
            UPDATE security_alerts
            SET assigned_to = :assigned_to,
                updated_at = :now
            WHERE alert_id = :alert_id
            RETURNING *
            """
        )
        params = {"alert_id": alert_id, "assigned_to": assigned_to, "now": now}
    else:
        stmt = text(
            """
            UPDATE security_alerts
            SET status = 'firing',
                suppressed_until = NULL,
                updated_at = :now
            WHERE alert_id = :alert_id
            RETURNING *
            """
        )
        params = {"alert_id": alert_id, "now": now}

    row = db.execute(stmt, params).mappings().first()
    if not row:
        return None
    return serialize_security_alert(dict(row))


def reopen_expired_suppressed_alerts(db: Session) -> int:
    now = datetime.now(UTC)
    result = db.execute(
        text(
            """
            UPDATE security_alerts
            SET status = 'firing',
                updated_at = :now
            WHERE status = 'suppressed'
              AND suppressed_until IS NOT NULL
              AND suppressed_until < :now
            """
        ),
        {"now": now},
    )
    return int(result.rowcount or 0)
