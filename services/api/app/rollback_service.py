"""Rollback execution helpers for automation actions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


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


def _restore_asset_tags(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    asset_key = str(payload.get("asset_key") or "").strip()
    previous_tags = payload.get("previous_tags")
    if not asset_key:
        raise ValueError("rollback_missing_asset_key")
    if not isinstance(previous_tags, list):
        previous_tags = []
    row = (
        db.execute(
            text(
                """
                UPDATE assets
                SET tags = CAST(:tags AS text[])
                WHERE asset_key = :asset_key
                RETURNING asset_id, asset_key, tags
                """
            ),
            {
                "asset_key": asset_key,
                "tags": [str(item) for item in previous_tags],
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("rollback_asset_not_found")
    return {
        "rollback_type": "asset_tags_restore",
        "asset_key": asset_key,
        "tags": list(row.get("tags") or []),
    }


def _restore_alert_suppressions(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    updates = payload.get("alerts")
    if not isinstance(updates, list):
        raise ValueError("rollback_missing_alerts")
    restored = 0
    for item in updates:
        if not isinstance(item, dict):
            continue
        alert_id = int(item.get("alert_id") or 0)
        if alert_id <= 0:
            continue
        status = str(item.get("status") or "firing").strip().lower()
        suppressed_until = item.get("suppressed_until")
        db.execute(
            text(
                """
                UPDATE security_alerts
                SET
                  status = :status,
                  suppressed_until = :suppressed_until,
                  updated_at = NOW()
                WHERE alert_id = :alert_id
                """
            ),
            {
                "alert_id": alert_id,
                "status": status,
                "suppressed_until": suppressed_until,
            },
        )
        restored += 1
    return {"rollback_type": "suppress_duplicates_restore", "restored": restored}


def execute_rollback(
    db: Session,
    *,
    rollback_id: int,
    actor: str,
) -> dict[str, Any] | None:
    row = (
        db.execute(
            text(
                """
                SELECT rollback_id, run_action_id, rollback_type, rollback_payload_json, status
                FROM automation_rollbacks
                WHERE rollback_id = :rollback_id
                """
            ),
            {"rollback_id": int(rollback_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    status = str(row.get("status") or "").strip().lower()
    if status == "executed":
        return {
            "rollback_id": int(row["rollback_id"]),
            "status": "executed",
            "already_executed": True,
        }
    payload = _safe_json(row.get("rollback_payload_json"), default={})
    rollback_type = str(row.get("rollback_type") or "").strip().lower()
    now = datetime.now(UTC)
    try:
        if rollback_type == "asset_tags_restore":
            result = _restore_asset_tags(db, payload)
        elif rollback_type == "suppress_duplicates_restore":
            result = _restore_alert_suppressions(db, payload)
        else:
            raise ValueError("unsupported_rollback_type")
        db.execute(
            text(
                """
                UPDATE automation_rollbacks
                SET
                  status = 'executed',
                  executed_by = :actor,
                  executed_at = :now,
                  error = NULL
                WHERE rollback_id = :rollback_id
                """
            ),
            {"rollback_id": int(rollback_id), "actor": actor, "now": now},
        )
        db.execute(
            text(
                """
                UPDATE automation_run_actions
                SET status = 'rolled_back', finished_at = COALESCE(finished_at, :now)
                WHERE run_action_id = :run_action_id
                """
            ),
            {"run_action_id": int(row.get("run_action_id") or 0), "now": now},
        )
        return {
            "rollback_id": int(row["rollback_id"]),
            "status": "executed",
            "run_action_id": int(row.get("run_action_id") or 0),
            "result": result,
        }
    except Exception as exc:
        db.execute(
            text(
                """
                UPDATE automation_rollbacks
                SET
                  status = 'failed',
                  executed_by = :actor,
                  executed_at = :now,
                  error = :error
                WHERE rollback_id = :rollback_id
                """
            ),
            {
                "rollback_id": int(rollback_id),
                "actor": actor,
                "now": now,
                "error": str(exc),
            },
        )
        return {
            "rollback_id": int(row["rollback_id"]),
            "status": "failed",
            "error": str(exc),
        }


def list_rollbacks(db: Session, *, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": max(1, min(int(limit), 1000))}
    if status:
        clauses.append("ar.status = :status")
        params["status"] = str(status).strip().lower()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  ar.rollback_id,
                  ar.run_action_id,
                  ar.rollback_type,
                  ar.rollback_payload_json,
                  ar.status,
                  ar.requested_by,
                  ar.executed_by,
                  ar.created_at,
                  ar.executed_at,
                  ar.error,
                  ara.run_id,
                  ara.action_type
                FROM automation_rollbacks ar
                JOIN automation_run_actions ara ON ara.run_action_id = ar.run_action_id
                WHERE {where}
                ORDER BY ar.created_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        out = dict(row)
        for key in ("created_at", "executed_at"):
            value = out.get(key)
            if hasattr(value, "isoformat"):
                out[key] = value.isoformat()
        out["rollback_payload_json"] = _safe_json(out.get("rollback_payload_json"), default={})
        items.append(out)
    return items


__all__ = ["execute_rollback", "list_rollbacks"]
