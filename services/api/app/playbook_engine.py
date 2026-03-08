"""Playbook evaluation helpers for automation workflows."""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

SUPPORTED_TRIGGERS = {
    "alert_created",
    "incident_created",
    "finding_created",
    "scan_completed",
    "ioc_matched",
    "anomaly_threshold_exceeded",
    "manual",
}
SUPPORTED_ACTIONS = {
    "enrich_alert",
    "create_incident",
    "notify_slack",
    "create_jira",
    "tag_asset",
    "run_job",
    "suppress_duplicates",
}
RISK_TIER_TO_ROLE = {"medium": "analyst", "high": "admin"}
ACTION_RISK_TIERS = {
    "enrich_alert": "low",
    "notify_slack": "low",
    "run_job": "low",
    "tag_asset": "low",
    "create_incident": "medium",
    "create_jira": "medium",
    "suppress_duplicates": "medium",
}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


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


def normalize_playbook_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out["conditions_json"] = _safe_json(out.get("conditions_json"), default=[])
    out["actions_json"] = _safe_json(out.get("actions_json"), default=[])
    out["rollback_steps_json"] = _safe_json(out.get("rollback_steps_json"), default=[])
    for key in ("created_at", "updated_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def load_enabled_playbooks(db: Session, *, trigger: str) -> list[dict[str, Any]]:
    normalized_trigger = str(trigger or "").strip().lower()
    if normalized_trigger not in SUPPORTED_TRIGGERS:
        return []
    rows = (
        db.execute(
            text(
                """
                SELECT
                  playbook_id,
                  title,
                  description,
                  trigger,
                  conditions_json,
                  actions_json,
                  approval_required,
                  rollback_steps_json,
                  enabled,
                  created_by,
                  created_at,
                  updated_at
                FROM automation_playbooks
                WHERE enabled = TRUE
                  AND trigger = :trigger
                ORDER BY updated_at DESC, playbook_id DESC
                """
            ),
            {"trigger": normalized_trigger},
        )
        .mappings()
        .all()
    )
    return [normalize_playbook_row(dict(row)) for row in rows]


def _get_context_value(context: dict[str, Any], field: str) -> Any:
    if not field:
        return None
    cursor: Any = context
    for part in field.split("."):
        key = part.strip()
        if not key:
            return None
        if isinstance(cursor, dict) and key in cursor:
            cursor = cursor[key]
            continue
        return None
    return cursor


def _normalize_condition_op(op: Any) -> str:
    return str(op or "eq").strip().lower()


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    text_value = str(value or "").strip()
    if not text_value:
        return None
    try:
        return float(text_value)
    except ValueError:
        return None


def _coerce_severity(value: Any) -> str:
    text_value = str(value or "").strip().lower()
    if text_value in SEVERITY_RANK:
        return text_value
    return "medium"


def evaluate_condition(condition: dict[str, Any], context: dict[str, Any]) -> bool:
    field = str(condition.get("field") or "").strip()
    op = _normalize_condition_op(condition.get("op"))
    expected = condition.get("value")
    actual = _get_context_value(context, field)

    if op == "exists":
        return actual is not None
    if op == "is_true":
        return bool(actual) is True
    if op == "is_false":
        return bool(actual) is False
    if op in {"eq", "ne"}:
        matches = actual == expected
        return matches if op == "eq" else not matches
    if op in {"contains", "in"}:
        if op == "contains":
            if isinstance(actual, list):
                return expected in actual
            return str(expected or "") in str(actual or "")
        if isinstance(expected, list):
            return actual in expected
        return str(actual or "") in {part.strip() for part in str(expected or "").split(",")}
    if op in {"gte", "gt", "lte", "lt"}:
        if field.endswith("severity"):
            left = SEVERITY_RANK.get(_coerce_severity(actual), 0)
            right = SEVERITY_RANK.get(_coerce_severity(expected), 0)
        else:
            left_num = _coerce_number(actual)
            right_num = _coerce_number(expected)
            if left_num is None or right_num is None:
                return False
            left = left_num
            right = right_num
        if op == "gte":
            return left >= right
        if op == "gt":
            return left > right
        if op == "lte":
            return left <= right
        return left < right
    return False


def evaluate_conditions(
    conditions: list[dict[str, Any]], context: dict[str, Any]
) -> dict[str, Any]:
    if not conditions:
        return {"matched": True, "matched_conditions": [], "failed_conditions": []}
    matched_conditions: list[dict[str, Any]] = []
    failed_conditions: list[dict[str, Any]] = []
    for condition in conditions:
        parsed = dict(condition or {})
        result = evaluate_condition(parsed, context)
        if result:
            matched_conditions.append(parsed)
        else:
            failed_conditions.append(parsed)
    return {
        "matched": len(failed_conditions) == 0,
        "matched_conditions": matched_conditions,
        "failed_conditions": failed_conditions,
    }


def action_risk_tier(action: dict[str, Any]) -> str:
    explicit = str(action.get("risk_tier") or "").strip().lower()
    if explicit in {"low", "medium", "high"}:
        return explicit
    action_type = str(action.get("type") or "").strip().lower()
    return ACTION_RISK_TIERS.get(action_type, "low")


def required_role_for_risk_tier(risk_tier: str) -> str | None:
    return RISK_TIER_TO_ROLE.get(str(risk_tier or "").strip().lower())


def resolve_templates(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {str(key): resolve_templates(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_templates(item, context) for item in value]
    if not isinstance(value, str):
        return value

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1) or ""
        resolved = _get_context_value(context, token)
        return "" if resolved is None else str(resolved)

    return _TEMPLATE_PATTERN.sub(_replace, value)


def normalize_action(
    action: dict[str, Any], *, context: dict[str, Any], index: int
) -> dict[str, Any]:
    action_type = str(action.get("type") or "").strip().lower()
    params = resolve_templates(dict(action.get("params") or {}), context)
    risk_tier = action_risk_tier(action)
    return {
        "action_index": int(index),
        "action_type": action_type,
        "params": params,
        "risk_tier": risk_tier,
        "requires_approval_role": required_role_for_risk_tier(risk_tier),
        "supported": action_type in SUPPORTED_ACTIONS,
    }


def evaluate_playbook(
    *,
    playbook: dict[str, Any],
    trigger_payload: dict[str, Any],
) -> dict[str, Any]:
    context = {"trigger": dict(trigger_payload or {}), **dict(trigger_payload or {})}
    conditions = [dict(item or {}) for item in (playbook.get("conditions_json") or [])]
    condition_result = evaluate_conditions(conditions, context)
    normalized_actions = [
        normalize_action(dict(action or {}), context=context, index=index)
        for index, action in enumerate(playbook.get("actions_json") or [])
    ]
    return {
        "playbook_id": int(playbook.get("playbook_id") or 0),
        "playbook_title": playbook.get("title"),
        "matched": bool(condition_result.get("matched")),
        "condition_result": condition_result,
        "actions": normalized_actions,
    }


__all__ = [
    "SUPPORTED_ACTIONS",
    "SUPPORTED_TRIGGERS",
    "action_risk_tier",
    "evaluate_playbook",
    "load_enabled_playbooks",
    "normalize_playbook_row",
    "required_role_for_risk_tier",
    "resolve_templates",
]
