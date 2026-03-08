"""Approval workflow helpers for automation actions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .playbook_engine import required_role_for_risk_tier


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("created_at", "decided_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def create_approval_request(
    db: Session,
    *,
    run_action_id: int,
    risk_tier: str,
    requested_by: str | None,
    reason: str | None = None,
) -> dict[str, Any]:
    required_role = required_role_for_risk_tier(risk_tier)
    if not required_role:
        raise ValueError("approval_not_required_for_risk_tier")
    row = (
        db.execute(
            text(
                """
                INSERT INTO automation_approvals (
                  run_action_id, required_role, risk_tier, status, requested_by, reason
                )
                VALUES (
                  :run_action_id, :required_role, :risk_tier, 'pending', :requested_by, :reason
                )
                ON CONFLICT (run_action_id) DO UPDATE
                SET
                  required_role = EXCLUDED.required_role,
                  risk_tier = EXCLUDED.risk_tier,
                  status = 'pending',
                  requested_by = EXCLUDED.requested_by,
                  reason = EXCLUDED.reason,
                  approved_by = NULL,
                  rejected_by = NULL,
                  decision_note = NULL,
                  decided_at = NULL
                RETURNING *
                """
            ),
            {
                "run_action_id": int(run_action_id),
                "required_role": required_role,
                "risk_tier": str(risk_tier).strip().lower(),
                "requested_by": requested_by,
                "reason": reason,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("approval_request_create_failed")
    return _serialize(dict(row))


def decide_approval(
    db: Session,
    *,
    approval_id: int,
    decision: str,
    actor: str,
    note: str | None = None,
) -> dict[str, Any] | None:
    normalized = str(decision or "").strip().lower()
    if normalized not in {"approved", "rejected"}:
        raise ValueError("invalid_approval_decision")
    now = datetime.now(UTC)
    if normalized == "approved":
        stmt = text(
            """
            UPDATE automation_approvals
            SET
              status = 'approved',
              approved_by = :actor,
              rejected_by = NULL,
              decision_note = :note,
              decided_at = :now
            WHERE approval_id = :approval_id
            RETURNING *
            """
        )
    else:
        stmt = text(
            """
            UPDATE automation_approvals
            SET
              status = 'rejected',
              rejected_by = :actor,
              approved_by = NULL,
              decision_note = :note,
              decided_at = :now
            WHERE approval_id = :approval_id
            RETURNING *
            """
        )
    row = (
        db.execute(
            stmt,
            {
                "approval_id": int(approval_id),
                "actor": actor,
                "note": (note or "").strip() or None,
                "now": now,
            },
        )
        .mappings()
        .first()
    )
    return _serialize(dict(row)) if row else None


def list_pending_approvals(db: Session, *, limit: int = 200) -> list[dict[str, Any]]:
    rows = (
        db.execute(
            text(
                """
                SELECT
                  ap.approval_id,
                  ap.run_action_id,
                  ap.required_role,
                  ap.risk_tier,
                  ap.status,
                  ap.requested_by,
                  ap.approved_by,
                  ap.rejected_by,
                  ap.reason,
                  ap.decision_note,
                  ap.created_at,
                  ap.decided_at,
                  ara.run_id,
                  ara.action_type,
                  ara.params_json
                FROM automation_approvals ap
                JOIN automation_run_actions ara ON ara.run_action_id = ap.run_action_id
                WHERE ap.status = 'pending'
                ORDER BY ap.created_at ASC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(int(limit), 1000))},
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        item = _serialize(dict(row))
        params_value = item.get("params_json")
        if isinstance(params_value, str):
            try:
                item["params_json"] = json.loads(params_value)
            except json.JSONDecodeError:
                item["params_json"] = {}
        items.append(item)
    return items


__all__ = ["create_approval_request", "decide_approval", "list_pending_approvals"]
