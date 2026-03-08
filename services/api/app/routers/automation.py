"""Automation playbooks, runs, approvals, and rollbacks."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.approval_service import create_approval_request, decide_approval, list_pending_approvals
from app.audit import log_audit
from app.automation_executor import execute_run_action, update_run_status
from app.db import get_db
from app.playbook_engine import (
    SUPPORTED_ACTIONS,
    SUPPORTED_TRIGGERS,
    evaluate_playbook,
    load_enabled_playbooks,
    normalize_playbook_row,
)
from app.request_context import request_id_ctx
from app.rollback_service import execute_rollback, list_rollbacks
from app.routers.auth import get_current_role, require_auth, require_role

router = APIRouter(prefix="/automation", tags=["automation"])


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


def _serialize_run(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["trigger_payload_json"] = _safe_json(out.get("trigger_payload_json"), default={})
    out["summary_json"] = _safe_json(out.get("summary_json"), default={})
    return out


def _serialize_action(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("created_at", "started_at", "finished_at"):
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    out["params_json"] = _safe_json(out.get("params_json"), default={})
    out["result_json"] = _safe_json(out.get("result_json"), default={})
    return out


def _load_run_actions(db: Session, run_id: int) -> list[dict[str, Any]]:
    rows = (
        db.execute(
            text(
                """
                SELECT
                  run_action_id,
                  run_id,
                  action_index,
                  action_type,
                  risk_tier,
                  status,
                  params_json,
                  result_json,
                  error,
                  created_at,
                  started_at,
                  finished_at
                FROM automation_run_actions
                WHERE run_id = :run_id
                ORDER BY action_index ASC
                """
            ),
            {"run_id": int(run_id)},
        )
        .mappings()
        .all()
    )
    return [_serialize_action(dict(row)) for row in rows]


def _ensure_trigger(trigger: str) -> str:
    normalized = str(trigger or "").strip().lower()
    if normalized not in SUPPORTED_TRIGGERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported trigger. Use one of: {sorted(SUPPORTED_TRIGGERS)}",
        )
    return normalized


class PlaybookBody(BaseModel):
    title: str
    description: str | None = None
    trigger: str
    conditions: list[dict] = []
    actions: list[dict] = []
    approval_required: bool = False
    rollback_steps: list[dict] = []
    enabled: bool = True


class PlaybookUpdateBody(BaseModel):
    description: str | None = None
    trigger: str | None = None
    conditions: list[dict] | None = None
    actions: list[dict] | None = None
    approval_required: bool | None = None
    rollback_steps: list[dict] | None = None
    enabled: bool | None = None


@router.get("/playbooks")
def list_playbooks(
    include_disabled: bool = Query(True),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    where = "" if include_disabled else "WHERE enabled = TRUE"
    rows = (
        db.execute(
            text(
                f"""
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
                {where}
                ORDER BY updated_at DESC, playbook_id DESC
                """
            )
        )
        .mappings()
        .all()
    )
    return {"items": [normalize_playbook_row(dict(row)) for row in rows]}


@router.post("/playbooks", status_code=201)
def create_playbook(
    body: PlaybookBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    title = (body.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title required")
    trigger = _ensure_trigger(body.trigger)
    actions = [dict(item or {}) for item in body.actions]
    unsupported_actions = sorted(
        {
            str(item.get("type") or "").strip().lower()
            for item in actions
            if str(item.get("type") or "").strip().lower() not in SUPPORTED_ACTIONS
        }
    )
    if unsupported_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported actions: {unsupported_actions}",
        )
    row = (
        db.execute(
            text(
                """
                INSERT INTO automation_playbooks (
                  title,
                  description,
                  trigger,
                  conditions_json,
                  actions_json,
                  approval_required,
                  rollback_steps_json,
                  enabled,
                  created_by,
                  updated_at
                )
                VALUES (
                  :title,
                  :description,
                  :trigger,
                  CAST(:conditions_json AS jsonb),
                  CAST(:actions_json AS jsonb),
                  :approval_required,
                  CAST(:rollback_steps_json AS jsonb),
                  :enabled,
                  :created_by,
                  NOW()
                )
                RETURNING
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
                """
            ),
            {
                "title": title,
                "description": (body.description or "").strip() or None,
                "trigger": trigger,
                "conditions_json": json.dumps(body.conditions or []),
                "actions_json": json.dumps(actions),
                "approval_required": bool(body.approval_required),
                "rollback_steps_json": json.dumps(body.rollback_steps or []),
                "enabled": bool(body.enabled),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create playbook")
    out = normalize_playbook_row(dict(row))
    log_audit(
        db,
        "automation.playbook.create",
        user_name=user,
        details={"playbook_id": int(out["playbook_id"]), "title": out.get("title")},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.patch("/playbooks/{playbook_id}")
def update_playbook(
    playbook_id: int,
    body: PlaybookUpdateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    current = (
        db.execute(
            text("SELECT * FROM automation_playbooks WHERE playbook_id = :playbook_id"),
            {"playbook_id": int(playbook_id)},
        )
        .mappings()
        .first()
    )
    if not current:
        raise HTTPException(status_code=404, detail="Playbook not found")
    trigger = _ensure_trigger(body.trigger) if body.trigger is not None else str(current["trigger"])
    actions = (
        [dict(item or {}) for item in (body.actions or [])]
        if body.actions is not None
        else _safe_json(current.get("actions_json"), default=[])
    )
    unsupported_actions = sorted(
        {
            str(item.get("type") or "").strip().lower()
            for item in actions
            if str(item.get("type") or "").strip().lower() not in SUPPORTED_ACTIONS
        }
    )
    if unsupported_actions:
        raise HTTPException(status_code=400, detail=f"Unsupported actions: {unsupported_actions}")
    row = (
        db.execute(
            text(
                """
                UPDATE automation_playbooks
                SET
                  description = :description,
                  trigger = :trigger,
                  conditions_json = CAST(:conditions_json AS jsonb),
                  actions_json = CAST(:actions_json AS jsonb),
                  approval_required = :approval_required,
                  rollback_steps_json = CAST(:rollback_steps_json AS jsonb),
                  enabled = :enabled,
                  updated_at = NOW()
                WHERE playbook_id = :playbook_id
                RETURNING
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
                """
            ),
            {
                "playbook_id": int(playbook_id),
                "description": (
                    body.description if body.description is not None else current.get("description")
                ),
                "trigger": trigger,
                "conditions_json": json.dumps(
                    body.conditions
                    if body.conditions is not None
                    else _safe_json(current.get("conditions_json"), default=[])
                ),
                "actions_json": json.dumps(actions),
                "approval_required": (
                    bool(body.approval_required)
                    if body.approval_required is not None
                    else bool(current.get("approval_required"))
                ),
                "rollback_steps_json": json.dumps(
                    body.rollback_steps
                    if body.rollback_steps is not None
                    else _safe_json(current.get("rollback_steps_json"), default=[])
                ),
                "enabled": bool(body.enabled)
                if body.enabled is not None
                else bool(current.get("enabled")),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to update playbook")
    out = normalize_playbook_row(dict(row))
    log_audit(
        db,
        "automation.playbook.update",
        user_name=user,
        details={"playbook_id": int(playbook_id)},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


class TriggerRunBody(BaseModel):
    trigger: str
    payload: dict = {}
    playbook_ids: list[int] | None = None


@router.post("/runs/trigger")
def trigger_playbook_runs(
    body: TriggerRunBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    trigger = _ensure_trigger(body.trigger)
    payload = dict(body.payload or {})
    payload.setdefault("trigger", trigger)
    playbooks = load_enabled_playbooks(db, trigger=trigger)
    if body.playbook_ids:
        target_ids = {int(item) for item in body.playbook_ids if int(item) > 0}
        playbooks = [item for item in playbooks if int(item.get("playbook_id") or 0) in target_ids]
    run_results: list[dict[str, Any]] = []
    for playbook in playbooks:
        evaluation = evaluate_playbook(playbook=playbook, trigger_payload=payload)
        matched = bool(evaluation.get("matched"))
        run_row = (
            db.execute(
                text(
                    """
                    INSERT INTO automation_runs (
                      playbook_id,
                      trigger_source,
                      trigger_payload_json,
                      matched,
                      status,
                      requested_by,
                      summary_json
                    )
                    VALUES (
                      :playbook_id,
                      :trigger_source,
                      CAST(:trigger_payload_json AS jsonb),
                      :matched,
                      :status,
                      :requested_by,
                      CAST(:summary_json AS jsonb)
                    )
                    RETURNING
                      run_id,
                      playbook_id,
                      trigger_source,
                      trigger_payload_json,
                      matched,
                      status,
                      requested_by,
                      started_at,
                      finished_at,
                      error,
                      summary_json
                    """
                ),
                {
                    "playbook_id": int(playbook.get("playbook_id") or 0),
                    "trigger_source": trigger,
                    "trigger_payload_json": json.dumps(payload),
                    "matched": matched,
                    "status": "running" if matched else "done",
                    "requested_by": user,
                    "summary_json": json.dumps(
                        {
                            "playbook_title": playbook.get("title"),
                            "condition_result": evaluation.get("condition_result"),
                        }
                    ),
                },
            )
            .mappings()
            .first()
        )
        if not run_row:
            continue
        run_id = int(run_row["run_id"])
        action_results: list[dict[str, Any]] = []
        if matched:
            for action in evaluation.get("actions") or []:
                status = "pending"
                if not action.get("supported"):
                    status = "failed"
                elif action.get("requires_approval_role"):
                    status = "pending_approval"
                action_row = (
                    db.execute(
                        text(
                            """
                            INSERT INTO automation_run_actions (
                              run_id,
                              action_index,
                              action_type,
                              risk_tier,
                              status,
                              params_json,
                              result_json
                            )
                            VALUES (
                              :run_id,
                              :action_index,
                              :action_type,
                              :risk_tier,
                              :status,
                              CAST(:params_json AS jsonb),
                              '{}'::jsonb
                            )
                            RETURNING run_action_id
                            """
                        ),
                        {
                            "run_id": run_id,
                            "action_index": int(action.get("action_index") or 0),
                            "action_type": str(action.get("action_type") or ""),
                            "risk_tier": str(action.get("risk_tier") or "low"),
                            "status": status,
                            "params_json": json.dumps(action.get("params") or {}),
                        },
                    )
                    .mappings()
                    .first()
                )
                if not action_row:
                    continue
                run_action_id = int(action_row["run_action_id"])
                if status == "failed":
                    db.execute(
                        text(
                            """
                            UPDATE automation_run_actions
                            SET
                              error = :error,
                              finished_at = NOW()
                            WHERE run_action_id = :run_action_id
                            """
                        ),
                        {
                            "run_action_id": run_action_id,
                            "error": "unsupported_action_type",
                        },
                    )
                    action_results.append(
                        {
                            "run_action_id": run_action_id,
                            "status": "failed",
                            "error": "unsupported_action_type",
                        }
                    )
                    continue
                if status == "pending_approval":
                    approval = create_approval_request(
                        db,
                        run_action_id=run_action_id,
                        risk_tier=str(action.get("risk_tier") or "medium"),
                        requested_by=user,
                        reason="playbook_action_requires_approval",
                    )
                    action_results.append(
                        {
                            "run_action_id": run_action_id,
                            "status": "pending_approval",
                            "approval_id": approval.get("approval_id"),
                            "required_role": approval.get("required_role"),
                        }
                    )
                    continue
                execution = execute_run_action(
                    db,
                    run_action_id=run_action_id,
                    actor=user,
                    trigger_payload=payload,
                )
                action_results.append(execution)
            run_status = update_run_status(db, run_id=run_id)
            if run_status == "done":
                db.execute(
                    text(
                        """
                        UPDATE automation_runs
                        SET summary_json = CAST(:summary_json AS jsonb)
                        WHERE run_id = :run_id
                        """
                    ),
                    {
                        "run_id": run_id,
                        "summary_json": json.dumps(
                            {
                                "playbook_title": playbook.get("title"),
                                "condition_result": evaluation.get("condition_result"),
                                "actions": action_results,
                            }
                        ),
                    },
                )
        serialized_run = _serialize_run(dict(run_row))
        serialized_run["actions"] = _load_run_actions(db, run_id)
        run_results.append(serialized_run)
    log_audit(
        db,
        "automation.run.trigger",
        user_name=user,
        details={"trigger": trigger, "runs_created": len(run_results)},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"trigger": trigger, "runs_created": len(run_results), "items": run_results}


@router.get("/runs")
def list_runs(
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1"]
    params: dict[str, Any] = {"limit": int(limit)}
    if status:
        clauses.append("r.status = :status")
        params["status"] = str(status).strip().lower()
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  r.run_id,
                  r.playbook_id,
                  p.title AS playbook_title,
                  r.trigger_source,
                  r.trigger_payload_json,
                  r.matched,
                  r.status,
                  r.requested_by,
                  r.started_at,
                  r.finished_at,
                  r.error,
                  r.summary_json
                FROM automation_runs r
                JOIN automation_playbooks p ON p.playbook_id = r.playbook_id
                WHERE {where}
                ORDER BY r.started_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_run(dict(row)) for row in rows]}


@router.get("/runs/{run_id}")
def get_run(
    run_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = (
        db.execute(
            text(
                """
                SELECT
                  r.run_id,
                  r.playbook_id,
                  p.title AS playbook_title,
                  r.trigger_source,
                  r.trigger_payload_json,
                  r.matched,
                  r.status,
                  r.requested_by,
                  r.started_at,
                  r.finished_at,
                  r.error,
                  r.summary_json
                FROM automation_runs r
                JOIN automation_playbooks p ON p.playbook_id = r.playbook_id
                WHERE r.run_id = :run_id
                """
            ),
            {"run_id": int(run_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Automation run not found")
    out = _serialize_run(dict(row))
    out["actions"] = _load_run_actions(db, int(run_id))
    return out


@router.get("/approvals")
def list_approvals(
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    return {"items": list_pending_approvals(db, limit=limit)}


class ApprovalDecisionBody(BaseModel):
    note: str | None = None


@router.post("/approvals/{approval_id}/approve")
def approve_action(
    approval_id: int,
    body: ApprovalDecisionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
    role: str = Depends(get_current_role),
):
    current = (
        db.execute(
            text(
                """
                SELECT
                  ap.approval_id,
                  ap.run_action_id,
                  ap.required_role,
                  ap.status,
                  ara.run_id
                FROM automation_approvals ap
                JOIN automation_run_actions ara ON ara.run_action_id = ap.run_action_id
                WHERE ap.approval_id = :approval_id
                """
            ),
            {"approval_id": int(approval_id)},
        )
        .mappings()
        .first()
    )
    if not current:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if str(current.get("status") or "") != "pending":
        raise HTTPException(status_code=400, detail="Approval is not pending")
    required_role = str(current.get("required_role") or "analyst")
    if required_role == "admin" and role != "admin":
        raise HTTPException(status_code=403, detail="Admin approval required")
    if required_role == "analyst" and role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Analyst approval required")
    decided = decide_approval(
        db,
        approval_id=int(approval_id),
        decision="approved",
        actor=user,
        note=body.note,
    )
    if not decided:
        raise HTTPException(status_code=500, detail="Failed to approve action")
    db.execute(
        text(
            """
            UPDATE automation_run_actions
            SET status = 'approved'
            WHERE run_action_id = :run_action_id
            """
        ),
        {"run_action_id": int(current.get("run_action_id") or 0)},
    )
    execution = execute_run_action(
        db,
        run_action_id=int(current.get("run_action_id") or 0),
        actor=user,
    )
    run_status = update_run_status(db, run_id=int(current.get("run_id") or 0))
    log_audit(
        db,
        "automation.approval.approve",
        user_name=user,
        details={
            "approval_id": int(approval_id),
            "run_action_id": int(current.get("run_action_id") or 0),
            "run_id": int(current.get("run_id") or 0),
            "run_status": run_status,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"approval": decided, "execution": execution, "run_status": run_status}


@router.post("/approvals/{approval_id}/reject")
def reject_action(
    approval_id: int,
    body: ApprovalDecisionBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
    role: str = Depends(get_current_role),
):
    current = (
        db.execute(
            text(
                """
                SELECT
                  ap.approval_id,
                  ap.run_action_id,
                  ap.required_role,
                  ap.status,
                  ara.run_id
                FROM automation_approvals ap
                JOIN automation_run_actions ara ON ara.run_action_id = ap.run_action_id
                WHERE ap.approval_id = :approval_id
                """
            ),
            {"approval_id": int(approval_id)},
        )
        .mappings()
        .first()
    )
    if not current:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if str(current.get("status") or "") != "pending":
        raise HTTPException(status_code=400, detail="Approval is not pending")
    required_role = str(current.get("required_role") or "analyst")
    if required_role == "admin" and role != "admin":
        raise HTTPException(status_code=403, detail="Admin approval required")
    if required_role == "analyst" and role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Analyst approval required")
    decided = decide_approval(
        db,
        approval_id=int(approval_id),
        decision="rejected",
        actor=user,
        note=body.note,
    )
    if not decided:
        raise HTTPException(status_code=500, detail="Failed to reject action")
    db.execute(
        text(
            """
            UPDATE automation_run_actions
            SET status = 'rejected', error = :error, finished_at = NOW()
            WHERE run_action_id = :run_action_id
            """
        ),
        {
            "run_action_id": int(current.get("run_action_id") or 0),
            "error": "approval_rejected",
        },
    )
    run_status = update_run_status(db, run_id=int(current.get("run_id") or 0))
    log_audit(
        db,
        "automation.approval.reject",
        user_name=user,
        details={
            "approval_id": int(approval_id),
            "run_action_id": int(current.get("run_action_id") or 0),
            "run_id": int(current.get("run_id") or 0),
            "run_status": run_status,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"approval": decided, "run_status": run_status}


@router.get("/rollbacks")
def list_rollback_items(
    status: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    return {"items": list_rollbacks(db, status=status, limit=limit)}


@router.post("/rollbacks/{rollback_id}/execute")
def execute_rollback_item(
    rollback_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    row = (
        db.execute(
            text(
                """
                SELECT ar.rollback_id, ara.run_id
                FROM automation_rollbacks ar
                JOIN automation_run_actions ara ON ara.run_action_id = ar.run_action_id
                WHERE ar.rollback_id = :rollback_id
                """
            ),
            {"rollback_id": int(rollback_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Rollback record not found")
    result = execute_rollback(db, rollback_id=int(rollback_id), actor=user)
    if not result:
        raise HTTPException(status_code=404, detail="Rollback record not found")
    run_status = update_run_status(db, run_id=int(row.get("run_id") or 0))
    log_audit(
        db,
        "automation.rollback.execute",
        user_name=user,
        details={
            "rollback_id": int(rollback_id),
            "run_id": int(row.get("run_id") or 0),
            "status": result.get("status"),
            "run_status": run_status,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"rollback": result, "run_status": run_status}
