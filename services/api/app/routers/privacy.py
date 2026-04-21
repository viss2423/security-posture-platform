"""Privacy/DSAR operations: export and pseudonymize subject data."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_role

router = APIRouter(prefix="/privacy", tags=["privacy"])


class DsarExportRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    include_samples: bool = False
    sample_limit: int = Field(default=20, ge=1, le=200)


class DsarDeleteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    execute: bool = False


_EXPORT_SOURCES = (
    {
        "name": "users",
        "count_sql": "SELECT COUNT(*) FROM users WHERE username = :username",
        "sample_sql": """
            SELECT username, role, disabled, created_at
            FROM users
            WHERE username = :username
            ORDER BY created_at DESC
            LIMIT :limit
        """,
    },
    {
        "name": "auth_refresh_tokens",
        "count_sql": "SELECT COUNT(*) FROM auth_refresh_tokens WHERE username = :username",
        "sample_sql": """
            SELECT id, username, issued_at, expires_at, revoked_at, revoked_reason, client_ip, user_agent
            FROM auth_refresh_tokens
            WHERE username = :username
            ORDER BY issued_at DESC
            LIMIT :limit
        """,
    },
    {
        "name": "audit_events",
        "count_sql": "SELECT COUNT(*) FROM audit_events WHERE user_name = :username",
        "sample_sql": """
            SELECT id, created_at, action, request_id, details
            FROM audit_events
            WHERE user_name = :username
            ORDER BY created_at DESC
            LIMIT :limit
        """,
    },
    {
        "name": "incident_notes",
        "count_sql": "SELECT COUNT(*) FROM incident_notes WHERE author = :username",
        "sample_sql": """
            SELECT id, incident_id, event_type, author, created_at
            FROM incident_notes
            WHERE author = :username
            ORDER BY created_at DESC
            LIMIT :limit
        """,
    },
    {
        "name": "scan_jobs",
        "count_sql": "SELECT COUNT(*) FROM scan_jobs WHERE requested_by = :username",
        "sample_sql": """
            SELECT job_id, job_type, requested_by, status, created_at
            FROM scan_jobs
            WHERE requested_by = :username
            ORDER BY created_at DESC
            LIMIT :limit
        """,
    },
)

_PSEUDONYMIZE_TARGETS = (
    ("audit_events", "user_name"),
    ("incident_notes", "author"),
    ("incident_watchers", "username"),
    ("incident_checklist_items", "done_by"),
    ("incident_checklist_items", "created_by"),
    ("incident_decisions", "decided_by"),
    ("incident_evidence", "added_by"),
    ("incident_auto_rules", "created_by"),
    ("incident_alerts", "added_by"),
    ("scan_jobs", "requested_by"),
    ("alert_states", "acked_by"),
    ("alert_states", "assigned_to"),
    ("security_alerts", "acknowledged_by"),
    ("security_alerts", "resolved_by"),
    ("security_alerts", "assigned_to"),
    ("automation_runs", "requested_by"),
    ("automation_rollbacks", "requested_by"),
    ("automation_rollbacks", "executed_by"),
    ("automation_playbooks", "created_by"),
)


def _normalize_username(username: str) -> str:
    return (username or "").strip()


def _pseudonym_for(username: str) -> str:
    digest = hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]
    return f"deleted-user-{digest}"


def _table_column_exists(db: Session, table_name: str, column_name: str) -> bool:
    row = (
        db.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = :table_name
                  AND column_name = :column_name
                """
            ),
            {"table_name": table_name, "column_name": column_name},
        )
        .mappings()
        .first()
    )
    return row is not None


def _rows_for_export(
    db: Session,
    *,
    username: str,
    include_samples: bool,
    sample_limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in _EXPORT_SOURCES:
        count = int(db.execute(text(source["count_sql"]), {"username": username}).scalar_one() or 0)
        row: dict[str, Any] = {
            "source": source["name"],
            "count": count,
        }
        if include_samples and count > 0:
            samples = (
                db.execute(
                    text(source["sample_sql"]),
                    {"username": username, "limit": int(sample_limit)},
                )
                .mappings()
                .all()
            )
            row["samples"] = [dict(sample) for sample in samples]
        rows.append(row)
    return rows


def _count_matches(db: Session, table_name: str, column_name: str, username: str) -> int:
    query = text(f"SELECT COUNT(*) FROM {table_name} WHERE {column_name} = :username")  # nosemgrep
    return int(db.execute(query, {"username": username}).scalar_one() or 0)


def _pseudonymize_column(
    db: Session,
    *,
    table_name: str,
    column_name: str,
    username: str,
    replacement: str,
) -> int:
    query = text(  # nosemgrep
        f"UPDATE {table_name} SET {column_name} = :replacement WHERE {column_name} = :username"
    )
    result = db.execute(query, {"replacement": replacement, "username": username})
    return int(result.rowcount or 0)


@router.post("/dsar/export")
def dsar_export(
    body: DsarExportRequest,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin"])),
) -> dict[str, Any]:
    username = _normalize_username(body.username)
    rows = _rows_for_export(
        db,
        username=username,
        include_samples=bool(body.include_samples),
        sample_limit=int(body.sample_limit),
    )
    total = sum(int(row["count"]) for row in rows)
    req_id = request_id_ctx.get("") or None
    log_audit(
        db,
        "privacy.dsar_export",
        user_name=_user,
        details={
            "subject_username": username,
            "sources": [{"source": row["source"], "count": row["count"]} for row in rows],
            "total_records": total,
            "include_samples": bool(body.include_samples),
        },
        request_id=req_id,
    )
    db.commit()
    return {
        "subject_username": username,
        "total_records": total,
        "sources": rows,
    }


@router.post("/dsar/delete")
def dsar_delete(
    body: DsarDeleteRequest,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin"])),
) -> dict[str, Any]:
    username = _normalize_username(body.username)
    replacement = _pseudonym_for(username)
    req_id = request_id_ctx.get("") or None

    actions: list[dict[str, Any]] = []
    for table_name, column_name in _PSEUDONYMIZE_TARGETS:
        if not _table_column_exists(db, table_name, column_name):
            continue
        matched = _count_matches(db, table_name, column_name, username)
        rewritten = 0
        if bool(body.execute) and matched > 0:
            rewritten = _pseudonymize_column(
                db,
                table_name=table_name,
                column_name=column_name,
                username=username,
                replacement=replacement,
            )
        actions.append(
            {
                "action": "pseudonymize",
                "table": table_name,
                "column": column_name,
                "matched_rows": matched,
                "updated_rows": rewritten,
            }
        )

    auth_token_rows = _count_matches(db, "auth_refresh_tokens", "username", username)
    deleted_tokens = 0
    if bool(body.execute) and auth_token_rows > 0:
        deleted_tokens = int(
            db.execute(
                text("DELETE FROM auth_refresh_tokens WHERE username = :username"),
                {"username": username},
            ).rowcount
            or 0
        )
    actions.append(
        {
            "action": "delete",
            "table": "auth_refresh_tokens",
            "column": "username",
            "matched_rows": auth_token_rows,
            "deleted_rows": deleted_tokens,
        }
    )

    user_rows = _count_matches(db, "users", "username", username)
    rewritten_users = 0
    if bool(body.execute) and user_rows > 0:
        rewritten_users = int(
            db.execute(
                text(
                    """
                    UPDATE users
                    SET username = :replacement,
                        disabled = TRUE,
                        password_hash = NULL
                    WHERE username = :username
                    """
                ),
                {"username": username, "replacement": replacement},
            ).rowcount
            or 0
        )
    actions.append(
        {
            "action": "pseudonymize_account",
            "table": "users",
            "column": "username",
            "matched_rows": user_rows,
            "updated_rows": rewritten_users,
        }
    )

    log_audit(
        db,
        "privacy.dsar_delete",
        user_name=_user,
        details={
            "subject_username": username,
            "execute": bool(body.execute),
            "replacement_username": replacement if bool(body.execute) else "",
            "actions": actions,
        },
        request_id=req_id,
    )
    db.commit()
    return {
        "subject_username": username,
        "execute": bool(body.execute),
        "replacement_username": replacement if bool(body.execute) else "",
        "actions": actions,
    }
