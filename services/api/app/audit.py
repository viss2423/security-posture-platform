"""Persist audit events to DB for audit log UI."""

import json
import logging
import time

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("secplat.audit")


def _is_retryable_audit_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "deadlock detected" in message
        or "serialization failure" in message
        or "current transaction is aborted" in message
    )


def log_audit(
    db: Session,
    action: str,
    user_name: str | None = None,
    asset_key: str | None = None,
    details: dict | None = None,
    request_id: str | None = None,
) -> None:
    """Append an audit event. Caller should not commit; they manage transaction."""
    q = text("""
        INSERT INTO audit_events (action, user_name, asset_key, details, request_id)
        VALUES (:action, :user_name, :asset_key, CAST(:details AS jsonb), :request_id)
    """)
    params = {
        "action": action,
        "user_name": user_name,
        "asset_key": asset_key,
        "details": json.dumps(details or {}),
        "request_id": request_id,
    }
    retries = 3
    for attempt in range(retries + 1):
        try:
            # Keep audit insert isolated from caller transaction to avoid
            # bubbling transient lock contention into API failures.
            with db.begin_nested():
                db.execute(q, params)
            return
        except Exception as exc:
            if _is_retryable_audit_error(exc) and attempt < retries:
                time.sleep(0.05 * (2**attempt))
                continue
            logger.warning(
                "audit_write_failed action=%s request_id=%s error=%s",
                action,
                request_id,
                exc,
            )
            return
