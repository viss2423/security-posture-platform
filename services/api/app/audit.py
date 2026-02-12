"""Persist audit events to DB for audit log UI."""
from sqlalchemy import text
from sqlalchemy.orm import Session


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
    import json
    db.execute(q, {
        "action": action,
        "user_name": user_name,
        "asset_key": asset_key,
        "details": json.dumps(details or {}),
        "request_id": request_id,
    })
