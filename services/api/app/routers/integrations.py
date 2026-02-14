"""Integrations: Slack interactive, Jira from incident (Phase B.4), WhatsApp (Twilio)."""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.settings import settings

router = APIRouter(prefix="/integrations", tags=["integrations"])


def _verify_twilio_signature(url: str, params: dict, signature: str | None) -> bool:
    """Twilio: HMAC-SHA1 of url + sorted params, base64, compare to X-Twilio-Signature."""
    token = (getattr(settings, "TWILIO_AUTH_TOKEN", None) or "").encode("utf-8")
    if not token or not signature:
        return False
    sorted_params = urlencode(sorted(params.items()), safe="")
    payload = url + sorted_params
    expected = base64.b64encode(hmac.new(token, payload.encode("utf-8"), hashlib.sha1).digest()).decode()
    return hmac.compare_digest(signature, expected)


def _verify_slack_signature(body: bytes, signature: str | None, timestamp: str | None) -> bool:
    """Verify X-Slack-Signature (v0=hex) and reject if timestamp older than 5 min."""
    secret = getattr(settings, "SLACK_SIGNING_SECRET", None) or ""
    if not secret or not signature or not timestamp:
        return False
    try:
        import time
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except ValueError:
        return False
    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    expected = "v0=" + hmac.new(
        secret.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _create_jira_for_incident(incident_id: int, db: Session) -> tuple[str, str] | None:
    """Create Jira issue for incident; update metadata. Returns (issue_key, url) or None if config missing."""
    from app.routers.incidents import _jira_create_issue

    project_key = (getattr(settings, "JIRA_PROJECT_KEY", None) or "").strip().upper()
    if not project_key:
        return None
    q = text("SELECT id, title, severity, status, metadata FROM incidents WHERE id = :id")
    row = db.execute(q, {"id": incident_id}).mappings().first()
    if not row:
        return None
    incident = dict(row)
    meta = incident.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta) if meta else {}
        except Exception:
            meta = {}
    if meta.get("jira_issue_key"):
        return (meta["jira_issue_key"], meta.get("jira_issue_url") or "")

    alerts_q = text("SELECT asset_key FROM incident_alerts WHERE incident_id = :id")
    alerts = db.execute(alerts_q, {"id": incident_id}).mappings().all()
    incident["alerts"] = [{"asset_key": a["asset_key"]} for a in alerts]
    frontend_url = (getattr(settings, "FRONTEND_URL", None) or "http://localhost:3000").rstrip("/")
    try:
        issue_key, browse_url = _jira_create_issue(incident, project_key, frontend_url)
    except (HTTPException, Exception):
        return None
    new_meta = {**meta, "jira_issue_key": issue_key, "jira_issue_url": browse_url}
    db.execute(
        text("UPDATE incidents SET metadata = :meta, updated_at = :now WHERE id = :id"),
        {"meta": json.dumps(new_meta), "now": datetime.now(timezone.utc), "id": incident_id},
    )
    db.commit()
    return (issue_key, browse_url)


@router.post("/slack/interactions", response_class=Response)
async def slack_interactions(request: Request, db: Session = Depends(get_db)):
    """
    Slack interactive components endpoint. Verifies SLACK_SIGNING_SECRET, handles block_actions.
    Action 'create_jira' with value=incident_id creates a Jira ticket and returns updated message.
    """
    body = await request.body()
    signature = request.headers.get("x-slack-signature") or request.headers.get("X-Slack-Signature")
    timestamp = request.headers.get("x-slack-request-timestamp") or request.headers.get("X-Slack-Request-Timestamp")
    if not _verify_slack_signature(body, signature, timestamp):
        return PlainTextResponse("Invalid signature", status_code=401)

    # Slack sends application/x-www-form-urlencoded with payload=...
    content_type = request.headers.get("content-type") or ""
    if "application/x-www-form-urlencoded" in content_type:
        from urllib.parse import parse_qs
        parsed = parse_qs(body.decode("utf-8"))
        payload_str = (parsed.get("payload") or [None])[0]
        if not payload_str:
            return PlainTextResponse("Missing payload", status_code=400)
        payload = json.loads(payload_str)
    else:
        payload = json.loads(body)

    if payload.get("type") == "block_actions":
        actions = payload.get("actions") or []
        for act in actions:
            if act.get("action_id") == "create_jira":
                value = act.get("value")
                try:
                    incident_id = int(value)
                except (TypeError, ValueError):
                    return PlainTextResponse("Invalid incident_id", status_code=400)
                result = _create_jira_for_incident(incident_id, db)
                if result is None:
                    return PlainTextResponse("Jira not configured or incident not found", status_code=200)
                issue_key, url = result
                # Optionally update the message via response_url
                response_url = payload.get("response_url")
                if response_url:
                    import httpx
                    with httpx.Client(timeout=5.0) as client:
                        client.post(
                            response_url,
                            json={
                                "replace_original": True,
                                "text": f"Jira ticket created: {issue_key}",
                                "blocks": [
                                    {
                                        "type": "section",
                                        "text": {"type": "mrkdwn", "text": f"*Jira ticket created:* <{url}|{issue_key}>"},
                                    }
                                ],
                            },
                        )
                return PlainTextResponse("", status_code=200)

    return PlainTextResponse("", status_code=200)


@router.post("/whatsapp/incoming")
async def whatsapp_incoming(request: Request):
    """
    Twilio WhatsApp webhook: receives incoming messages. Configure in Twilio Console as WhatsApp Sandbox/Messaging webhook.
    Optionally validates X-Twilio-Signature if TWILIO_AUTH_TOKEN is set. Returns 200 with empty body (or TwiML to reply).
    """
    form = await request.form()
    params = dict(form)
    signature = request.headers.get("X-Twilio-Signature") or request.headers.get("x-twilio-signature")
    url = str(request.url)
    if getattr(settings, "TWILIO_AUTH_TOKEN", None) and signature:
        if not _verify_twilio_signature(url, params, signature):
            return PlainTextResponse("Invalid signature", status_code=403)
    return PlainTextResponse("", status_code=200)
