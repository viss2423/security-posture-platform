"""Notification adapters for automation actions."""

from __future__ import annotations

import logging
import threading
from typing import Any

import httpx

from .settings import settings

logger = logging.getLogger(__name__)


def send_slack_notification(
    *,
    text: str,
    blocks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    webhook = str(getattr(settings, "SLACK_WEBHOOK_URL", "") or "").strip()
    if not webhook:
        return {
            "delivered": False,
            "provider": "slack",
            "reason": "slack_webhook_not_configured",
        }
    payload: dict[str, Any] = {"text": text or "SecPlat automation notification"}
    if blocks:
        payload["blocks"] = blocks
    with httpx.Client(timeout=10.0) as client:
        response = client.post(webhook, json=payload)
    return {
        "delivered": response.status_code < 300,
        "provider": "slack",
        "status_code": int(response.status_code),
        "response_text": response.text[:500],
    }


def send_discord_notification(*, text: str) -> dict[str, Any]:
    webhook = str(getattr(settings, "DISCORD_WEBHOOK_URL", "") or "").strip()
    if not webhook:
        return {
            "delivered": False,
            "provider": "discord",
            "reason": "discord_webhook_not_configured",
        }
    # Discord hard-caps webhook message content at 2000 characters.
    payload: dict[str, Any] = {"content": (text or "SecPlat notification")[:1900]}
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook, json=payload)
    except Exception as exc:  # best-effort adapter; never raise into the caller
        logger.warning("discord_notification_failed error=%s", exc)
        return {"delivered": False, "provider": "discord", "reason": "request_failed"}
    return {
        "delivered": response.status_code < 300,
        "provider": "discord",
        "status_code": int(response.status_code),
        "response_text": response.text[:500],
    }


def _deliver_critical_finding(message: str, slack_url: str, discord_url: str) -> None:
    """Fan a critical-finding alert out to every configured channel.

    Runs on a background daemon thread. Each channel is independent and best-effort; a failure
    on one never blocks or fails the other, and nothing raises out of this function.
    """
    if slack_url:
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(slack_url, json={"text": message})
        except Exception as exc:
            logger.warning("critical_finding_slack_failed error=%s", exc)
    if discord_url:
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(discord_url, json={"content": message[:1900]})
        except Exception as exc:
            logger.warning("critical_finding_discord_failed error=%s", exc)


def notify_new_critical_finding(
    *,
    finding_key: str,
    title: str,
    asset_key: str,
    severity: str = "critical",
    source: str | None = None,
) -> bool:
    """Best-effort chat alert for a newly-detected critical finding.

    Config-gated: if neither SLACK_WEBHOOK_URL nor DISCORD_WEBHOOK_URL is set this is a no-op —
    no thread is spawned and no outbound request is made. Delivery runs on a background daemon
    thread so the caller (scan job or finding upsert) never blocks on outbound HTTP. Never raises.

    The message deliberately carries only the finding title, asset, source and key — never the
    finding evidence — to avoid leaking sensitive detail into a chat channel. Returns True when a
    delivery was dispatched (a channel is configured), False when it was skipped.
    """
    slack_url = str(getattr(settings, "SLACK_WEBHOOK_URL", "") or "").strip()
    discord_url = str(getattr(settings, "DISCORD_WEBHOOK_URL", "") or "").strip()
    if not slack_url and not discord_url:
        return False
    lines = [
        "\U0001f6a8 SecPlat — new CRITICAL finding",
        f"• {title}",
        f"• Asset: {asset_key}",
    ]
    if source:
        lines.append(f"• Source: {source}")
    lines.append(f"• Finding: {finding_key}")
    message = "\n".join(lines)
    threading.Thread(
        target=_deliver_critical_finding,
        args=(message, slack_url, discord_url),
        daemon=True,
        name="secplat-critical-alert",
    ).start()
    return True


__all__ = [
    "send_slack_notification",
    "send_discord_notification",
    "notify_new_critical_finding",
]
