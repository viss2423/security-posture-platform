"""Notification adapters for automation actions."""

from __future__ import annotations

from typing import Any

import httpx

from .settings import settings


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


__all__ = ["send_slack_notification"]
