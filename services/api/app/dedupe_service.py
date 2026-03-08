"""Alert deduplication helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def summarize_alert_deduplication(alert_row: dict[str, Any]) -> dict[str, Any]:
    first_seen = alert_row.get("first_seen_at")
    last_seen = alert_row.get("last_seen_at")
    event_count = max(1, int(alert_row.get("event_count") or 1))

    window_minutes: float | None = None
    recurrence_per_hour: float | None = None
    if isinstance(first_seen, datetime) and isinstance(last_seen, datetime):
        seconds = max((last_seen - first_seen).total_seconds(), 0.0)
        window_minutes = round(seconds / 60.0, 2)
        if seconds > 0:
            recurrence_per_hour = round((event_count / seconds) * 3600.0, 3)

    return {
        "dedupe_key": alert_row.get("dedupe_key"),
        "event_count": event_count,
        "first_seen_at": first_seen.isoformat() if hasattr(first_seen, "isoformat") else first_seen,
        "last_seen_at": last_seen.isoformat() if hasattr(last_seen, "isoformat") else last_seen,
        "window_minutes": window_minutes,
        "recurrence_per_hour": recurrence_per_hour,
        "is_recurring": event_count > 1,
    }


__all__ = ["summarize_alert_deduplication"]
