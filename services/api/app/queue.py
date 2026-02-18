"""Phase 1: Publish scan jobs to Redis stream. No-op when REDIS_URL is not set."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.settings import settings

logger = logging.getLogger("secplat.queue")
STREAM_SCAN = "secplat.jobs.scan"
STREAM_NOTIFY = "secplat.events.notify"
STREAM_CORRELATION = "secplat.events.correlation"


def _client():
    if not getattr(settings, "REDIS_URL", None) or not settings.REDIS_URL.strip():
        return None
    import redis

    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish_scan_job(
    job_id: int, job_type: str, target_asset_id: int | None, requested_by: str
) -> bool:
    """Publish a scan job to secplat.jobs.scan. Returns True if published."""
    r = _client()
    if not r:
        return False
    try:
        msg = {
            "job_id": str(job_id),
            "job_type": job_type,
            "target_asset_id": str(target_asset_id) if target_asset_id is not None else "",
            "requested_by": requested_by,
        }
        r.xadd(STREAM_SCAN, msg, maxlen=100_000)
        logger.info("published job_id=%s to stream=%s", job_id, STREAM_SCAN)
        return True
    except Exception as e:
        logger.warning("queue publish failed: %s", e)
        return False


def publish_notify(down_assets: list[str]) -> bool:
    """Publish an alert notification to secplat.events.notify (Phase 2.3). Notifier consumes and sends Slack/Twilio."""
    if not down_assets:
        return False
    r = _client()
    if not r:
        return False
    try:
        msg = {"type": "down_assets", "down_assets": json.dumps(down_assets)}
        r.xadd(STREAM_NOTIFY, msg, maxlen=10_000)
        logger.info("published notify to stream=%s down_assets=%s", STREAM_NOTIFY, down_assets)
        return True
    except Exception as e:
        logger.warning("queue publish notify failed: %s", e)
        return False


def publish_correlation_event(
    event_type: str,
    *,
    asset_key: str | None = None,
    finding_key: str | None = None,
    severity: str | None = None,
    down_assets: list[str] | None = None,
) -> bool:
    """Publish to secplat.events.correlation for Phase 3.1 correlator. event_type: finding.created | alert.triggered."""
    r = _client()
    if not r:
        return False
    try:
        msg = {"event_type": event_type, "ts": datetime.now(UTC).isoformat()}
        if asset_key:
            msg["asset_key"] = asset_key
        if finding_key:
            msg["finding_key"] = finding_key
        if severity:
            msg["severity"] = severity
        if down_assets:
            msg["down_assets"] = json.dumps(down_assets)
        r.xadd(STREAM_CORRELATION, msg, maxlen=50_000)
        logger.info("published correlation event_type=%s stream=%s", event_type, STREAM_CORRELATION)
        return True
    except Exception as e:
        logger.warning("queue publish correlation failed: %s", e)
        return False


def queue_health() -> dict[str, Any] | None:
    """Return Redis and stream info for GET /queue/health, or None if Redis not configured."""
    r = _client()
    if not r:
        return None
    try:
        info = r.info("server")
        streams = {}
        for stream in (STREAM_SCAN, STREAM_NOTIFY, STREAM_CORRELATION):
            try:
                streams[stream] = r.xlen(stream)
            except Exception:
                streams[stream] = 0
        return {
            "redis": "ok",
            "redis_version": info.get("redis_version"),
            "streams": streams,
        }
    except Exception as e:
        return {"redis": "error", "error": str(e)}
