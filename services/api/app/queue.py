"""Phase 1: Publish scan jobs to Redis stream. No-op when REDIS_URL is not set."""

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.request_context import request_id_ctx
from app.settings import settings

logger = logging.getLogger("secplat.queue")
STREAM_SCAN = "secplat.jobs.scan"
STREAM_NOTIFY = "secplat.events.notify"
STREAM_CORRELATION = "secplat.events.correlation"
STREAM_DLQ = {
    STREAM_SCAN: f"{STREAM_SCAN}.dlq",
    STREAM_NOTIFY: f"{STREAM_NOTIFY}.dlq",
    STREAM_CORRELATION: f"{STREAM_CORRELATION}.dlq",
}
STREAM_GROUPS: dict[str, tuple[str, ...]] = {
    STREAM_SCAN: ("workers",),
    STREAM_NOTIFY: ("notifiers",),
    STREAM_CORRELATION: ("correlators",),
}


def _client():
    if not getattr(settings, "REDIS_URL", None) or not settings.REDIS_URL.strip():
        return None
    import redis

    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def _resolve_trace_id(trace_id: str | None = None) -> str:
    if trace_id and trace_id.strip():
        return trace_id.strip()
    ctx_id = request_id_ctx.get("")
    if ctx_id:
        return ctx_id
    return str(uuid4())


def publish_scan_job(
    job_id: int,
    job_type: str,
    target_asset_id: int | None,
    requested_by: str,
    trace_id: str | None = None,
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
            "trace_id": _resolve_trace_id(trace_id),
        }
        r.xadd(STREAM_SCAN, msg, maxlen=100_000)
        logger.info("published job_id=%s to stream=%s", job_id, STREAM_SCAN)
        return True
    except Exception as e:
        logger.warning("queue publish failed: %s", e)
        return False


def publish_notify(down_assets: list[str], trace_id: str | None = None) -> bool:
    """Publish an alert notification to secplat.events.notify (Phase 2.3). Notifier consumes and sends Slack/Twilio."""
    if not down_assets:
        return False
    r = _client()
    if not r:
        return False
    try:
        msg = {
            "type": "down_assets",
            "down_assets": json.dumps(down_assets),
            "trace_id": _resolve_trace_id(trace_id),
        }
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
    incident_key: str | None = None,
    trace_id: str | None = None,
) -> bool:
    """Publish to secplat.events.correlation for Phase 3.1 correlator. event_type: finding.created | alert.triggered."""
    r = _client()
    if not r:
        return False
    try:
        msg = {
            "event_type": event_type,
            "ts": datetime.now(UTC).isoformat(),
            "trace_id": _resolve_trace_id(trace_id),
        }
        if asset_key:
            msg["asset_key"] = asset_key
        if finding_key:
            msg["finding_key"] = finding_key
        if severity:
            msg["severity"] = severity
        if down_assets:
            msg["down_assets"] = json.dumps(down_assets)
        if incident_key:
            msg["incident_key"] = incident_key
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
        dlq_streams = {}
        pending: dict[str, Any] = {}
        for stream in (STREAM_SCAN, STREAM_NOTIFY, STREAM_CORRELATION):
            try:
                streams[stream] = r.xlen(stream)
            except Exception:
                streams[stream] = 0
            try:
                dlq_streams[STREAM_DLQ[stream]] = r.xlen(STREAM_DLQ[stream])
            except Exception:
                dlq_streams[STREAM_DLQ[stream]] = 0
            stream_groups = {}
            for group in STREAM_GROUPS.get(stream, ()):
                try:
                    summary = r.xpending(stream, group)
                    if isinstance(summary, dict):
                        pending_count = int(summary.get("pending", 0))
                        min_id = summary.get("min")
                        max_id = summary.get("max")
                    elif isinstance(summary, (list, tuple)) and len(summary) >= 4:
                        pending_count = int(summary[0] or 0)
                        min_id = summary[1]
                        max_id = summary[2]
                    else:
                        pending_count = 0
                        min_id = None
                        max_id = None
                    oldest_idle_ms = None
                    if pending_count > 0:
                        try:
                            pending_items = r.xpending_range(
                                stream,
                                group,
                                min="-",
                                max="+",
                                count=1,
                            )
                            if pending_items and isinstance(pending_items[0], dict):
                                oldest_idle_ms = int(
                                    pending_items[0].get("time_since_delivered", 0)
                                )
                        except Exception:
                            oldest_idle_ms = None
                    stream_groups[group] = {
                        "pending": pending_count,
                        "min_id": min_id,
                        "max_id": max_id,
                        "oldest_idle_ms": oldest_idle_ms,
                    }
                except Exception:
                    stream_groups[group] = {
                        "pending": 0,
                        "min_id": None,
                        "max_id": None,
                        "oldest_idle_ms": None,
                    }
            if stream_groups:
                pending[stream] = stream_groups
        return {
            "redis": "ok",
            "redis_version": info.get("redis_version"),
            "streams": streams,
            "dlq_streams": dlq_streams,
            "pending": pending,
        }
    except Exception as e:
        return {"redis": "error", "error": str(e)}
