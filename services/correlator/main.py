"""secplat-correlator: Phase 3.1. Consume secplat.events.correlation and create incidents via API."""

import hashlib
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime

import httpx
import redis

_STANDARD_ATTRS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "pid": os.getpid(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in payload:
                continue
            try:
                json.dumps({key: value})
                payload[key] = value
            except Exception:
                payload[key] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service="secplat-correlator"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


class NonRetryableMessageError(Exception):
    """Payload/content errors that should not be retried."""


configure_logging()
logger = logging.getLogger("correlator")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STREAM = "secplat.events.correlation"
STREAM_DLQ = f"{STREAM}.dlq"
GROUP = "correlators"
CONSUMER = os.environ.get("CORRELATOR_CONSUMER", "correlator-1")
API_URL = (os.environ.get("API_URL") or "http://api:8000").rstrip("/")
CORRELATOR_USER = os.environ.get("CORRELATOR_USER") or os.environ.get("ADMIN_USERNAME", "admin")
CORRELATOR_PASSWORD = os.environ.get("CORRELATOR_PASSWORD") or os.environ.get(
    "ADMIN_PASSWORD", "admin"
)
BLOCK_MS = 5000
STREAM_MAX_RETRIES = int(
    os.getenv("CORRELATOR_STREAM_MAX_RETRIES", os.getenv("STREAM_MAX_RETRIES", "5"))
)
STREAM_CLAIM_IDLE_MS = int(
    os.getenv("CORRELATOR_STREAM_CLAIM_IDLE_MS", os.getenv("STREAM_CLAIM_IDLE_MS", "120000"))
)

_token: str | None = None


def _event_hour_bucket(ts_raw: str | None) -> str:
    if ts_raw:
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            return dt.astimezone(UTC).strftime("%Y%m%d%H")
        except ValueError:
            pass
    return datetime.now(UTC).strftime("%Y%m%d%H")


def _incident_key_for_finding(asset_key: str, finding_key: str) -> str:
    fk = finding_key or "unknown"
    return f"finding:{asset_key}:{fk}"


def _normalize_down_assets(raw: object) -> list[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
            parsed = [x.strip().strip('"').strip("'") for x in s.split(",") if x.strip()]
        else:
            parsed = [s] if s else []
    if isinstance(parsed, list):
        return [str(x).strip() for x in parsed if str(x).strip()]
    return [str(parsed).strip()] if str(parsed).strip() else []


def _incident_key_for_alert(down_assets: list[str], ts_raw: str | None) -> str:
    bucket = _event_hour_bucket(ts_raw)
    normalized = sorted({a.strip() for a in down_assets if a.strip()})
    digest = hashlib.sha1(",".join(normalized).encode("utf-8")).hexdigest()[:16]
    return f"alert:{bucket}:{digest}"


def get_token(*, force_refresh: bool = False) -> str | None:
    global _token
    if _token and not force_refresh:
        return _token
    try:
        r = httpx.post(
            f"{API_URL}/auth/login",
            data={"username": CORRELATOR_USER, "password": CORRELATOR_PASSWORD},
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json()
        _token = data.get("access_token")
        return _token
    except Exception as e:
        logger.warning("login failed: %s", e)
        return None


def create_incident(
    title: str,
    *,
    severity: str = "medium",
    asset_keys: list[str] | None = None,
    incident_key: str | None = None,
    trace_id: str | None = None,
) -> dict:
    global _token
    token = get_token()
    if not token:
        raise RuntimeError("correlator_login_failed")

    payload = {
        "title": title,
        "severity": severity,
        "asset_keys": asset_keys or [],
        "incident_key": incident_key,
    }
    headers = {"Authorization": f"Bearer {token}"}
    if trace_id:
        headers["x-request-id"] = trace_id

    r = httpx.post(
        f"{API_URL}/incidents",
        json=payload,
        headers=headers,
        timeout=10.0,
    )
    if r.status_code in (401, 403):
        logger.info("incident create auth failed status=%s refreshing token", r.status_code)
        _token = None
        fresh = get_token(force_refresh=True)
        if not fresh:
            raise RuntimeError("correlator_token_refresh_failed")
        headers = {"Authorization": f"Bearer {fresh}"}
        if trace_id:
            headers["x-request-id"] = trace_id
        r = httpx.post(
            f"{API_URL}/incidents",
            json=payload,
            headers=headers,
            timeout=10.0,
        )
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        status = e.response.status_code if e.response is not None else 0
        if status in (400, 404, 409, 422):
            raise NonRetryableMessageError(f"incident_api_status_{status}") from e
        raise
    return r.json()


def _ensure_stream_group(r: redis.Redis) -> None:
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def _read_one_from_stream(r: redis.Redis) -> tuple[str, str, dict] | None:
    """
    Reclaim stale pending entries first, then read new ones.
    Returns (source, message_id, fields), source in reclaimed|new.
    """
    _ensure_stream_group(r)
    claimed = r.xautoclaim(
        STREAM,
        GROUP,
        CONSUMER,
        min_idle_time=STREAM_CLAIM_IDLE_MS,
        start_id="0-0",
        count=1,
    )
    claimed_messages = claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) > 1 else []
    if claimed_messages:
        msg_id, fields = claimed_messages[0]
        return ("reclaimed", msg_id, dict(fields))

    streams = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=1, block=BLOCK_MS)
    if not streams:
        return None
    for _stream_name, messages in streams:
        for msg_id, fields in messages:
            return ("new", msg_id, dict(fields))
    return None


def _parse_attempts(fields: dict) -> int:
    try:
        return max(0, int(fields.get("attempts", "0")))
    except Exception:
        return 0


def _ack_stream(r: redis.Redis, msg_id: str) -> None:
    try:
        r.xack(STREAM, GROUP, msg_id)
    except Exception as e:
        logger.warning(
            "correlation_ack_failed",
            extra={
                "action": "correlation_ack",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(e),
            },
        )


def _requeue_stream_message(r: redis.Redis, fields: dict, attempts: int) -> None:
    payload = {k: str(v) for k, v in fields.items()}
    payload["attempts"] = str(attempts)
    r.xadd(STREAM, payload, maxlen=50_000)


def _publish_dlq(
    r: redis.Redis,
    msg_id: str,
    fields: dict,
    *,
    error: str,
    retryable: bool,
    attempts: int,
) -> None:
    payload = {k: str(v) for k, v in fields.items()}
    payload.update(
        {
            "original_stream": STREAM,
            "original_id": msg_id,
            "error": error,
            "retryable": str(retryable).lower(),
            "attempts": str(attempts),
            "failed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    r.xadd(STREAM_DLQ, payload, maxlen=10_000)


def handle_event(payload: dict) -> dict:
    trace_id = (payload.get("trace_id") or "").strip() or None
    event_type = (payload.get("event_type") or "").strip()
    if not event_type:
        raise NonRetryableMessageError("missing_event_type")

    if event_type == "finding.created":
        asset_key = (payload.get("asset_key") or "").strip()
        finding_key = (payload.get("finding_key") or "").strip()
        severity = (payload.get("severity") or "medium").strip() or "medium"
        if not asset_key:
            raise NonRetryableMessageError("missing_asset_key")
        incident_key = (payload.get("incident_key") or "").strip() or _incident_key_for_finding(
            asset_key, finding_key
        )
        logger.info(
            "processing event_type=finding.created trace_id=%s asset_key=%s finding_key=%s incident_key=%s",
            trace_id,
            asset_key,
            finding_key,
            incident_key,
        )
        title = f"Finding: {finding_key or 'unknown'} on {asset_key}"
        inc = create_incident(
            title=title,
            severity=severity,
            asset_keys=[asset_key],
            incident_key=incident_key,
            trace_id=trace_id,
        )
        incident_id = inc.get("id")
        logger.info(
            "created incident id=%s title=%s incident_key=%s", incident_id, title, incident_key
        )
        return {
            "event_type": event_type,
            "incident_id": incident_id,
            "incident_key": incident_key,
        }

    if event_type == "alert.triggered":
        down_assets = _normalize_down_assets(payload.get("down_assets"))
        if not down_assets:
            raise NonRetryableMessageError("empty_down_assets")
        incident_key = (payload.get("incident_key") or "").strip() or _incident_key_for_alert(
            down_assets, (payload.get("ts") or "").strip() or None
        )
        logger.info(
            "processing event_type=alert.triggered trace_id=%s down_assets=%s incident_key=%s",
            trace_id,
            down_assets[:5],
            incident_key,
        )
        title = f"Assets down: {', '.join(down_assets[:5])}{' ...' if len(down_assets) > 5 else ''}"
        inc = create_incident(
            title=title,
            severity="high",
            asset_keys=down_assets,
            incident_key=incident_key,
            trace_id=trace_id,
        )
        incident_id = inc.get("id")
        logger.info(
            "created incident id=%s assets=%s incident_key=%s",
            incident_id,
            len(down_assets),
            incident_key,
        )
        return {
            "event_type": event_type,
            "incident_id": incident_id,
            "incident_key": incident_key,
        }

    raise NonRetryableMessageError(f"unknown_event_type:{event_type}")


def main() -> None:
    logger.info(
        "secplat-correlator started stream=%s group=%s consumer=%s api=%s dlq=%s claim_idle_ms=%s max_retries=%s",
        STREAM,
        GROUP,
        CONSUMER,
        API_URL,
        STREAM_DLQ,
        STREAM_CLAIM_IDLE_MS,
        STREAM_MAX_RETRIES,
    )
    r = redis.from_url(REDIS_URL, decode_responses=True)
    _ensure_stream_group(r)

    while True:
        try:
            from_stream = _read_one_from_stream(r)
            if not from_stream:
                continue
            delivery, mid, fields = from_stream
            attempts = _parse_attempts(fields)
            trace_id = (fields.get("trace_id") or "").strip() or None
            try:
                result = handle_event(fields)
                logger.info(
                    "correlation_processed",
                    extra={
                        "action": "correlation_process",
                        "status": "done",
                        "delivery": delivery,
                        "message_id": mid,
                        "attempt": attempts,
                        "event_type": result.get("event_type"),
                        "incident_id": result.get("incident_id"),
                        "incident_key": result.get("incident_key"),
                        "trace_id": trace_id,
                    },
                )
            except NonRetryableMessageError as e:
                logger.warning(
                    "correlation_non_retryable",
                    extra={
                        "action": "correlation_process",
                        "status": "dropped",
                        "retryable": False,
                        "delivery": delivery,
                        "message_id": mid,
                        "attempt": attempts,
                        "trace_id": trace_id,
                        "error": str(e),
                    },
                )
                _publish_dlq(
                    r,
                    mid,
                    fields,
                    error=str(e),
                    retryable=False,
                    attempts=attempts,
                )
            except Exception as e:
                if attempts < STREAM_MAX_RETRIES:
                    try:
                        _requeue_stream_message(r, fields, attempts + 1)
                    except Exception as requeue_exc:
                        logger.exception(
                            "correlation_requeue_failed",
                            extra={
                                "action": "correlation_requeue",
                                "status": "error",
                                "retryable": True,
                                "delivery": delivery,
                                "message_id": mid,
                                "attempt": attempts + 1,
                                "trace_id": trace_id,
                                "error": str(requeue_exc),
                            },
                        )
                        _publish_dlq(
                            r,
                            mid,
                            fields,
                            error=f"{e}; requeue_failed={requeue_exc}",
                            retryable=True,
                            attempts=attempts,
                        )
                    else:
                        logger.warning(
                            "correlation_requeued",
                            extra={
                                "action": "correlation_requeue",
                                "status": "queued",
                                "retryable": True,
                                "delivery": delivery,
                                "message_id": mid,
                                "attempt": attempts + 1,
                                "trace_id": trace_id,
                                "error": str(e),
                            },
                        )
                else:
                    _publish_dlq(
                        r,
                        mid,
                        fields,
                        error=str(e),
                        retryable=True,
                        attempts=attempts,
                    )
                    logger.exception(
                        "correlation_failed_dlq",
                        extra={
                            "action": "correlation_process",
                            "status": "failed",
                            "retryable": True,
                            "delivery": delivery,
                            "message_id": mid,
                            "attempt": attempts,
                            "trace_id": trace_id,
                            "error": str(e),
                        },
                    )
            finally:
                _ack_stream(r, mid)
        except redis.ConnectionError as e:
            logger.warning("redis connection error: %s", e)
            time.sleep(5)
        except redis.ResponseError as e:
            if "NOGROUP" in str(e):
                try:
                    _ensure_stream_group(r)
                    logger.info("recreated group %s on %s after NOGROUP", GROUP, STREAM)
                except redis.ResponseError as e2:
                    if "BUSYGROUP" not in str(e2):
                        logger.warning("xgroup_create after NOGROUP: %s", e2)
            else:
                logger.warning("redis response error: %s", e)
            time.sleep(2)


if __name__ == "__main__":
    main()
