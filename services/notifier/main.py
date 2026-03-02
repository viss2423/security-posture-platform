"""secplat-notifier: Phase 2.3. Consume secplat.events.notify and send Slack/Twilio."""

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
    handler.setFormatter(JsonFormatter(service="secplat-notifier"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


class NonRetryableMessageError(Exception):
    """Payload/config errors that should go directly to DLQ."""


configure_logging()
logger = logging.getLogger("notifier")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STREAM_NOTIFY = "secplat.events.notify"
STREAM_DLQ = f"{STREAM_NOTIFY}.dlq"
GROUP = "notifiers"
CONSUMER = os.environ.get("NOTIFIER_CONSUMER", "notifier-1")
BLOCK_MS = 5000
STREAM_MAX_RETRIES = int(
    os.getenv("NOTIFIER_STREAM_MAX_RETRIES", os.getenv("STREAM_MAX_RETRIES", "5"))
)
STREAM_CLAIM_IDLE_MS = int(
    os.getenv("NOTIFIER_STREAM_CLAIM_IDLE_MS", os.getenv("STREAM_CLAIM_IDLE_MS", "120000"))
)

# Slack/Twilio (same as API)
SLACK_WEBHOOK_URL = (os.environ.get("SLACK_WEBHOOK_URL") or "").strip()
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") or ""
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN") or ""
TWILIO_WHATSAPP_FROM = (os.environ.get("TWILIO_WHATSAPP_FROM") or "").strip()
WHATSAPP_ALERT_TO = (os.environ.get("WHATSAPP_ALERT_TO") or "").strip()


def _slack_configured() -> bool:
    return bool(SLACK_WEBHOOK_URL)


def _whatsapp_configured() -> bool:
    return bool(
        TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM and WHATSAPP_ALERT_TO
    )


def send_slack(down_assets: list[str]) -> bool:
    if not _slack_configured():
        return False
    text = f"*SecPlat alert:* {len(down_assets)} asset(s) down: {', '.join(down_assets)}"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.post(SLACK_WEBHOOK_URL, json={"text": text})
            r.raise_for_status()
        logger.info("slack sent for %s down assets", len(down_assets))
        return True
    except Exception as e:
        logger.warning("slack send failed: %s", e)
        return False


def send_whatsapp(down_assets: list[str]) -> bool:
    if not _whatsapp_configured():
        return False
    from_ = (
        TWILIO_WHATSAPP_FROM
        if TWILIO_WHATSAPP_FROM.startswith("whatsapp:")
        else f"whatsapp:{TWILIO_WHATSAPP_FROM}"
    )
    to = (
        WHATSAPP_ALERT_TO
        if WHATSAPP_ALERT_TO.startswith("whatsapp:")
        else f"whatsapp:{WHATSAPP_ALERT_TO}"
    )
    body = f"SecPlat alert: {len(down_assets)} asset(s) down: {', '.join(down_assets)}"
    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                url,
                auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
                data={"From": from_, "To": to, "Body": body},
            )
            r.raise_for_status()
        logger.info("whatsapp sent for %s down assets", len(down_assets))
        return True
    except Exception as e:
        logger.warning("whatsapp send failed: %s", e)
        return False


def _ensure_stream_group(r: redis.Redis) -> None:
    try:
        r.xgroup_create(STREAM_NOTIFY, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def _read_one_from_stream(r: redis.Redis) -> tuple[str, str, dict] | None:
    """
    Reclaim stale pending entries first, then read new messages.
    Returns (source, message_id, fields), where source is reclaimed|new.
    """
    _ensure_stream_group(r)
    claimed = r.xautoclaim(
        STREAM_NOTIFY,
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

    streams = r.xreadgroup(GROUP, CONSUMER, {STREAM_NOTIFY: ">"}, count=1, block=BLOCK_MS)
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
        r.xack(STREAM_NOTIFY, GROUP, msg_id)
    except Exception as e:
        logger.warning(
            "notify_ack_failed",
            extra={
                "action": "notify_ack",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(e),
            },
        )


def _requeue_stream_message(r: redis.Redis, fields: dict, attempts: int) -> None:
    payload = {k: str(v) for k, v in fields.items()}
    payload["attempts"] = str(attempts)
    r.xadd(STREAM_NOTIFY, payload, maxlen=10_000)


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
            "original_stream": STREAM_NOTIFY,
            "original_id": msg_id,
            "error": error,
            "retryable": str(retryable).lower(),
            "attempts": str(attempts),
            "failed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    r.xadd(STREAM_DLQ, payload, maxlen=10_000)


def _parse_down_assets(raw: object, trace_id: str | None) -> list[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback for "[a,b]" format where quotes may be stripped by shell.
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
            parsed = [x.strip().strip('"').strip("'") for x in s.split(",") if x.strip()]
        else:
            parsed = [s] if s else []
        if not parsed:
            logger.warning("invalid down_assets trace_id=%s: %s", trace_id, raw)
    if isinstance(parsed, list):
        return [str(x).strip() for x in parsed if str(x).strip()]
    return [str(parsed).strip()] if str(parsed).strip() else []


def handle_notify(payload: dict) -> list[str]:
    trace_id = (payload.get("trace_id") or "").strip() or None
    msg_type = (payload.get("type") or "").strip()
    if msg_type != "down_assets":
        raise NonRetryableMessageError(f"unknown_type:{msg_type or 'missing'}")

    down_assets = _parse_down_assets(payload.get("down_assets", "[]"), trace_id)
    if not down_assets:
        raise NonRetryableMessageError("empty_down_assets")

    slack_configured = _slack_configured()
    whatsapp_configured = _whatsapp_configured()
    if not slack_configured and not whatsapp_configured:
        raise NonRetryableMessageError("no_notification_channels_configured")

    logger.info("processing notify trace_id=%s down_assets=%s", trace_id, down_assets)
    sent = False
    if slack_configured:
        sent = send_slack(down_assets) or sent
    if whatsapp_configured:
        sent = send_whatsapp(down_assets) or sent

    if not sent:
        raise RuntimeError("notification_delivery_failed")
    return down_assets


def main() -> None:
    logger.info(
        "secplat-notifier started stream=%s group=%s consumer=%s dlq=%s claim_idle_ms=%s max_retries=%s",
        STREAM_NOTIFY,
        GROUP,
        CONSUMER,
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
                down_assets = handle_notify(fields)
                logger.info(
                    "notify_processed",
                    extra={
                        "action": "notify_process",
                        "status": "done",
                        "delivery": delivery,
                        "message_id": mid,
                        "attempt": attempts,
                        "down_assets_count": len(down_assets),
                        "trace_id": trace_id,
                    },
                )
            except NonRetryableMessageError as e:
                logger.warning(
                    "notify_non_retryable",
                    extra={
                        "action": "notify_process",
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
                            "notify_requeue_failed",
                            extra={
                                "action": "notify_requeue",
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
                            "notify_requeued",
                            extra={
                                "action": "notify_requeue",
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
                        "notify_failed_dlq",
                        extra={
                            "action": "notify_process",
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
                    logger.info("recreated group %s on %s after NOGROUP", GROUP, STREAM_NOTIFY)
                except redis.ResponseError as e2:
                    if "BUSYGROUP" not in str(e2):
                        logger.warning("xgroup_create after NOGROUP: %s", e2)
            else:
                logger.warning("redis response error: %s", e)
            time.sleep(2)


if __name__ == "__main__":
    main()
