"""secplat-notifier: Phase 2.3. Consume secplat.events.notify and send Slack/Twilio."""

import json
import logging
import os
import time

import httpx
import redis

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("notifier")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STREAM_NOTIFY = "secplat.events.notify"
GROUP = "notifiers"
CONSUMER = os.environ.get("NOTIFIER_CONSUMER", "notifier-1")
BLOCK_MS = 5000

# Slack/Twilio (same as API)
SLACK_WEBHOOK_URL = (os.environ.get("SLACK_WEBHOOK_URL") or "").strip()
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") or ""
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN") or ""
TWILIO_WHATSAPP_FROM = (os.environ.get("TWILIO_WHATSAPP_FROM") or "").strip()
WHATSAPP_ALERT_TO = (os.environ.get("WHATSAPP_ALERT_TO") or "").strip()


def send_slack(down_assets: list[str]) -> bool:
    if not SLACK_WEBHOOK_URL:
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
    if (
        not TWILIO_ACCOUNT_SID
        or not TWILIO_AUTH_TOKEN
        or not TWILIO_WHATSAPP_FROM
        or not WHATSAPP_ALERT_TO
    ):
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


def handle_notify(payload: dict, r: redis.Redis, stream: str, group: str, mid: str) -> None:
    msg_type = payload.get("type", "")
    if msg_type != "down_assets":
        logger.warning("unknown type=%s, acking", msg_type)
        r.xack(stream, group, mid)
        return
    raw = payload.get("down_assets", "[]")
    if not isinstance(raw, str):
        down_assets = raw if isinstance(raw, list) else []
    else:
        try:
            down_assets = json.loads(raw)
        except json.JSONDecodeError:
            # Fallback: "[a,b]" or "[a]" when shell stripped quotes
            s = raw.strip()
            if s.startswith("[") and s.endswith("]"):
                s = s[1:-1]
                down_assets = [x.strip().strip('"').strip("'") for x in s.split(",") if x.strip()]
            else:
                down_assets = [s] if s else []
            if not down_assets:
                logger.warning("invalid down_assets: %s", raw)
        if not isinstance(down_assets, list):
            down_assets = [str(down_assets)] if down_assets is not None else []
    if not down_assets:
        r.xack(stream, group, mid)
        return
    logger.info("processing notify down_assets=%s", down_assets)
    send_slack(down_assets)
    send_whatsapp(down_assets)
    r.xack(stream, group, mid)


def main() -> None:
    logger.info(
        "secplat-notifier started stream=%s group=%s consumer=%s", STREAM_NOTIFY, GROUP, CONSUMER
    )
    r = redis.from_url(REDIS_URL, decode_responses=True)
    # Create consumer group (start from 0 to process existing; use $ for new-only)
    try:
        r.xgroup_create(STREAM_NOTIFY, GROUP, id="0", mkstream=True)
        logger.info("created group %s on %s", GROUP, STREAM_NOTIFY)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            logger.warning("xgroup_create: %s", e)

    while True:
        try:
            streams = r.xreadgroup(GROUP, CONSUMER, {STREAM_NOTIFY: ">"}, count=1, block=BLOCK_MS)
            if not streams:
                continue
            for _sname, messages in streams:
                for mid, fields in messages:
                    payload = dict(fields)
                    try:
                        handle_notify(payload, r, STREAM_NOTIFY, GROUP, mid)
                    except Exception as e:
                        logger.exception("handle_notify failed id=%s: %s", mid, e)
                        # Don't ack so it can be retried
        except redis.ConnectionError as e:
            logger.warning("redis connection error: %s", e)
            time.sleep(5)
        except redis.ResponseError as e:
            if "NOGROUP" in str(e):
                try:
                    r.xgroup_create(STREAM_NOTIFY, GROUP, id="0", mkstream=True)
                    logger.info("recreated group %s on %s after NOGROUP", GROUP, STREAM_NOTIFY)
                except redis.ResponseError as e2:
                    if "BUSYGROUP" not in str(e2):
                        logger.warning("xgroup_create after NOGROUP: %s", e2)
            else:
                logger.warning("redis response error: %s", e)
            time.sleep(2)


if __name__ == "__main__":
    main()
